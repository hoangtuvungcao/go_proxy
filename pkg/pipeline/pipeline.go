package pipeline

import (
	"bufio"
	"context"
	"fmt"
	"io"
	"net"
	"net/url"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/fatih/color"
	"goproxy/pkg/checker"
	"goproxy/pkg/model"
	"goproxy/pkg/storage"
)

// Job đại diện cho một địa chỉ IP:Port cần kiểm tra
type Job struct {
	IP       string
	Port     int
	Protocol model.Protocol
}

// Pipeline điều phối quá trình: nhận dữ liệu đầu vào, phân phối worker, xác minh, và xuất kết quả
type Pipeline struct {
	config   *model.Config
	checker  *checker.Checker
	storage  *storage.SQLiteStore
	exporter *storage.Exporter
	stats    *model.Stats
	dedup    *ShardedDeduplicator
	quiet    bool
	jobsChan chan Job
	wg       sync.WaitGroup
	ctx      context.Context
	cancel   context.CancelFunc
}

// NewPipeline khởi tạo Pipeline mới
func NewPipeline(cfg *model.Config, store *storage.SQLiteStore, exp *storage.Exporter, quiet bool) *Pipeline {
	ctx, cancel := context.WithCancel(context.Background())
	return &Pipeline{
		config:   cfg,
		checker:  checker.NewChecker(cfg),
		storage:  store,
		exporter: exp,
		stats:    model.NewStats(),
		dedup:    NewShardedDeduplicator(15 * time.Minute),
		quiet:    quiet,
		jobsChan: make(chan Job, cfg.Engine.MaxQueueSize),
		ctx:      ctx,
		cancel:   cancel,
	}
}

// Start khởi động worker pool với số lượng goroutine chỉ định
func (p *Pipeline) Start(numWorkers int) {
	if numWorkers <= 0 {
		numWorkers = p.config.Engine.Workers
	}

	for i := 0; i < numWorkers; i++ {
		p.wg.Add(1)
		go p.worker()
	}
}

// worker là goroutine xử lý job từ hàng đợi — mỗi worker độc lập, không chia sẻ trạng thái
func (p *Pipeline) worker() {
	defer p.wg.Done()

	for {
		select {
		case <-p.ctx.Done():
			return
		case job, ok := <-p.jobsChan:
			if !ok {
				return
			}
			p.processJob(job)
		}
	}
}

// processJob xử lý một địa chỉ: kiểm tra, ghi file ngay, ghi DB, in log
func (p *Pipeline) processJob(job Job) {
	result := p.checker.CheckIPPort(p.ctx, job.IP, job.Port, job.Protocol)
	p.stats.RecordResult(result)

	if result.Success {
		proxy := &model.Proxy{
			IP:            result.IP,
			Port:          result.Port,
			Protocol:      result.Protocol,
			Anonymity:     result.Anonymity,
			Country:       result.Country,
			CountryCode:   result.CountryCode,
			City:          result.City,
			ASN:           result.ASN,
			Org:           result.Org,
			Latency:       result.Latency,
			LatencyMs:     result.LatencyMs,
			SSL:           result.SSL,
			TargetOK:      result.TargetOK,
			JudgeCount:    result.JudgeCount,
			SuccessChecks: 1,
			IsAlive:       true,
			LastAlive:     time.Now(),
			FirstSeen:     time.Now(),
		}
		proxy.Score = checker.CalculateScore(proxy)

		// GHI FILE NGAY LẬP TỨC — tránh mất dữ liệu khi tắt chương trình đột ngột
		// Exporter dùng append mode + file handle pool nên không gây I/O blocking
		if p.exporter != nil {
			p.exporter.WriteAlive(proxy)
		}

		// Ghi vào SQLite (bất đồng bộ qua batch channel, không block worker)
		if p.storage != nil {
			_ = p.storage.SaveOrUpdateProxy(proxy)
		}

		// In log nếu không ở chế độ yên lặng
		if !p.quiet {
			p.printAliveLine(proxy)
		}
	}
}

// printAliveLine in một dòng thông tin proxy sống lên terminal
func (p *Pipeline) printAliveLine(px *model.Proxy) {
	anonColor := color.FgYellow
	if px.Anonymity == model.AnonElite {
		anonColor = color.FgGreen
	} else if px.Anonymity == model.AnonTransparent {
		anonColor = color.FgRed
	}

	color.New(color.FgHiGreen, color.Bold).Printf("[+] SỐNG ")
	fmt.Printf("%-26s ", px.URLString())
	color.New(anonColor).Printf("[%s] ", strings.ToUpper(string(px.Anonymity)))
	color.New(color.FgCyan).Printf("[%dms] ", px.LatencyMs)
	if px.CountryCode != "" {
		color.New(color.FgMagenta).Printf("[%s] ", px.CountryCode)
	}
	if px.SSL {
		color.New(color.FgHiGreen).Printf("[SSL] ")
	}
	color.New(color.FgHiBlue).Printf("Điểm:%d\n", px.Score)
}

// IngestFromReader đọc địa chỉ mục tiêu từng dòng từ bất kỳ io.Reader nào (stdin, file)
func (p *Pipeline) IngestFromReader(r io.Reader, defaultPort int, defaultProto model.Protocol) error {
	scanner := bufio.NewScanner(r)
	buf := make([]byte, 64*1024)
	scanner.Buffer(buf, 1024*1024) // Buffer 1MB để xử lý dòng dài

	for scanner.Scan() {
		select {
		case <-p.ctx.Done():
			return p.ctx.Err()
		default:
		}

		line := strings.TrimSpace(scanner.Text())
		if line == "" || strings.HasPrefix(line, "#") {
			continue // Bỏ qua dòng rỗng và dòng comment
		}

		job, err := parseLineToJob(line, defaultPort, defaultProto)
		if err != nil {
			continue
		}

		// Loại bỏ trùng lặp trong vòng 15 phút
		dedupKey := fmt.Sprintf("%s:%d:%s", job.IP, job.Port, job.Protocol)
		if p.dedup != nil && !p.dedup.CheckAndSet(dedupKey) {
			continue
		}

		p.stats.IncQueued()

		// Đẩy vào queue — nếu ctx bị hủy hoặc queue đầy thì xử lý đúng cách
		select {
		case <-p.ctx.Done():
			return p.ctx.Err()
		case p.jobsChan <- job:
		}
	}

	return scanner.Err()
}

// parseLineToJob chuyển đổi chuỗi đầu vào (IP, IP:Port, URL) thành Job
func parseLineToJob(line string, defaultPort int, defaultProto model.Protocol) (Job, error) {
	line = strings.TrimSpace(line)

	// Định dạng URL (ví dụ: socks5://1.2.3.4:1080)
	if strings.Contains(line, "://") {
		u, err := url.Parse(line)
		if err == nil && u.Host != "" {
			proto := model.Protocol(strings.ToLower(u.Scheme))
			host, portStr, err := net.SplitHostPort(u.Host)
			if err == nil {
				port, _ := strconv.Atoi(portStr)
				return Job{IP: host, Port: port, Protocol: proto}, nil
			}
			return Job{IP: u.Host, Port: defaultPort, Protocol: proto}, nil
		}
	}

	// Định dạng IP:Port (ví dụ: 1.2.3.4:8080)
	if strings.Contains(line, ":") {
		host, portStr, err := net.SplitHostPort(line)
		if err == nil {
			port, err := strconv.Atoi(portStr)
			if err == nil && port > 0 && port <= 65535 {
				return Job{IP: host, Port: port, Protocol: defaultProto}, nil
			}
		}
	}

	// Chỉ có IP (ví dụ: đầu ra từ ZMap: 1.2.3.4)
	ip := net.ParseIP(line)
	if ip != nil {
		if defaultPort <= 0 {
			defaultPort = 8080
		}
		return Job{IP: line, Port: defaultPort, Protocol: defaultProto}, nil
	}

	return Job{}, fmt.Errorf("dòng không hợp lệ: %s", line)
}

// Cancel dừng ngay lập tức toàn bộ worker và tác vụ mạng đang chạy
func (p *Pipeline) Cancel() {
	p.cancel()
}

// Stop chờ tất cả job đang xử lý kết thúc rồi giải phóng tài nguyên
func (p *Pipeline) Stop() {
	p.cancel()
	p.wg.Wait()
}

// Stats trả về bộ thu thập thống kê đang hoạt động
func (p *Pipeline) Stats() *model.Stats {
	return p.stats
}
