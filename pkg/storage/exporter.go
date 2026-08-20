package storage

import (
	"encoding/csv"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"time"

	"goproxy/pkg/model"
)

// Exporter ghi proxy đã xác minh vào các file phân loại theo thời gian thực.
// Mỗi proxy sống được ghi NGAY LẬP TỨC khi tìm thấy — không buffering thêm —
// đảm bảo không mất dữ liệu khi tắt chương trình đột ngột.
type Exporter struct {
	outputDir      string
	splitByCountry bool
	splitByType    bool
	saveJSON       bool
	saveCSV        bool
	mu             sync.Mutex
	fileHandles    map[string]*os.File // Pool file handle tái sử dụng, tránh mở/đóng liên tục
	csvWriter      *csv.Writer
	csvFile        *os.File
}

// NewExporter tạo và khởi tạo Exporter, tạo thư mục output nếu chưa tồn tại
func NewExporter(cfg model.StorageConfig) (*Exporter, error) {
	if cfg.OutputDir == "" {
		cfg.OutputDir = "output"
	}
	if err := os.MkdirAll(cfg.OutputDir, 0755); err != nil {
		return nil, fmt.Errorf("không tạo được thư mục output: %w", err)
	}

	if cfg.SplitByCountry {
		_ = os.MkdirAll(filepath.Join(cfg.OutputDir, "countries"), 0755)
	}

	exp := &Exporter{
		outputDir:      cfg.OutputDir,
		splitByCountry: cfg.SplitByCountry,
		splitByType:    cfg.SplitByType,
		saveJSON:       cfg.SaveJSON,
		saveCSV:        cfg.SaveCSV,
		fileHandles:    make(map[string]*os.File),
	}

	if cfg.SaveCSV {
		csvPath := filepath.Join(cfg.OutputDir, "proxies.csv")
		f, err := os.OpenFile(csvPath, os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0644)
		if err == nil {
			exp.csvFile = f
			exp.csvWriter = csv.NewWriter(f)
			// Ghi header nếu file mới tạo (rỗng)
			fi, _ := f.Stat()
			if fi != nil && fi.Size() == 0 {
				_ = exp.csvWriter.Write([]string{"IP", "Port", "Protocol", "Anonymity", "Country", "CountryCode", "City", "LatencyMs", "Score", "LastAlive"})
				exp.csvWriter.Flush()
			}
		}
	}

	return exp, nil
}

// WriteAlive ghi ngay lập tức một proxy sống vào tất cả các định dạng output đã cấu hình.
// Hàm này được gọi từ worker goroutine ngay khi proxy được xác minh thành công.
// Dùng file handle pool để không tốn thời gian mở/đóng file mỗi lần ghi.
func (e *Exporter) WriteAlive(p *model.Proxy) {
	e.mu.Lock()
	defer e.mu.Unlock()

	addr := p.Address()
	urlStr := p.URLString()

	// 1. File tổng hợp tất cả proxy sống (dạng IP:PORT chuẩn)
	e.appendLine("alive.txt", addr)
	e.appendLine("alive_url.txt", urlStr)

	// 2. Phân loại theo giao thức (dạng IP:PORT)
	if e.splitByType {
		protoFile := fmt.Sprintf("%s.txt", p.Protocol)
		e.appendLine(protoFile, addr)
	}

	// 3. File proxy ẩn danh cao cấp (Elite)
	if p.Anonymity == model.AnonElite {
		e.appendLine("elite.txt", addr)
		if p.Protocol == model.ProtoSOCKS5 {
			e.appendLine("socks5_elite.txt", addr)
		}
	}

	// 4. File proxy nhanh (< 500ms) và chất lượng cao (Score >= 80)
	if p.LatencyMs > 0 && p.LatencyMs <= 500 {
		e.appendLine("fast.txt", addr)
	}
	if p.Score >= 80 {
		e.appendLine("high_quality.txt", addr)
	}

	// 5. Phân loại theo quốc gia (output/countries/VN.txt, output/countries/VN_socks5.txt)
	if e.splitByCountry && p.CountryCode != "" && p.CountryCode != "XX" {
		cc := p.CountryCode
		e.appendLine(filepath.Join("countries", fmt.Sprintf("%s.txt", cc)), addr)
		e.appendLine(filepath.Join("countries", fmt.Sprintf("%s_%s.txt", cc, p.Protocol)), addr)
	}

	// 6. JSON Lines (mỗi proxy 1 dòng JSON)
	if e.saveJSON {
		jsonPath := filepath.Join(e.outputDir, "proxies.jsonl")
		f := e.getFileHandle(jsonPath)
		if f != nil {
			data, _ := json.Marshal(p)
			_, _ = f.Write(append(data, '\n'))
		}
	}

	// 7. CSV với đầy đủ metadata
	if e.csvWriter != nil {
		_ = e.csvWriter.Write([]string{
			p.IP,
			strconv.Itoa(p.Port),
			string(p.Protocol),
			string(p.Anonymity),
			p.Country,
			p.CountryCode,
			p.City,
			strconv.FormatInt(p.LatencyMs, 10),
			strconv.Itoa(p.Score),
			p.LastAlive.Format(time.RFC3339),
		})
		e.csvWriter.Flush() // Flush ngay để dữ liệu không nằm trong buffer
	}
}

// appendLine ghi một dòng vào file, dùng file handle pool để tránh syscall open/close liên tục
func (e *Exporter) appendLine(filename string, line string) {
	path := filepath.Join(e.outputDir, filename)
	f := e.getFileHandle(path)
	if f != nil {
		_, _ = f.WriteString(line + "\n")
	}
}

// getFileHandle trả về file handle từ pool, hoặc mở file mới nếu chưa có
func (e *Exporter) getFileHandle(path string) *os.File {
	if f, exists := e.fileHandles[path]; exists {
		return f // Tái sử dụng handle đã mở sẵn
	}

	dir := filepath.Dir(path)
	_ = os.MkdirAll(dir, 0755)

	// Mở ở chế độ APPEND — luôn ghi tiếp vào cuối file, không ghi đè
	f, err := os.OpenFile(path, os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0644)
	if err != nil {
		return nil
	}
	e.fileHandles[path] = f
	return f
}

// SyncAliveFiles ghi lại toàn bộ các file output chỉ với proxy hiện đang sống.
// Hàm này được daemon gọi sau mỗi chu kỳ recheck để đảm bảo file luôn cập nhật.
func (e *Exporter) SyncAliveFiles(proxies []*model.Proxy) error {
	e.mu.Lock()
	defer e.mu.Unlock()

	// Đóng tất cả file handle cũ trước khi ghi đè
	for _, f := range e.fileHandles {
		_ = f.Close()
	}
	e.fileHandles = make(map[string]*os.File)

	linesByFile := make(map[string][]string)

	for _, p := range proxies {
		if !p.IsAlive {
			continue
		}

		addr := p.Address()
		urlStr := p.URLString()

		linesByFile["alive.txt"] = append(linesByFile["alive.txt"], addr)
		linesByFile["alive_url.txt"] = append(linesByFile["alive_url.txt"], urlStr)

		if e.splitByType {
			protoFile := fmt.Sprintf("%s.txt", p.Protocol)
			linesByFile[protoFile] = append(linesByFile[protoFile], addr)
		}

		if p.Anonymity == model.AnonElite {
			linesByFile["elite.txt"] = append(linesByFile["elite.txt"], addr)
			if p.Protocol == model.ProtoSOCKS5 {
				linesByFile["socks5_elite.txt"] = append(linesByFile["socks5_elite.txt"], addr)
			}
		}

		if p.LatencyMs > 0 && p.LatencyMs <= 500 {
			linesByFile["fast.txt"] = append(linesByFile["fast.txt"], addr)
		}
		if p.Score >= 80 {
			linesByFile["high_quality.txt"] = append(linesByFile["high_quality.txt"], addr)
		}

		if e.splitByCountry && p.CountryCode != "" && p.CountryCode != "XX" {
			cc := p.CountryCode
			countryFile := filepath.Join("countries", fmt.Sprintf("%s.txt", cc))
			countryProtoFile := filepath.Join("countries", fmt.Sprintf("%s_%s.txt", cc, p.Protocol))
			linesByFile[countryFile] = append(linesByFile[countryFile], addr)
			linesByFile[countryProtoFile] = append(linesByFile[countryProtoFile], addr)
		}
	}

	// Ghi tất cả file một lần (atomic overwrite)
	for relPath, lines := range linesByFile {
		fullPath := filepath.Join(e.outputDir, relPath)
		_ = os.MkdirAll(filepath.Dir(fullPath), 0755)
		content := strings.Join(lines, "\n")
		if len(lines) > 0 {
			content += "\n"
		}
		_ = os.WriteFile(fullPath, []byte(content), 0644)
	}

	return nil
}

// Close đóng tất cả file descriptor đang mở, flush CSV buffer
func (e *Exporter) Close() {
	e.mu.Lock()
	defer e.mu.Unlock()

	if e.csvWriter != nil {
		e.csvWriter.Flush()
	}
	if e.csvFile != nil {
		_ = e.csvFile.Close()
	}
	for _, f := range e.fileHandles {
		_ = f.Close()
	}
	e.fileHandles = make(map[string]*os.File)
}
