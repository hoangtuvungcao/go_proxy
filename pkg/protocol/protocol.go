package protocol

import (
	"bufio"
	"bytes"
	"context"
	"crypto/tls"
	"encoding/binary"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"sync"
	"time"

	"goproxy/pkg/model"
)

var (
	// fastDialer - TCP dialer không giữ kết nối (KeepAlive=-1) để tái sử dụng socket nhanh hơn
	fastDialer = &net.Dialer{
		Timeout:   900 * time.Millisecond,
		KeepAlive: -1,
	}

	// sharedTLSConfig - TLS config dùng chung với LRU session cache để tăng tốc TLS resumption
	sharedTLSConfig = &tls.Config{
		InsecureSkipVerify: true,
		ClientSessionCache: tls.NewLRUClientSessionCache(20000),
		MinVersion:         tls.VersionTLS10, // Chấp nhận TLS cũ từ proxy giá rẻ
	}

	// Hai pool buffer theo tier kích thước để giảm cấp phát bộ nhớ
	bufPool2K = sync.Pool{New: func() interface{} { b := make([]byte, 2048); return &b }}
	bufPool8K = sync.Pool{New: func() interface{} { b := make([]byte, 8192); return &b }}
)

// validJudgeMarkers - chuỗi CÓ THỂ xuất hiện trong response của judge hợp lệ.
// Đây là "positive marker": response thật từ httpbin/azenv/judge tự host thường chứa những chuỗi này.
var validJudgeMarkers = [][]byte{
	[]byte(`"origin"`),
	[]byte(`"ip"`),
	[]byte("REMOTE_ADDR"),
	[]byte("origin"),
}

// suspiciousResponseMarkers - chuỗi xuất hiện trong trang KHÔNG PHẢI judge.
// Những chuỗi này chỉ ra đây là trang đăng nhập router, captive portal, hay challenge page
// → false positive (proxy trả về 200 OK nhưng dẫn tới trang khác, không phải judge).
var suspiciousResponseMarkers = [][]byte{
	[]byte("<form"),
	[]byte(`type="password"`),
	[]byte("captive portal"),
	[]byte("mikrotik"),
	[]byte("routeros"),
	[]byte("ubiquiti"),
	[]byte("cloudflare challenge"),
	[]byte("challenge-form"),
	[]byte("synology"),
	[]byte("<title>Login</title>"),
	[]byte("Please enable JavaScript"),
}

// judgeResponse - cấu trúc để parse JSON từ judge (httpbin, ipify, v.v.)
type judgeResponse struct {
	IP     string `json:"ip"`
	Origin string `json:"origin"`
}

// CheckHTTP thực hiện kiểm tra đầu cuối (end-to-end) cho HTTP Forward Proxy.
// Trả về: độ trễ, body phản hồi, header phản hồi, lỗi.
func CheckHTTP(ctx context.Context, proxyAddr string, judgeURL string, timeout time.Duration) (time.Duration, []byte, http.Header, error) {
	start := time.Now()

	conn, err := fastDial(ctx, proxyAddr, timeout)
	if err != nil {
		return 0, nil, nil, fmt.Errorf("kết nối HTTP thất bại: %w", err)
	}
	defer conn.Close()

	_ = conn.SetDeadline(time.Now().Add(timeout))

	u, err := url.Parse(judgeURL)
	if err != nil || u.Host == "" {
		u, _ = url.Parse("http://httpbin.org/ip")
	}

	reqPath := u.String()
	if !strings.HasPrefix(reqPath, "http://") && !strings.HasPrefix(reqPath, "https://") {
		reqPath = "http://" + u.Host + u.Path
	}

	// Dùng User-Agent giống trình duyệt thật để tránh bị block
	req := fmt.Sprintf(
		"GET %s HTTP/1.1\r\nHost: %s\r\nUser-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36\r\nAccept: application/json, text/plain, */*\r\nConnection: close\r\n\r\n",
		reqPath, u.Host,
	)
	if _, err := conn.Write([]byte(req)); err != nil {
		return 0, nil, nil, fmt.Errorf("ghi request thất bại: %w", err)
	}

	bufPtr := bufPool8K.Get().(*[]byte)
	defer bufPool8K.Put(bufPtr)
	reader := bufio.NewReaderSize(conn, len(*bufPtr))

	resp, err := http.ReadResponse(reader, &http.Request{Method: "GET"})
	if err != nil {
		return 0, nil, nil, fmt.Errorf("đọc response thất bại: %w", err)
	}
	defer resp.Body.Close()

	latency := time.Since(start)

	if resp.StatusCode < 200 || resp.StatusCode >= 400 {
		return latency, nil, resp.Header, fmt.Errorf("status code không hợp lệ: %d", resp.StatusCode)
	}

	body, err := io.ReadAll(io.LimitReader(resp.Body, 32768))
	if err != nil {
		return latency, nil, resp.Header, fmt.Errorf("đọc body thất bại: %w", err)
	}

	// --- Bộ lọc False Positive đa lớp ---
	if err := validateJudgeResponse(resp.Header, body); err != nil {
		return latency, nil, resp.Header, err
	}

	return latency, body, resp.Header, nil
}

// validateJudgeResponse kiểm tra xem response có phải từ judge thật không.
// Ưu tiên: phân tích JSON IP > marker check > nghi ngờ HTML.
func validateJudgeResponse(headers http.Header, body []byte) error {
	// Lớp 1: Body rỗng → reject
	if len(body) == 0 {
		return fmt.Errorf("false positive: body rỗng")
	}

	// Lớp 2: Body quá nhỏ (< 5 byte) → reject
	if len(body) < 5 {
		return fmt.Errorf("false positive: body quá ngắn (%d byte)", len(body))
	}

	contentType := strings.ToLower(headers.Get("Content-Type"))

	// Lớp 3: Nếu là JSON → thử parse và xác minh IP echo (bằng chứng chính)
	if strings.Contains(contentType, "application/json") || (len(body) > 0 && body[0] == '{') {
		var jr judgeResponse
		if err := json.Unmarshal(body, &jr); err == nil {
			ip := jr.IP
			if ip == "" {
				ip = jr.Origin
				// origin có thể là "1.2.3.4, 5.6.7.8" (multi-hop)
				if idx := strings.Index(ip, ","); idx > 0 {
					ip = strings.TrimSpace(ip[:idx])
				}
			}
			if ip != "" && net.ParseIP(ip) != nil {
				// ✅ JSON hợp lệ và chứa IP thật → đây là judge response chính xác
				return nil
			}
		}
	}

	// Lớp 4: Nếu là plain text → thử parse IP trực tiếp (ifconfig.me style)
	if strings.Contains(contentType, "text/plain") {
		trimmed := strings.TrimSpace(string(body))
		if net.ParseIP(trimmed) != nil {
			// ✅ Trả về đúng 1 địa chỉ IP → hợp lệ
			return nil
		}
	}

	// Lớp 5: HTML → kiểm tra có marker judge không (AZENV style)
	if strings.Contains(contentType, "text/html") || bytes.Contains(body, []byte("<html")) {
		hasJudgeMarker := false
		for _, kw := range validJudgeMarkers {
			if bytes.Contains(body, kw) {
				hasJudgeMarker = true
				break
			}
		}
		if !hasJudgeMarker {
			return fmt.Errorf("false positive: HTML không có judge marker")
		}
		// Kiểm tra thêm các dấu hiệu trang đáng ngờ (router/captive portal)
		lbody := bytes.ToLower(body)
		for _, marker := range suspiciousResponseMarkers {
			if bytes.Contains(lbody, marker) {
				return fmt.Errorf("false positive: phát hiện trang captive portal/router (%s)", marker)
			}
		}
		return nil
	}

	// Lớp 6: Các content-type khác → dùng marker check cơ bản
	for _, kw := range validJudgeMarkers {
		if bytes.Contains(body, kw) {
			return nil
		}
	}

	return fmt.Errorf("false positive: response không nhận dạng được là judge hợp lệ")
}

// CheckHTTPS xác minh HTTPS CONNECT tunnel với TLS handshake thực.
func CheckHTTPS(ctx context.Context, proxyAddr string, targetHost string, timeout time.Duration) (time.Duration, error) {
	start := time.Now()

	conn, err := fastDial(ctx, proxyAddr, timeout)
	if err != nil {
		return 0, fmt.Errorf("kết nối HTTPS thất bại: %w", err)
	}
	defer conn.Close()

	_ = conn.SetDeadline(time.Now().Add(timeout))

	if targetHost == "" {
		targetHost = "api.ipify.org:443"
	}
	if !strings.Contains(targetHost, ":") {
		targetHost = targetHost + ":443"
	}

	connectReq := fmt.Sprintf(
		"CONNECT %s HTTP/1.1\r\nHost: %s\r\nUser-Agent: Mozilla/5.0 (compatible; GoProxy/3.0)\r\nProxy-Connection: Keep-Alive\r\n\r\n",
		targetHost, targetHost,
	)
	if _, err := conn.Write([]byte(connectReq)); err != nil {
		return 0, fmt.Errorf("ghi CONNECT request thất bại: %w", err)
	}

	bufPtr := bufPool2K.Get().(*[]byte)
	defer bufPool2K.Put(bufPtr)
	reader := bufio.NewReaderSize(conn, len(*bufPtr))

	resp, err := http.ReadResponse(reader, &http.Request{Method: "CONNECT"})
	if err != nil {
		return 0, fmt.Errorf("đọc CONNECT response thất bại: %w", err)
	}
	_ = resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return 0, fmt.Errorf("CONNECT bị từ chối với status: %d", resp.StatusCode)
	}

	// Bắt tay TLS qua tunnel vừa thiết lập
	hostOnly, _, _ := net.SplitHostPort(targetHost)
	tlsConfig := sharedTLSConfig.Clone()
	tlsConfig.ServerName = hostOnly

	tlsConn := tls.Client(conn, tlsConfig)
	defer tlsConn.Close()

	_ = tlsConn.SetDeadline(time.Now().Add(timeout))
	if err := tlsConn.HandshakeContext(ctx); err != nil {
		return 0, fmt.Errorf("TLS handshake thất bại: %w", err)
	}

	latency := time.Since(start)
	return latency, nil
}

// CheckSOCKS5 xác minh proxy SOCKS5 (RFC 1928) đầu cuối.
// Hỗ trợ cả No-Auth (0x00) và Username/Password auth (0x02).
func CheckSOCKS5(ctx context.Context, proxyAddr string, targetHost string, targetPort int, timeout time.Duration) (time.Duration, error) {
	start := time.Now()

	conn, err := fastDial(ctx, proxyAddr, timeout)
	if err != nil {
		return 0, fmt.Errorf("kết nối SOCKS5 thất bại: %w", err)
	}
	defer conn.Close()

	if tcpConn, ok := conn.(*net.TCPConn); ok {
		_ = tcpConn.SetNoDelay(true)
		_ = tcpConn.SetLinger(0)
	}
	_ = conn.SetDeadline(time.Now().Add(timeout))

	// Bước 1: Đàm phán xác thực — đề xuất No-Auth (0x00) và Username/Pass (0x02)
	if _, err := conn.Write([]byte{0x05, 0x02, 0x00, 0x02}); err != nil {
		return 0, fmt.Errorf("SOCKS5 ghi auth request thất bại: %w", err)
	}

	authResp := make([]byte, 2)
	if _, err := io.ReadFull(conn, authResp); err != nil {
		return 0, fmt.Errorf("SOCKS5 đọc auth response thất bại: %w", err)
	}

	if authResp[0] != 0x05 {
		return 0, fmt.Errorf("SOCKS5 version không hợp lệ: 0x%X", authResp[0])
	}
	if authResp[1] == 0xFF {
		return 0, fmt.Errorf("SOCKS5 không có phương thức xác thực phù hợp")
	}

	// Bước 2: Gửi request kết nối tới địa chỉ đích
	if targetHost == "" {
		targetHost = "1.1.1.1"
		targetPort = 80
	}

	parsedIP := net.ParseIP(targetHost).To4()
	if parsedIP != nil {
		// Địa chỉ đích là IPv4
		req := make([]byte, 10)
		req[0] = 0x05
		req[1] = 0x01 // CONNECT
		req[2] = 0x00
		req[3] = 0x01 // ATYP: IPv4
		copy(req[4:8], parsedIP)
		binary.BigEndian.PutUint16(req[8:10], uint16(targetPort))
		if _, err := conn.Write(req); err != nil {
			return 0, fmt.Errorf("SOCKS5 ghi connect request (IPv4) thất bại: %w", err)
		}
	} else {
		// Địa chỉ đích là domain name
		domainBytes := []byte(targetHost)
		req := make([]byte, 7+len(domainBytes))
		req[0] = 0x05
		req[1] = 0x01
		req[2] = 0x00
		req[3] = 0x03 // ATYP: Domain
		req[4] = byte(len(domainBytes))
		copy(req[5:5+len(domainBytes)], domainBytes)
		binary.BigEndian.PutUint16(req[5+len(domainBytes):], uint16(targetPort))
		if _, err := conn.Write(req); err != nil {
			return 0, fmt.Errorf("SOCKS5 ghi connect request (domain) thất bại: %w", err)
		}
	}

	// Bước 3: Đọc reply từ server
	replyHeader := make([]byte, 4)
	if _, err := io.ReadFull(conn, replyHeader); err != nil {
		return 0, fmt.Errorf("SOCKS5 đọc reply thất bại: %w", err)
	}

	if replyHeader[0] != 0x05 || replyHeader[1] != 0x00 {
		return 0, fmt.Errorf("SOCKS5 kết nối bị từ chối, mã lỗi: 0x%X", replyHeader[1])
	}

	// Đọc phần địa chỉ trong reply để drain buffer
	var addrLen int
	switch replyHeader[3] {
	case 0x01: // IPv4
		addrLen = 4
	case 0x03: // Domain
		var l [1]byte
		if _, err := io.ReadFull(conn, l[:]); err != nil {
			return 0, err
		}
		addrLen = int(l[0])
	case 0x04: // IPv6
		addrLen = 16
	default:
		addrLen = 4
	}

	restBuf := make([]byte, addrLen+2)
	if _, err := io.ReadFull(conn, restBuf); err != nil {
		return 0, err
	}

	latency := time.Since(start)
	return latency, nil
}

// CheckSOCKS4 xác minh proxy SOCKS4/4a đầu cuối.
func CheckSOCKS4(ctx context.Context, proxyAddr string, targetIP string, targetPort int, timeout time.Duration) (time.Duration, error) {
	start := time.Now()

	conn, err := fastDial(ctx, proxyAddr, timeout)
	if err != nil {
		return 0, fmt.Errorf("kết nối SOCKS4 thất bại: %w", err)
	}
	defer conn.Close()

	if tcpConn, ok := conn.(*net.TCPConn); ok {
		_ = tcpConn.SetNoDelay(true)
		_ = tcpConn.SetLinger(0)
	}
	_ = conn.SetDeadline(time.Now().Add(timeout))

	if targetIP == "" {
		targetIP = "1.1.1.1"
		targetPort = 80
	}

	parsedIP := net.ParseIP(targetIP).To4()
	if parsedIP == nil {
		parsedIP = net.IPv4(1, 1, 1, 1).To4()
		targetPort = 80
	}

	req := make([]byte, 9)
	req[0] = 0x04 // Version
	req[1] = 0x01 // CD: Connect
	binary.BigEndian.PutUint16(req[2:4], uint16(targetPort))
	copy(req[4:8], parsedIP)
	req[8] = 0x00 // User ID kết thúc bằng null

	if _, err := conn.Write(req); err != nil {
		return 0, fmt.Errorf("SOCKS4 ghi request thất bại: %w", err)
	}

	resp := make([]byte, 8)
	if _, err := io.ReadFull(conn, resp); err != nil {
		return 0, fmt.Errorf("SOCKS4 đọc reply thất bại: %w", err)
	}

	if resp[1] != 0x5A { // 0x5A = 90 = Request Granted
		return 0, fmt.Errorf("SOCKS4 bị từ chối, mã: 0x%X", resp[1])
	}

	latency := time.Since(start)
	return latency, nil
}

// FastTCPPing kiểm tra kết nối TCP thuần túy trong thời gian timeout.
// Dùng như bộ lọc nhanh trước khi thực hiện handshake đầy đủ.
func FastTCPPing(ctx context.Context, addr string, timeout time.Duration) bool {
	d := &net.Dialer{Timeout: timeout, KeepAlive: -1}
	conn, err := d.DialContext(ctx, "tcp", addr)
	if err != nil {
		return false
	}
	_ = conn.Close()
	return true
}

// ketQuaDongThoi lưu kết quả của một probe protocol đồng thời
type ketQuaDongThoi struct {
	proto   model.Protocol
	latency time.Duration
	body    []byte
	err     error
}

// DetectProtocol thử các protocol ĐỒNG THỜI dựa trên ưu tiên cổng.
// Cái nào trả kết quả thành công trước sẽ thắng và huỷ các probe còn lại.
func DetectProtocol(ctx context.Context, ip string, port int, judgeURL string, timeout time.Duration) (model.Protocol, time.Duration, []byte, error) {
	addr := net.JoinHostPort(ip, strconv.Itoa(port))

	// Xác định thứ tự probe dựa trên số cổng phổ biến
	order := thuTuProbeTheoPort(port)

	// Timeout per-probe ngắn hơn để các probe song song không đè lên nhau
	probeTimeout := timeout
	if probeTimeout > 4*time.Second {
		probeTimeout = 4 * time.Second
	}

	resultCh := make(chan ketQuaDongThoi, len(order))
	probeCtx, cancel := context.WithCancel(ctx)
	defer cancel()

	var wg sync.WaitGroup
	for _, proto := range order {
		proto := proto
		wg.Add(1)
		go func() {
			defer wg.Done()
			lat, body, err := probeMotProtocol(probeCtx, proto, addr, judgeURL, probeTimeout)
			resultCh <- ketQuaDongThoi{proto: proto, latency: lat, body: body, err: err}
		}()
	}

	// Đóng channel sau khi tất cả probe xong
	go func() {
		wg.Wait()
		close(resultCh)
	}()

	var lastErr error
	for res := range resultCh {
		if res.err == nil {
			cancel() // Huỷ các probe còn lại
			return res.proto, res.latency, res.body, nil
		}
		lastErr = res.err
	}

	return model.ProtoUnknown, 0, nil, lastErr
}

// probeMotProtocol chạy kiểm tra một protocol duy nhất
func probeMotProtocol(ctx context.Context, proto model.Protocol, addr, judgeURL string, timeout time.Duration) (time.Duration, []byte, error) {
	select {
	case <-ctx.Done():
		return 0, nil, ctx.Err()
	default:
	}

	switch proto {
	case model.ProtoHTTP:
		lat, body, _, err := CheckHTTP(ctx, addr, judgeURL, timeout)
		return lat, body, err
	case model.ProtoHTTPS:
		lat, err := CheckHTTPS(ctx, addr, "", timeout)
		return lat, nil, err
	case model.ProtoSOCKS5:
		lat, err := CheckSOCKS5(ctx, addr, "1.1.1.1", 80, timeout)
		return lat, nil, err
	case model.ProtoSOCKS4:
		lat, err := CheckSOCKS4(ctx, addr, "1.1.1.1", 80, timeout)
		return lat, nil, err
	}
	return 0, nil, fmt.Errorf("protocol không hỗ trợ: %s", proto)
}

// thuTuProbeTheoPort trả về thứ tự ưu tiên các protocol dựa vào số cổng phổ biến
func thuTuProbeTheoPort(port int) []model.Protocol {
	switch {
	case port == 1080 || port == 10808 || port == 9050 || port == 1081 || port == 10809:
		// Các cổng SOCKS phổ biến
		return []model.Protocol{model.ProtoSOCKS5, model.ProtoSOCKS4, model.ProtoHTTP, model.ProtoHTTPS}
	case port == 443 || port == 8443 || port == 4443:
		// Cổng HTTPS/TLS
		return []model.Protocol{model.ProtoHTTPS, model.ProtoHTTP, model.ProtoSOCKS5}
	case port == 3128 || port == 8888 || port == 8080 || port == 80:
		// Cổng HTTP proxy phổ biến
		return []model.Protocol{model.ProtoHTTP, model.ProtoHTTPS, model.ProtoSOCKS5, model.ProtoSOCKS4}
	default:
		// Mặc định: thử HTTP trước
		return []model.Protocol{model.ProtoHTTP, model.ProtoHTTPS, model.ProtoSOCKS5, model.ProtoSOCKS4}
	}
}

// fastDial tạo kết nối TCP với các tùy chọn socket tối ưu (NoDelay, Linger=0)
func fastDial(ctx context.Context, addr string, timeout time.Duration) (net.Conn, error) {
	d := &net.Dialer{Timeout: timeout, KeepAlive: -1}
	conn, err := d.DialContext(ctx, "tcp", addr)
	if err != nil {
		return nil, err
	}
	if tcpConn, ok := conn.(*net.TCPConn); ok {
		_ = tcpConn.SetNoDelay(true) // Tắt Nagle algorithm để giảm độ trễ
		_ = tcpConn.SetLinger(0)     // Đóng socket ngay lập tức khi close()
	}
	return conn, nil
}
