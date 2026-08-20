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

	if resp.StatusCode != http.StatusOK {
		return latency, nil, resp.Header, fmt.Errorf("status code không phải 200 OK: %d", resp.StatusCode)
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

// validateJudgeResponse xác thực nghiêm ngặt phản hồi từ Judge.
// CHỈ CHẤP NHẬN nếu Judge trả về địa chỉ IP thực tế (JSON IP echo hoặc plain text IP hoặc AZENV).
// Toàn bộ các trang web thông thường, Router MikroTik/TP-Link, 404/Login page đều bị loại bỏ 100%.
func validateJudgeResponse(headers http.Header, body []byte) error {
	trimmed := bytes.TrimSpace(body)
	if len(trimmed) < 4 {
		return fmt.Errorf("false positive: body quá ngắn (%d bytes)", len(trimmed))
	}

	lowerBody := bytes.ToLower(trimmed)

	// Lớp 1: Bất kỳ HTML thông thường nào (trang web, router, login portal) -> Loại bỏ 100%
	if bytes.HasPrefix(lowerBody, []byte("<!doctype")) ||
		bytes.HasPrefix(lowerBody, []byte("<html")) ||
		bytes.HasPrefix(lowerBody, []byte("<head")) ||
		bytes.HasPrefix(lowerBody, []byte("<body")) ||
		bytes.Contains(lowerBody, []byte("<title>")) ||
		bytes.Contains(lowerBody, []byte("<script")) ||
		bytes.Contains(lowerBody, []byte("<div")) ||
		bytes.Contains(lowerBody, []byte("<p>")) {

		// Chỉ chấp nhận nếu HTML đó thực chất là trang AZENV có chứa REMOTE_ADDR = <ip_hợp_lệ>
		if ip := extractAzenvIP(trimmed); ip != "" {
			return nil
		}
		return fmt.Errorf("false positive: phát hiện trang web HTML / Router thay vì proxy thật")
	}

	// Lớp 2: Thử parse JSON chứa trường "ip" hoặc "origin" (chuẩn httpbin, ipify, ifconfig.co, v.v.)
	if trimmed[0] == '{' {
		var jr judgeResponse
		if err := json.Unmarshal(trimmed, &jr); err == nil {
			ip := jr.IP
			if ip == "" {
				ip = jr.Origin
				if idx := strings.Index(ip, ","); idx > 0 {
					ip = strings.TrimSpace(ip[:idx])
				}
			}
			ip = strings.TrimSpace(ip)
			if ip != "" && net.ParseIP(ip) != nil {
				// JSON chứa IP echo hợp lệ
				return nil
			}
		}

		// Thử generic JSON unmarshal nếu key khác
		var genericMap map[string]interface{}
		if err := json.Unmarshal(trimmed, &genericMap); err == nil {
			for _, k := range []string{"ip", "origin", "query", "client_ip", "remote_addr"} {
				if val, exists := genericMap[k]; exists {
					if strVal, ok := val.(string); ok {
						strVal = strings.TrimSpace(strVal)
						if net.ParseIP(strVal) != nil {
							return nil
						}
					}
				}
			}
		}
	}

	// Lớp 3: Thử parse dạng plain text IP (chuẩn ifconfig.me/ip, icanhazip.com, api.ipify.org)
	strBody := strings.Trim(string(trimmed), "\"'\r\n\t ")
	if net.ParseIP(strBody) != nil {
		// Trả về đúng 1 địa chỉ IP hợp lệ
		return nil
	}

	// Lớp 4: Kiểm tra định dạng AZENV (REMOTE_ADDR = ...)
	if ip := extractAzenvIP(trimmed); ip != "" {
		return nil
	}

	return fmt.Errorf("false positive: phản hồi không chứa IP echo hợp lệ từ judge")
}

// extractAzenvIP trích xuất và xác thực IP từ dữ liệu AZENV
func extractAzenvIP(body []byte) string {
	lines := strings.Split(string(body), "\n")
	for _, l := range lines {
		l = strings.TrimSpace(l)
		if strings.HasPrefix(l, "REMOTE_ADDR") || strings.HasPrefix(l, "HTTP_CLIENT_IP") {
			parts := strings.SplitN(l, "=", 2)
			if len(parts) == 2 {
				ipStr := strings.TrimSpace(parts[1])
				ipStr = strings.Trim(ipStr, "\"' \r\t")
				if net.ParseIP(ipStr) != nil {
					return ipStr
				}
			}
		}
	}
	return ""
}

// CheckHTTPS xác minh HTTPS CONNECT tunnel với TLS handshake và HTTP request thực tế.
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
		"CONNECT %s HTTP/1.1\r\nHost: %s\r\nUser-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36\r\nProxy-Connection: Keep-Alive\r\n\r\n",
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

	// Bắt tay TLS qua tunnel vừa thiết lập với chứng chỉ thật
	hostOnly, _, _ := net.SplitHostPort(targetHost)
	tlsConfig := &tls.Config{
		ServerName:         hostOnly,
		InsecureSkipVerify: true,
		MinVersion:         tls.VersionTLS10,
	}

	tlsConn := tls.Client(conn, tlsConfig)
	defer tlsConn.Close()

	_ = tlsConn.SetDeadline(time.Now().Add(timeout))
	if err := tlsConn.HandshakeContext(ctx); err != nil {
		return 0, fmt.Errorf("TLS handshake thất bại: %w", err)
	}

	// Xác minh truyền tải dữ liệu thực tế qua TLS tunnel
	probeReq := fmt.Sprintf("GET /?format=json HTTP/1.1\r\nHost: %s\r\nUser-Agent: GoProxy/2.0\r\nConnection: close\r\n\r\n", hostOnly)
	if _, err := tlsConn.Write([]byte(probeReq)); err != nil {
		return 0, fmt.Errorf("gửi probe qua TLS thất bại: %w", err)
	}
	tlsReader := bufio.NewReaderSize(tlsConn, 2048)
	tlsResp, err := http.ReadResponse(tlsReader, &http.Request{Method: "GET"})
	if err != nil {
		return 0, fmt.Errorf("đọc phản hồi qua TLS thất bại: %w", err)
	}
	_ = tlsResp.Body.Close()
	if tlsResp.StatusCode != http.StatusOK {
		return 0, fmt.Errorf("TLS target trả về status: %d", tlsResp.StatusCode)
	}

	latency := time.Since(start)
	return latency, nil
}

// CheckSOCKS5 xác minh proxy SOCKS5 (RFC 1928) đầu cuối với probe thực tế.
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

	// Bước 1: Đàm phán xác thực
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

	// Bước 2: Gửi request kết nối tới địa chỉ đích (1.1.1.1:80)
	if targetHost == "" {
		targetHost = "1.1.1.1"
		targetPort = 80
	}

	parsedIP := net.ParseIP(targetHost).To4()
	if parsedIP != nil {
		req := make([]byte, 10)
		req[0] = 0x05
		req[1] = 0x01 // CONNECT
		req[2] = 0x00
		req[3] = 0x01 // ATYP: IPv4
		copy(req[4:8], parsedIP)
		binary.BigEndian.PutUint16(req[8:10], uint16(targetPort))
		if _, err := conn.Write(req); err != nil {
			return 0, fmt.Errorf("SOCKS5 ghi connect request thất bại: %w", err)
		}
	} else {
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

	// Bước 4: Kiểm tra truyền tải end-to-end qua SOCKS5 tunnel
	probe := "GET / HTTP/1.1\r\nHost: 1.1.1.1\r\nUser-Agent: GoProxy/2.0\r\nConnection: close\r\n\r\n"
	if _, err := conn.Write([]byte(probe)); err != nil {
		return 0, fmt.Errorf("SOCKS5 ghi probe thất bại: %w", err)
	}
	probeResp := make([]byte, 12)
	if _, err := io.ReadAtLeast(conn, probeResp, 4); err != nil {
		return 0, fmt.Errorf("SOCKS5 nhận phản hồi probe thất bại: %w", err)
	}
	if !bytes.HasPrefix(probeResp, []byte("HTTP/")) {
		return 0, fmt.Errorf("SOCKS5 không chuyển tiếp dữ liệu HTTP hợp lệ")
	}

	latency := time.Since(start)
	return latency, nil
}

// CheckSOCKS4 xác minh proxy SOCKS4/4a đầu cuối với probe thực tế.
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
	req[8] = 0x00

	if _, err := conn.Write(req); err != nil {
		return 0, fmt.Errorf("SOCKS4 ghi request thất bại: %w", err)
	}

	resp := make([]byte, 8)
	if _, err := io.ReadFull(conn, resp); err != nil {
		return 0, fmt.Errorf("SOCKS4 đọc reply thất bại: %w", err)
	}

	if resp[1] != 0x5A {
		return 0, fmt.Errorf("SOCKS4 bị từ chối, mã: 0x%X", resp[1])
	}

	// Bước 3: Kiểm tra truyền tải end-to-end qua SOCKS4 tunnel
	probe := "GET / HTTP/1.1\r\nHost: 1.1.1.1\r\nUser-Agent: GoProxy/2.0\r\nConnection: close\r\n\r\n"
	if _, err := conn.Write([]byte(probe)); err != nil {
		return 0, fmt.Errorf("SOCKS4 ghi probe thất bại: %w", err)
	}
	probeResp := make([]byte, 12)
	if _, err := io.ReadAtLeast(conn, probeResp, 4); err != nil {
		return 0, fmt.Errorf("SOCKS4 nhận phản hồi probe thất bại: %w", err)
	}
	if !bytes.HasPrefix(probeResp, []byte("HTTP/")) {
		return 0, fmt.Errorf("SOCKS4 không chuyển tiếp dữ liệu HTTP hợp lệ")
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
