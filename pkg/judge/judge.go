package judge

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"goproxy/pkg/model"
)

var (
	cachedPublicIP string
	publicIPOnce   sync.Once
)

// GetHostPublicIP tự động lấy địa chỉ IP Public của máy chủ hiện tại
func GetHostPublicIP() string {
	publicIPOnce.Do(func() {
		discoveryEndpoints := []string{
			"http://api.ipify.org",
			"http://icanhazip.com",
			"http://checkip.amazonaws.com",
			"http://ifconfig.me/ip",
		}
		client := &http.Client{Timeout: 3 * time.Second}
		for _, ep := range discoveryEndpoints {
			resp, err := client.Get(ep)
			if err == nil && resp.StatusCode == 200 {
				body, err := io.ReadAll(io.LimitReader(resp.Body, 64))
				_ = resp.Body.Close()
				if err == nil {
					ipStr := strings.TrimSpace(string(body))
					if parsed := net.ParseIP(ipStr); parsed != nil {
						cachedPublicIP = ipStr
						return
					}
				}
			}
		}

		// Fallback nếu không có internet: thử lấy IP từ network interface
		if addrs, err := net.InterfaceAddrs(); err == nil {
			for _, addr := range addrs {
				if ipNet, ok := addr.(*net.IPNet); ok && !ipNet.IP.IsLoopback() {
					if ipNet.IP.To4() != nil {
						cachedPublicIP = ipNet.IP.String()
						return
					}
				}
			}
		}

		cachedPublicIP = "127.0.0.1"
	})
	return cachedPublicIP
}

// ResolveJudgeURL tự động chuyển đổi path tương đối (/json, /judge, /ip) hoặc template {MY_IP} thành URL đầy đủ với IP/Port thật
func ResolveJudgeURL(rawURL string, serverPort string) string {
	rawURL = strings.TrimSpace(rawURL)
	if rawURL == "" {
		return ""
	}

	port := strings.TrimPrefix(serverPort, ":")
	if port == "" {
		port = "8080"
	}

	publicIP := GetHostPublicIP()

	// Nếu cấu hình chỉ để path như: "/json", "/judge", "/ip"
	if strings.HasPrefix(rawURL, "/") {
		return fmt.Sprintf("http://%s:%s%s", publicIP, port, rawURL)
	}

	// Nếu cấu hình chứa placeholder {MY_IP} hoặc {PORT}
	rawURL = strings.ReplaceAll(rawURL, "{MY_IP}", publicIP)
	rawURL = strings.ReplaceAll(rawURL, "{HOST}", publicIP)
	rawURL = strings.ReplaceAll(rawURL, "{PORT}", port)

	return rawURL
}

// judgeEntry tracks the health and latency of a single judge URL
type judgeEntry struct {
	url       string
	latencyMs int64 // atomic EMA latency
	healthy   int32 // atomic: 1 = healthy, 0 = dead
}

// Evaluator evaluates proxy anonymity and manages a healthy judge pool
type Evaluator struct {
	myIP       string
	myIPOnce   sync.Once
	serverPort string
	judges     []*judgeEntry
	mu         sync.RWMutex
	httpClient *http.Client
}

// NewEvaluator creates a new Evaluator with dynamic judge URL resolution based on server port configuration
func NewEvaluator(judges []string, customJudge string, serverAddr ...string) *Evaluator {
	port := "8080"
	if len(serverAddr) > 0 && serverAddr[0] != "" {
		port = serverAddr[0]
	}

	list := []string{}
	if customJudge != "" {
		resolved := ResolveJudgeURL(customJudge, port)
		if resolved != "" {
			list = append(list, resolved)
		}
	}
	if len(judges) > 0 {
		for _, u := range judges {
			resolved := ResolveJudgeURL(u, port)
			if resolved != "" {
				list = append(list, resolved)
			}
		}
	} else {
		list = []string{
			ResolveJudgeURL("/json", port),
			ResolveJudgeURL("/judge", port),
			ResolveJudgeURL("/ip", port),
		}
	}

	entries := make([]*judgeEntry, 0, len(list))
	for _, u := range list {
		e := &judgeEntry{url: u}
		atomic.StoreInt32(&e.healthy, 1)
		atomic.StoreInt64(&e.latencyMs, 500) // initial estimate
		entries = append(entries, e)
	}

	ev := &Evaluator{
		serverPort: port,
		judges:     entries,
		httpClient: &http.Client{
			Timeout: 5 * time.Second,
			Transport: &http.Transport{
				MaxIdleConns:        500,
				MaxIdleConnsPerHost: 100,
				IdleConnTimeout:     60 * time.Second,
				DisableKeepAlives:   false,
			},
		},
	}

	// Start background health checker
	go ev.healthLoop()
	return ev
}

// healthLoop checks each judge every 60s and updates healthy/latency
func (e *Evaluator) healthLoop() {
	ticker := time.NewTicker(60 * time.Second)
	defer ticker.Stop()
	// Run initial check immediately
	e.checkAllJudges()
	for range ticker.C {
		e.checkAllJudges()
	}
}

func (e *Evaluator) checkAllJudges() {
	for _, j := range e.judges {
		j := j
		go func() {
			start := time.Now()
			ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
			defer cancel()
			req, err := http.NewRequestWithContext(ctx, "GET", j.url, nil)
			if err != nil {
				atomic.StoreInt32(&j.healthy, 0)
				return
			}
			resp, err := e.httpClient.Do(req)
			if err != nil || resp.StatusCode >= 400 {
				atomic.StoreInt32(&j.healthy, 0)
				if resp != nil {
					_ = resp.Body.Close()
				}
				return
			}
			_, _ = io.Copy(io.Discard, io.LimitReader(resp.Body, 1024))
			_ = resp.Body.Close()

			ms := time.Since(start).Milliseconds()
			// EMA smoothing: new = 0.3*sample + 0.7*old
			old := atomic.LoadInt64(&j.latencyMs)
			newMs := int64(0.3*float64(ms) + 0.7*float64(old))
			atomic.StoreInt64(&j.latencyMs, newMs)
			atomic.StoreInt32(&j.healthy, 1)
		}()
	}
}

// PickJudge returns the fastest healthy judge URL
func (e *Evaluator) PickJudge() string {
	var best *judgeEntry
	for _, j := range e.judges {
		if atomic.LoadInt32(&j.healthy) == 0 {
			continue
		}
		if best == nil || atomic.LoadInt64(&j.latencyMs) < atomic.LoadInt64(&best.latencyMs) {
			best = j
		}
	}
	if best != nil {
		return best.url
	}
	// All judges dead — fallback to first
	if len(e.judges) > 0 {
		return e.judges[0].url
	}
	return ResolveJudgeURL("/json", e.serverPort)
}

// GetMyPublicIP fetches the host's actual public IP to detect transparent proxies
func (e *Evaluator) GetMyPublicIP() string {
	if e.myIP != "" {
		return e.myIP
	}
	e.myIPOnce.Do(func() {
		for _, j := range e.judges {
			if atomic.LoadInt32(&j.healthy) == 0 {
				continue
			}
			ctx, cancel := context.WithTimeout(context.Background(), 4*time.Second)
			req, err2 := http.NewRequestWithContext(ctx, "GET", j.url, nil)
			if err2 != nil {
				cancel()
				continue
			}
			resp, err := e.httpClient.Do(req)
			cancel()
			if err != nil {
				continue
			}
			body, _ := io.ReadAll(io.LimitReader(resp.Body, 4096))
			_ = resp.Body.Close()

			if ip := extractIPFromBody(body); ip != "" {
				e.myIP = ip
				return
			}
		}
	})
	return e.myIP
}

// extractIPFromBody parses an IP address from a judge response body
func extractIPFromBody(body []byte) string {
	var data struct {
		Origin string `json:"origin"`
		IP     string `json:"ip"`
	}
	if err := json.Unmarshal(body, &data); err == nil {
		if data.Origin != "" {
			parts := strings.Split(data.Origin, ",")
			return strings.TrimSpace(parts[0])
		}
		if data.IP != "" {
			return strings.TrimSpace(data.IP)
		}
	}
	str := strings.TrimSpace(string(body))
	if parsed := net.ParseIP(str); parsed != nil {
		return str
	}
	return ""
}

// EvaluateAnonymity determines whether proxy is Transparent, Anonymous, or Elite
// using a comprehensive set of proxy-revealing headers and body patterns
func (e *Evaluator) EvaluateAnonymity(headers http.Header, body []byte) model.Anonymity {
	myIP := e.GetMyPublicIP()

	// 1. Check if real IP is leaked in headers or body
	if myIP != "" {
		for _, v := range headers {
			for _, val := range v {
				if strings.Contains(val, myIP) {
					return model.AnonTransparent
				}
			}
		}
		if bytes.Contains(body, []byte(myIP)) {
			return model.AnonTransparent
		}
	}

	// 2. Comprehensive proxy signature header check (expanded from 9 → 18 headers)
	proxyHeaders := []string{
		"Via",
		"X-Forwarded-For",
		"X-Forwarded-Proto",
		"X-Forwarded-Host",
		"X-Proxy-ID",
		"Forwarded",
		"Proxy-Connection",
		"X-Real-IP",
		"Client-IP",
		"X-BlueCoat-Via",
		"X-Client-IP",
		"HTTP-X-Forwarded-For",
		"X-Cluster-Client-IP",
		"X-Original-Forwarded-For",
		"True-Client-IP",
		"CF-Connecting-IP",
		"X-ProxyUser-Ip",
		"WL-Proxy-Client-IP",
	}

	for _, h := range proxyHeaders {
		if headers.Get(h) != "" {
			return model.AnonAnonymous
		}
	}

	// 3. AZENV-style body scan for proxy variables
	bodyUpper := strings.ToUpper(string(body))
	azenvMarkers := []string{
		"HTTP_VIA", "HTTP_X_FORWARDED_FOR", "HTTP_PROXY_CONNECTION",
		"HTTP_X_REAL_IP", "HTTP_CLIENT_IP", "HTTP_FORWARDED",
		"HTTP_X_CLUSTER_CLIENT_IP",
	}
	for _, marker := range azenvMarkers {
		if strings.Contains(bodyUpper, marker) {
			return model.AnonAnonymous
		}
	}

	return model.AnonElite
}
