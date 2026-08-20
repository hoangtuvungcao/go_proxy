package server

import (
	"context"
	_ "embed"
	"encoding/json"
	"fmt"
	"net/http"
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

//go:embed dashboard.html
var dashboardHTML string

// wsClient represents a connected WebSocket-like SSE client
type sseClient struct {
	ch     chan []byte
	closed chan struct{}
}

// APIServer manages REST API, Real-Time SSE Stream, Prometheus Metrics, and Web Dashboard
type APIServer struct {
	addr    string
	storage *storage.SQLiteStore
	server  *http.Server
	stats   *model.Stats
	checker *checker.Checker

	// SSE broadcast
	sseClients   map[*sseClient]struct{}
	sseClientsMu sync.RWMutex
	sseBroadcast chan []byte
}

// NewAPIServer creates a new API and Web server
func NewAPIServer(addr string, store *storage.SQLiteStore, stats *model.Stats) *APIServer {
	if addr == "" {
		addr = ":8080"
	}
	api := &APIServer{
		addr:         addr,
		storage:      store,
		stats:        stats,
		checker:      checker.NewChecker(model.DefaultConfig()),
		sseClients:   make(map[*sseClient]struct{}),
		sseBroadcast: make(chan []byte, 256),
	}

	go api.broadcastLoop()

	mux := http.NewServeMux()
	mux.HandleFunc("/api/v1/proxies", api.handleProxies)
	mux.HandleFunc("/api/v1/random", api.handleRandom)
	mux.HandleFunc("/api/v1/stats", api.handleStats)
	mux.HandleFunc("/api/v1/stats/history", api.handleStatsHistory)
	mux.HandleFunc("/api/v1/stats/breakdown", api.handleStatsBreakdown)
	mux.HandleFunc("/api/v1/test", api.handleTest)
	mux.HandleFunc("/api/v1/stream", api.handleStream)
	mux.HandleFunc("/api/v1/export", api.handleExport)
	mux.HandleFunc("/api/v1/top", api.handleTop)
	mux.HandleFunc("/metrics", api.handleMetrics)
	mux.HandleFunc("/healthz", api.handleHealthz)
	mux.HandleFunc("/", api.handleDashboard)

	api.server = &http.Server{
		Addr:         addr,
		Handler:      corsMiddleware(mux),
		ReadTimeout:  30 * time.Second,
		WriteTimeout: 60 * time.Second,
		IdleTimeout:  120 * time.Second,
	}

	return api
}

// Start launches the REST API and Dashboard
func (s *APIServer) Start() error {
	color.New(color.FgHiCyan, color.Bold).Printf("[*] REST API & Web Dashboard → http://localhost%s\n", s.addr)
	return s.server.ListenAndServe()
}

// Close gracefully stops the server
func (s *APIServer) Close() error {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	return s.server.Shutdown(ctx)
}

func corsMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Access-Control-Allow-Origin", "*")
		w.Header().Set("Access-Control-Allow-Methods", "GET, POST, OPTIONS")
		w.Header().Set("Access-Control-Allow-Headers", "Content-Type, Authorization")
		if r.Method == http.MethodOptions {
			w.WriteHeader(http.StatusOK)
			return
		}
		next.ServeHTTP(w, r)
	})
}

// BroadcastProxy sends a newly found proxy to all SSE clients
func (s *APIServer) BroadcastProxy(p *model.Proxy) {
	data, err := json.Marshal(map[string]interface{}{
		"type":  "proxy",
		"proxy": p,
	})
	if err != nil {
		return
	}
	select {
	case s.sseBroadcast <- data:
	default:
		// Drop if broadcast buffer full
	}
}

// broadcastLoop distributes SSE events to all connected clients
func (s *APIServer) broadcastLoop() {
	for data := range s.sseBroadcast {
		s.sseClientsMu.RLock()
		for client := range s.sseClients {
			select {
			case client.ch <- data:
			case <-client.closed:
			default:
			}
		}
		s.sseClientsMu.RUnlock()
	}
}

func (s *APIServer) handleProxies(w http.ResponseWriter, r *http.Request) {
	q := r.URL.Query()
	limit, _ := strconv.Atoi(q.Get("limit"))
	if limit <= 0 || limit > 5000 {
		limit = 100
	}
	offset, _ := strconv.Atoi(q.Get("offset"))
	minScore, _ := strconv.Atoi(q.Get("min_score"))
	maxLat, _ := strconv.ParseInt(q.Get("max_latency"), 10, 64)

	filter := storage.ProxyFilter{
		Protocol:    q.Get("protocol"),
		CountryCode: q.Get("country"),
		Anonymity:   q.Get("anonymity"),
		MinScore:    minScore,
		MaxLatency:  maxLat,
		OnlyAlive:   q.Get("alive") != "false",
		Limit:       limit,
		Offset:      offset,
	}

	list, err := s.storage.QueryProxies(filter)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	format := q.Get("format")
	switch format {
	case "txt", "text":
		w.Header().Set("Content-Type", "text/plain")
		for _, p := range list {
			_, _ = fmt.Fprintln(w, p.URLString())
		}
	case "csv":
		w.Header().Set("Content-Type", "text/csv")
		w.Header().Set("Content-Disposition", `attachment; filename="proxies.csv"`)
		_, _ = fmt.Fprintln(w, "protocol,ip,port,anonymity,country_code,latency_ms,score,uptime_percent")
		for _, p := range list {
			_, _ = fmt.Fprintf(w, "%s,%s,%d,%s,%s,%d,%d,%.1f\n",
				p.Protocol, p.IP, p.Port, p.Anonymity, p.CountryCode, p.LatencyMs, p.Score, p.UptimePercent)
		}
	default:
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]interface{}{
			"total":   len(list),
			"offset":  offset,
			"proxies": list,
		})
	}
}

func (s *APIServer) handleRandom(w http.ResponseWriter, r *http.Request) {
	q := r.URL.Query()
	p, err := s.storage.GetRandomAliveProxy(q.Get("protocol"), q.Get("country"))
	if err != nil {
		http.Error(w, err.Error(), http.StatusNotFound)
		return
	}

	if q.Get("format") == "json" {
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(p)
		return
	}

	w.Header().Set("Content-Type", "text/plain")
	_, _ = fmt.Fprint(w, p.URLString())
}

func (s *APIServer) handleStats(w http.ResponseWriter, r *http.Request) {
	aliveCount, _ := s.storage.TotalAliveCount()
	var liveStats map[string]interface{}
	if s.stats != nil {
		liveStats = s.stats.Snapshot()
	}

	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(map[string]interface{}{
		"total_alive_in_db": aliveCount,
		"live_metrics":      liveStats,
		"server_time":       time.Now().Format(time.RFC3339),
	})
}

// handleStatsHistory returns the last 120 seconds of scan history for charts
func (s *APIServer) handleStatsHistory(w http.ResponseWriter, r *http.Request) {
	if s.stats == nil {
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode([]interface{}{})
		return
	}
	history := s.stats.GetHistory()
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(history)
}

// handleStatsBreakdown returns detailed protocol and country breakdown
func (s *APIServer) handleStatsBreakdown(w http.ResponseWriter, r *http.Request) {
	aliveByProto, err := s.storage.CountByProtocol()
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	aliveByCountry, err := s.storage.CountByCountry(10)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	aliveByAnon, err := s.storage.CountByAnonymity()
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(map[string]interface{}{
		"by_protocol":  aliveByProto,
		"by_country":   aliveByCountry,
		"by_anonymity": aliveByAnon,
	})
}

// handleTop returns the top proxies ranked by score or latency
func (s *APIServer) handleTop(w http.ResponseWriter, r *http.Request) {
	q := r.URL.Query()
	limit, _ := strconv.Atoi(q.Get("limit"))
	if limit <= 0 || limit > 100 {
		limit = 20
	}
	list, err := s.storage.QueryProxies(storage.ProxyFilter{
		OnlyAlive: true,
		MinScore:  60,
		Limit:     limit,
	})
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(map[string]interface{}{
		"total":   len(list),
		"proxies": list,
	})
}

// handleTest executes on-demand verification for a single proxy
func (s *APIServer) handleTest(w http.ResponseWriter, r *http.Request) {
	target := strings.TrimSpace(r.URL.Query().Get("proxy"))
	if target == "" {
		http.Error(w, "Missing 'proxy' (e.g. ?proxy=socks5://1.2.3.4:1080 or ?proxy=1.2.3.4:8080)", http.StatusBadRequest)
		return
	}

	var proto model.Protocol = model.ProtoUnknown
	var host string
	var port int = 8080

	if strings.Contains(target, "://") {
		u, err := url.Parse(target)
		if err == nil {
			proto = model.Protocol(strings.ToLower(u.Scheme))
			host = u.Hostname()
			if p, err := strconv.Atoi(u.Port()); err == nil && p > 0 {
				port = p
			}
		}
	} else if strings.Contains(target, ":") {
		parts := strings.SplitN(target, ":", 2)
		host = parts[0]
		port, _ = strconv.Atoi(parts[1])
	} else {
		host = target
	}

	ctx, cancel := context.WithTimeout(r.Context(), 8*time.Second)
	defer cancel()

	result := s.checker.CheckIPPort(ctx, host, port, proto)

	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(result)
}

// handleStream streams real-time metrics to browser via Server-Sent Events (SSE)
func (s *APIServer) handleStream(w http.ResponseWriter, r *http.Request) {
	flusher, ok := w.(http.Flusher)
	if !ok {
		http.Error(w, "Streaming unsupported", http.StatusInternalServerError)
		return
	}

	w.Header().Set("Content-Type", "text/event-stream")
	w.Header().Set("Cache-Control", "no-cache")
	w.Header().Set("Connection", "keep-alive")
	w.Header().Set("X-Accel-Buffering", "no")

	client := &sseClient{
		ch:     make(chan []byte, 64),
		closed: make(chan struct{}),
	}

	s.sseClientsMu.Lock()
	s.sseClients[client] = struct{}{}
	s.sseClientsMu.Unlock()

	defer func() {
		s.sseClientsMu.Lock()
		delete(s.sseClients, client)
		s.sseClientsMu.Unlock()
		close(client.closed)
	}()

	// Send stats every 1 second
	ticker := time.NewTicker(time.Second)
	defer ticker.Stop()

	for {
		select {
		case <-r.Context().Done():
			return
		case data := <-client.ch:
			_, _ = fmt.Fprintf(w, "data: %s\n\n", data)
			flusher.Flush()
		case <-ticker.C:
			aliveCount, _ := s.storage.TotalAliveCount()
			var liveStats map[string]interface{}
			if s.stats != nil {
				liveStats = s.stats.Snapshot()
			}
			payload, _ := json.Marshal(map[string]interface{}{
				"type":              "stats",
				"total_alive_in_db": aliveCount,
				"live_metrics":      liveStats,
				"server_time":       time.Now().Unix(),
			})
			_, _ = fmt.Fprintf(w, "data: %s\n\n", payload)
			flusher.Flush()
		}
	}
}

// handleMetrics exports standard Prometheus metrics
func (s *APIServer) handleMetrics(w http.ResponseWriter, r *http.Request) {
	aliveCount, _ := s.storage.TotalAliveCount()
	var scanned, alive, dead, rate float64
	if s.stats != nil {
		snap := s.stats.Snapshot()
		scanned = float64(snap["total_scanned"].(int64))
		alive = float64(snap["total_alive"].(int64))
		dead = float64(snap["total_dead"].(int64))
		rate = snap["speed_ips_sec"].(float64)
	}

	w.Header().Set("Content-Type", "text/plain; version=0.0.4")
	writeMetric := func(help, typ, name string, val interface{}) {
		_, _ = fmt.Fprintf(w, "# HELP %s %s\n# TYPE %s %s\n%s %v\n\n", name, help, name, typ, name, val)
	}
	writeMetric("Total active proxies in SQLite pool", "gauge", "goproxy_pool_alive_total", aliveCount)
	writeMetric("Total targets scanned", "counter", "goproxy_scanned_total", fmt.Sprintf("%.0f", scanned))
	writeMetric("Total alive proxies found", "counter", "goproxy_alive_total", fmt.Sprintf("%.0f", alive))
	writeMetric("Total dead targets", "counter", "goproxy_dead_total", fmt.Sprintf("%.0f", dead))
	writeMetric("Current scan rate IPs/sec", "gauge", "goproxy_scan_rate_ips_per_second", fmt.Sprintf("%.2f", rate))
}

func (s *APIServer) handleHealthz(w http.ResponseWriter, r *http.Request) {
	w.WriteHeader(http.StatusOK)
	_, _ = fmt.Fprint(w, "OK")
}

func (s *APIServer) handleExport(w http.ResponseWriter, r *http.Request) {
	q := r.URL.Query()
	format := q.Get("format")
	filter := storage.ProxyFilter{
		Protocol:    q.Get("protocol"),
		CountryCode: q.Get("country"),
		Anonymity:   q.Get("anonymity"),
		OnlyAlive:   true,
		Limit:       50000,
	}

	list, err := s.storage.QueryProxies(filter)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	ts := time.Now().Format("20060102_150405")
	switch format {
	case "json":
		w.Header().Set("Content-Disposition", fmt.Sprintf(`attachment; filename="proxies_%s.json"`, ts))
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(list)
	case "csv":
		w.Header().Set("Content-Disposition", fmt.Sprintf(`attachment; filename="proxies_%s.csv"`, ts))
		w.Header().Set("Content-Type", "text/csv")
		_, _ = fmt.Fprintln(w, "protocol,ip,port,anonymity,country_code,city,latency_ms,score,uptime_percent,ssl")
		for _, p := range list {
			ssl := "false"
			if p.SSL {
				ssl = "true"
			}
			_, _ = fmt.Fprintf(w, "%s,%s,%d,%s,%s,%s,%d,%d,%.1f,%s\n",
				p.Protocol, p.IP, p.Port, p.Anonymity, p.CountryCode, p.City, p.LatencyMs, p.Score, p.UptimePercent, ssl)
		}
	default:
		w.Header().Set("Content-Disposition", fmt.Sprintf(`attachment; filename="proxies_%s.txt"`, ts))
		w.Header().Set("Content-Type", "text/plain")
		for _, p := range list {
			_, _ = fmt.Fprintln(w, p.URLString())
		}
	}
}

func (s *APIServer) handleDashboard(w http.ResponseWriter, r *http.Request) {
	if r.URL.Path != "/" {
		http.NotFound(w, r)
		return
	}
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.Header().Set("Cache-Control", "no-store")
	_, _ = w.Write([]byte(dashboardHTML))
}
