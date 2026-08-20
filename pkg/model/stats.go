package model

import (
	"sync"
	"sync/atomic"
	"time"
)

const historySize = 120 // 120 seconds of history at 1s intervals

// HistoryPoint is a snapshot of metrics at a point in time
type HistoryPoint struct {
	Timestamp int64 `json:"ts"`
	Alive     int64 `json:"alive"`
	Scanned   int64 `json:"scanned"`
	SpeedIPS  float64 `json:"speed"`
}

// Stats holds real-time telemetry metrics during execution
type Stats struct {
	TotalQueued      int64
	TotalScanned     int64
	TotalAlive       int64
	TotalDead        int64
	TotalTimeout     int64
	TotalError       int64

	// By Protocol
	HTTPAlive   int64
	HTTPSAlive  int64
	SOCKS4Alive int64
	SOCKS5Alive int64

	// By Anonymity
	EliteAlive       int64
	AnonymousAlive   int64
	TransparentAlive int64

	StartTime time.Time
	mu        sync.RWMutex

	// Country counters (top 50)
	CountryCounts map[string]int64

	// History ring buffer for charts (120 x 1s points)
	history    [historySize]HistoryPoint
	historyIdx int64 // atomic ring buffer index
}

// NewStats initializes a thread-safe Stats collector
func NewStats() *Stats {
	s := &Stats{
		StartTime:     time.Now(),
		CountryCounts: make(map[string]int64),
	}
	// Pre-fill history timestamps
	now := time.Now().Unix()
	for i := range s.history {
		s.history[i].Timestamp = now - int64(historySize-i)
	}
	return s
}

// IncQueued increments total queued count
func (s *Stats) IncQueued() {
	atomic.AddInt64(&s.TotalQueued, 1)
}

// RecordResult updates metrics atomically based on CheckResult
func (s *Stats) RecordResult(r *CheckResult) {
	atomic.AddInt64(&s.TotalScanned, 1)
	if r.Success {
		atomic.AddInt64(&s.TotalAlive, 1)

		switch r.Protocol {
		case ProtoHTTP:
			atomic.AddInt64(&s.HTTPAlive, 1)
		case ProtoHTTPS:
			atomic.AddInt64(&s.HTTPSAlive, 1)
		case ProtoSOCKS4, ProtoSOCKS4A:
			atomic.AddInt64(&s.SOCKS4Alive, 1)
		case ProtoSOCKS5:
			atomic.AddInt64(&s.SOCKS5Alive, 1)
		}

		switch r.Anonymity {
		case AnonElite:
			atomic.AddInt64(&s.EliteAlive, 1)
		case AnonAnonymous:
			atomic.AddInt64(&s.AnonymousAlive, 1)
		case AnonTransparent:
			atomic.AddInt64(&s.TransparentAlive, 1)
		}

		if r.CountryCode != "" {
			s.mu.Lock()
			s.CountryCounts[r.CountryCode]++
			s.mu.Unlock()
		}
	} else {
		atomic.AddInt64(&s.TotalDead, 1)
	}
}

// Speed returns the current scan rate (IPs/sec)
func (s *Stats) Speed() float64 {
	elapsed := time.Since(s.StartTime).Seconds()
	if elapsed <= 0 {
		return 0
	}
	return float64(atomic.LoadInt64(&s.TotalScanned)) / elapsed
}

// PushHistoryPoint saves a snapshot to the ring buffer. Call every 1s.
func (s *Stats) PushHistoryPoint() {
	idx := atomic.AddInt64(&s.historyIdx, 1)
	slot := int(idx) % historySize
	s.history[slot] = HistoryPoint{
		Timestamp: time.Now().Unix(),
		Alive:     atomic.LoadInt64(&s.TotalAlive),
		Scanned:   atomic.LoadInt64(&s.TotalScanned),
		SpeedIPS:  s.Speed(),
	}
}

// GetHistory returns the last N history points ordered oldest→newest
func (s *Stats) GetHistory() []HistoryPoint {
	currentIdx := atomic.LoadInt64(&s.historyIdx)
	result := make([]HistoryPoint, historySize)
	for i := 0; i < historySize; i++ {
		slot := int(currentIdx+int64(i)+1) % historySize
		result[i] = s.history[slot]
	}
	return result
}

// Snapshot returns a point-in-time copy of the statistics
func (s *Stats) Snapshot() map[string]interface{} {
	s.mu.RLock()
	countries := make(map[string]int64, len(s.CountryCounts))
	for k, v := range s.CountryCounts {
		countries[k] = v
	}
	s.mu.RUnlock()

	scanned := atomic.LoadInt64(&s.TotalScanned)
	alive := atomic.LoadInt64(&s.TotalAlive)
	dead := atomic.LoadInt64(&s.TotalDead)
	elapsed := time.Since(s.StartTime).Seconds()
	rate := float64(0)
	if elapsed > 0 {
		rate = float64(scanned) / elapsed
	}

	return map[string]interface{}{
		"total_queued":      atomic.LoadInt64(&s.TotalQueued),
		"total_scanned":     scanned,
		"total_alive":       alive,
		"total_dead":        dead,
		"speed_ips_sec":     rate,
		"uptime_seconds":    int64(elapsed),
		"http_alive":        atomic.LoadInt64(&s.HTTPAlive),
		"https_alive":       atomic.LoadInt64(&s.HTTPSAlive),
		"socks4_alive":      atomic.LoadInt64(&s.SOCKS4Alive),
		"socks5_alive":      atomic.LoadInt64(&s.SOCKS5Alive),
		"elite_alive":       atomic.LoadInt64(&s.EliteAlive),
		"anonymous_alive":   atomic.LoadInt64(&s.AnonymousAlive),
		"transparent_alive": atomic.LoadInt64(&s.TransparentAlive),
		"top_countries":     countries,
	}
}
