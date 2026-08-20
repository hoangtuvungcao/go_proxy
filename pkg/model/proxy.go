package model

import (
	"encoding/json"
	"fmt"
	"time"
)

// Protocol defines the proxy protocol type
type Protocol string

const (
	ProtoHTTP    Protocol = "http"
	ProtoHTTPS   Protocol = "https" // HTTP CONNECT tunnel
	ProtoSOCKS4  Protocol = "socks4"
	ProtoSOCKS4A Protocol = "socks4a"
	ProtoSOCKS5  Protocol = "socks5"
	ProtoUnknown Protocol = "unknown"
)

// Anonymity defines the proxy anonymity level
type Anonymity string

const (
	AnonTransparent Anonymity = "transparent" // Leaks real client IP
	AnonAnonymous   Anonymity = "anonymous"   // Hides IP, but reveals proxy usage
	AnonElite       Anonymity = "elite"       // High anonymity, looks like normal client
	AnonUnknown     Anonymity = "unknown"
)

// IPVersion indicates IPv4 or IPv6
type IPVersion int

const (
	IPv4 IPVersion = 4
	IPv6 IPVersion = 6
)

// Proxy represents a checked proxy server with extended quality metrics
type Proxy struct {
	ID              int64         `json:"id,omitempty"`
	IP              string        `json:"ip"`
	Port            int           `json:"port"`
	Protocol        Protocol      `json:"protocol"`
	Anonymity       Anonymity     `json:"anonymity"`
	Country         string        `json:"country"`
	CountryCode     string        `json:"country_code"`
	City            string        `json:"city"`
	ASN             string        `json:"asn"`
	Org             string        `json:"org"`
	Latency         time.Duration `json:"latency_ns"`
	LatencyMs       int64         `json:"latency_ms"`
	LatencyP50      int64         `json:"latency_p50,omitempty"` // Median latency over history
	LatencyP95      int64         `json:"latency_p95,omitempty"` // 95th percentile latency
	SpeedKbps       float64       `json:"speed_kbps,omitempty"`  // Downstream bandwidth test
	SSL             bool          `json:"ssl"`
	TargetOK        bool          `json:"target_ok"`
	Score           int           `json:"score"`          // 0 - 100 quality score
	UptimePercent   float64       `json:"uptime_percent"` // Rolling uptime percentage
	SuccessChecks   int           `json:"success_checks"`
	FailedChecks    int           `json:"failed_checks"`
	ConsecutiveFail int           `json:"consecutive_fail"`
	JudgeCount      int           `json:"judge_count,omitempty"` // Number of judges that confirmed this proxy
	IPVer           IPVersion     `json:"ip_version,omitempty"`  // 4 or 6
	LastAlive       time.Time     `json:"last_alive"`
	LastChecked     time.Time     `json:"last_checked"`
	FirstSeen       time.Time     `json:"first_seen"`
	IsAlive         bool          `json:"is_alive"`
}

// Address returns "ip:port"
func (p *Proxy) Address() string {
	return fmt.Sprintf("%s:%d", p.IP, p.Port)
}

// URLString returns "protocol://ip:port"
func (p *Proxy) URLString() string {
	return fmt.Sprintf("%s://%s:%d", p.Protocol, p.IP, p.Port)
}

// CheckResult represents the outcome of a single proxy verification run
type CheckResult struct {
	IP          string        `json:"ip"`
	Port        int           `json:"port"`
	Protocol    Protocol      `json:"protocol"`
	Anonymity   Anonymity     `json:"anonymity"`
	Latency     time.Duration `json:"latency_ns"`
	LatencyMs   int64         `json:"latency_ms"`
	SpeedKbps   float64       `json:"speed_kbps,omitempty"`
	SSL         bool          `json:"ssl"`
	TargetOK    bool          `json:"target_ok"`
	Country     string        `json:"country"`
	CountryCode string        `json:"country_code"`
	City        string        `json:"city"`
	ASN         string        `json:"asn"`
	Org         string        `json:"org"`
	JudgeCount  int           `json:"judge_count"` // How many judges confirmed
	Error       error         `json:"-"`
	ErrorMsg    string        `json:"error,omitempty"`
	Success     bool          `json:"success"`
}

// MarshalJSON formats CheckResult with a readable error string
func (r CheckResult) MarshalJSON() ([]byte, error) {
	type Alias CheckResult
	aux := struct {
		Alias
		ErrorMsg string `json:"error,omitempty"`
	}{
		Alias: Alias(r),
	}
	if r.Error != nil {
		aux.ErrorMsg = r.Error.Error()
	} else if r.ErrorMsg != "" {
		aux.ErrorMsg = r.ErrorMsg
	}
	return json.Marshal(aux)
}
