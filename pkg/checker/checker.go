package checker

import (
	"context"
	"fmt"
	"math"
	"net"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"time"

	"goproxy/pkg/geoip"
	"goproxy/pkg/judge"
	"goproxy/pkg/model"
	"goproxy/pkg/protocol"
)

// Checker coordinates multi-protocol verification and quality scoring
type Checker struct {
	config *model.Config
	judge  *judge.Evaluator
	geoip  *geoip.Resolver
}

// NewChecker initializes a new Checker instance
func NewChecker(cfg *model.Config) *Checker {
	if cfg == nil {
		cfg = model.DefaultConfig()
	}
	return &Checker{
		config: cfg,
		judge:  judge.NewEvaluator(cfg.Judge.Judges, cfg.Judge.CustomJudgeURL),
		geoip:  geoip.NewResolver(cfg.GeoIP.Enabled),
	}
}

// CheckIPPort verifies a single IP and Port through all validation stages
func (c *Checker) CheckIPPort(ctx context.Context, ip string, port int, proto model.Protocol) *model.CheckResult {
	loc := c.geoip.Lookup(ip)
	result := &model.CheckResult{
		IP:          ip,
		Port:        port,
		Protocol:    proto,
		Anonymity:   model.AnonUnknown,
		Country:     loc.Country,
		CountryCode: loc.CountryCode,
		City:        loc.City,
		ASN:         loc.ASN,
		Org:         loc.Org,
		Success:     false,
	}

	addr := net.JoinHostPort(ip, strconv.Itoa(port))

	// Stage 1: Fast TCP Ping (sub-millisecond pre-filter)
	if c.config.Protocol.FastFailTCP {
		timeout := c.config.Engine.ConnectTimeout
		if timeout > 800*time.Millisecond {
			timeout = 800 * time.Millisecond
		}
		if !protocol.FastTCPPing(ctx, addr, timeout) {
			result.Error = fmt.Errorf("tcp connect timed out")
			return result
		}
	}

	// Stage 2: Deep Protocol Handshake & End-to-End Relay Test
	judgeURL := c.judge.PickJudge()
	reqTimeout := c.config.Engine.ReadWriteTimeout

	var latency time.Duration
	var err error

	if proto == "" || proto == model.ProtoUnknown {
		// Auto-detect: try protocols concurrently (the fastest wins)
		var body []byte
		var detectedProto model.Protocol
		detectedProto, latency, body, err = protocol.DetectProtocol(ctx, ip, port, judgeURL, reqTimeout)
		if err != nil {
			result.Error = err
			return result
		}
		result.Protocol = detectedProto
		proto = detectedProto
		_ = body
		// Conservative anonymity assignment for concurrent detect (no headers from race)
		if proto == model.ProtoHTTPS || proto == model.ProtoSOCKS5 ||
			proto == model.ProtoSOCKS4 || proto == model.ProtoSOCKS4A {
			result.Anonymity = model.AnonElite
		} else {
			result.Anonymity = model.AnonElite
		}
	} else {
		// Specific protocol check
		switch proto {
		case model.ProtoHTTP:
			var body []byte
			var hdrs http.Header
			latency, body, hdrs, err = protocol.CheckHTTP(ctx, addr, judgeURL, reqTimeout)
			if err != nil {
				result.Error = err
				return result
			}
			result.Anonymity = c.judge.EvaluateAnonymity(hdrs, body)

		case model.ProtoHTTPS:
			targetHost := c.getTargetHost()
			latency, err = protocol.CheckHTTPS(ctx, addr, targetHost, reqTimeout)
			if err != nil {
				result.Error = err
				return result
			}
			result.SSL = true
			result.Anonymity = model.AnonElite

		case model.ProtoSOCKS5:
			latency, err = protocol.CheckSOCKS5(ctx, addr, "1.1.1.1", 80, reqTimeout)
			if err != nil {
				result.Error = err
				return result
			}
			result.Anonymity = model.AnonElite

		case model.ProtoSOCKS4, model.ProtoSOCKS4A:
			latency, err = protocol.CheckSOCKS4(ctx, addr, "1.1.1.1", 80, reqTimeout)
			if err != nil {
				result.Error = err
				return result
			}
			result.Anonymity = model.AnonElite

		default:
			result.Error = fmt.Errorf("unsupported protocol: %s", proto)
			return result
		}
	}

	if proto == model.ProtoHTTPS {
		result.SSL = true
	}
	if result.Anonymity == model.AnonUnknown {
		result.Anonymity = model.AnonElite
	}

	result.Latency = latency
	result.LatencyMs = latency.Milliseconds()
	result.Success = true
	result.JudgeCount = 1

	return result
}

// CalculateScore computes a quality score (0-100) using the v3 weighted algorithm:
//   - Logarithmic latency penalty (smooth curve, not step function)
//   - Exponential consecutive failure penalty
//   - Historical success rate weighting
//   - Protocol and SSL quality bonuses
//   - Exponential time-decay for inactive proxies
//   - Multi-judge confirmation bonus
func CalculateScore(p *model.Proxy) int {
	score := 100.0

	// 1. Latency: logarithmic penalty from 0ms (0) → 5000ms (45)
	if p.LatencyMs > 0 {
		penalty := 45.0 * math.Log10(float64(p.LatencyMs)/100.0+1.0) / math.Log10(51.0)
		if penalty > 45 {
			penalty = 45
		}
		score -= penalty
	}

	// 2. Anonymity weight
	switch p.Anonymity {
	case model.AnonElite:
		score += 8
	case model.AnonTransparent:
		score -= 30
	}

	// 3. Protocol bonus (SOCKS5 > HTTPS > SOCKS4 > HTTP)
	switch p.Protocol {
	case model.ProtoSOCKS5:
		score += 10
	case model.ProtoHTTPS:
		score += 6
	case model.ProtoSOCKS4, model.ProtoSOCKS4A:
		score += 4
	}

	// 4. SSL bonus
	if p.SSL {
		score += 6
	}

	// 5. Consecutive failure: exponential penalty (min(50, 2^n * 8))
	if p.ConsecutiveFail > 0 {
		penalty := math.Min(50.0, math.Pow(2, float64(p.ConsecutiveFail))*8.0)
		score -= penalty
	}

	// 6. Historical success rate: (1 - rate) * 30 penalty
	totalChecks := p.SuccessChecks + p.FailedChecks
	if totalChecks > 2 {
		successRate := float64(p.SuccessChecks) / float64(totalChecks)
		score -= (1.0 - successRate) * 30.0
	}

	// 7. Time decay: e^(-t/τ), τ=24h → up to 25 penalty for long-inactive proxies
	if !p.LastAlive.IsZero() {
		hoursInactive := time.Since(p.LastAlive).Hours()
		if hoursInactive > 0 {
			decay := math.Exp(-hoursInactive / 24.0)
			score -= (1.0 - decay) * 25.0
		}
	}

	// 8. Multi-judge confirmation bonus (+3 per additional judge)
	if p.JudgeCount > 1 {
		bonus := float64(p.JudgeCount-1) * 3.0
		if bonus > 10 {
			bonus = 10
		}
		score += bonus
	}

	// Clamp to [0, 100]
	if score > 100 {
		score = 100
	}
	if score < 0 {
		score = 0
	}
	return int(math.Round(score))
}

// getTargetHost trích xuất domain:port từ cấu hình target.url trong config.yaml
func (c *Checker) getTargetHost() string {
	if c.config != nil && c.config.Target.URL != "" {
		u, err := url.Parse(c.config.Target.URL)
		if err == nil && u.Host != "" {
			if !strings.Contains(u.Host, ":") {
				if u.Scheme == "http" {
					return u.Host + ":80"
				}
				return u.Host + ":443"
			}
			return u.Host
		}
	}
	return "www.google.com:443"
}
