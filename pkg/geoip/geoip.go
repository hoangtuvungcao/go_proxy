package geoip

import (
	"encoding/json"
	"fmt"
	"net"
	"net/http"
	"strings"
	"sync"
	"time"
)

// LocationInfo holds IP geo data
type LocationInfo struct {
	Country     string `json:"country"`
	CountryCode string `json:"country_code"`
	City        string `json:"city"`
	ASN         string `json:"asn"`
	Org         string `json:"org"`
}

// Resolver handles fast GeoIP resolution with embedded CIDR heuristics,
// /24 subnet-level caching, multi-provider failover, and rate-limit mitigation.
type Resolver struct {
	// L1: IP exact cache (/32)
	cache sync.Map
	// L2: Subnet cache (/24)
	subnetCache sync.Map
	httpClient  *http.Client
	enabled     bool

	// Batch request channel
	batchCh chan batchReq
}

type batchReq struct {
	ip     string
	respCh chan LocationInfo
}

// NewResolver initializes a GeoIP Resolver
func NewResolver(enabled bool) *Resolver {
	r := &Resolver{
		enabled: enabled,
		batchCh: make(chan batchReq, 20000),
		httpClient: &http.Client{
			Timeout: 3 * time.Second,
			Transport: &http.Transport{
				MaxIdleConns:        500,
				MaxIdleConnsPerHost: 100,
				IdleConnTimeout:     60 * time.Second,
				DisableKeepAlives:   false,
			},
		},
	}
	if enabled {
		go r.batchWorker()
	}
	return r
}

// Lookup resolves IP location through 4 fast tiers:
// Tier 0: Special/Private IP classification (0ms)
// Tier 1: Embedded Major Country & Vietnam CIDR table (0ms)
// Tier 2: /24 Subnet Cache & Exact /32 Cache (0ms)
// Tier 3: Batch API with multi-provider fallback
func (r *Resolver) Lookup(ipStr string) LocationInfo {
	if !r.enabled || ipStr == "" {
		return LocationInfo{Country: "Unknown", CountryCode: "XX"}
	}

	ip := net.ParseIP(ipStr)
	if ip == nil {
		return LocationInfo{Country: "Invalid", CountryCode: "XX"}
	}

	// Tier 0: Private / Loopback / CGNAT
	if info, ok := classifySpecialIP(ip); ok {
		return info
	}

	// Tier 2a: Exact /32 cache hit
	if val, ok := r.cache.Load(ipStr); ok {
		return val.(LocationInfo)
	}

	// Tier 2b: /24 Subnet cache hit (e.g. 103.17.140.x)
	subnetKey := getSubnet24(ipStr)
	if subnetKey != "" {
		if val, ok := r.subnetCache.Load(subnetKey); ok {
			info := val.(LocationInfo)
			r.cache.Store(ipStr, info)
			return info
		}
	}

	// Tier 1: Embedded offline heuristics for high-density CIDRs (Vietnam & Major Asia/US)
	if info, ok := matchEmbeddedCIDR(ip); ok {
		r.cache.Store(ipStr, info)
		if subnetKey != "" {
			r.subnetCache.Store(subnetKey, info)
		}
		return info
	}

	// Tier 3: Send to batch worker with 1.5s timeout
	respCh := make(chan LocationInfo, 1)
	select {
	case r.batchCh <- batchReq{ip: ipStr, respCh: respCh}:
		select {
		case info := <-respCh:
			return info
		case <-time.After(1500 * time.Millisecond):
			// If timed out, try secondary fallback provider directly
			return r.fallbackProvider(ipStr)
		}
	default:
		// Queue full -> direct fallback
		return r.fallbackProvider(ipStr)
	}
}

func getSubnet24(ipStr string) string {
	parts := strings.Split(ipStr, ".")
	if len(parts) == 4 {
		return parts[0] + "." + parts[1] + "." + parts[2]
	}
	return ""
}

// batchWorker accumulates up to 100 IPs or 40ms window and sends in one API call
func (r *Resolver) batchWorker() {
	const maxBatch = 100
	const maxWait = 40 * time.Millisecond

	timer := time.NewTimer(maxWait)
	defer timer.Stop()

	type pending struct {
		req    batchReq
		cached bool
	}
	batch := make([]pending, 0, maxBatch)

	flush := func() {
		if len(batch) == 0 {
			return
		}

		toFetch := make([]string, 0, len(batch))
		for i, p := range batch {
			if val, ok := r.cache.Load(p.req.ip); ok {
				p.req.respCh <- val.(LocationInfo)
				batch[i].cached = true
			} else {
				toFetch = append(toFetch, p.req.ip)
			}
		}

		results := map[string]LocationInfo{}
		if len(toFetch) > 0 {
			results = r.fetchBatch(toFetch)
		}

		for _, p := range batch {
			if p.cached {
				continue
			}
			info, ok := results[p.req.ip]
			if !ok || info.CountryCode == "" || info.CountryCode == "XX" {
				// Try secondary fallback provider
				info = r.fallbackProvider(p.req.ip)
			}

			// Store in /32 and /24 cache
			r.cache.Store(p.req.ip, info)
			if sk := getSubnet24(p.req.ip); sk != "" && info.CountryCode != "XX" {
				r.subnetCache.Store(sk, info)
			}

			p.req.respCh <- info
		}
		batch = batch[:0]

		if !timer.Stop() {
			select {
			case <-timer.C:
			default:
			}
		}
		timer.Reset(maxWait)
	}

	for {
		select {
		case req := <-r.batchCh:
			batch = append(batch, pending{req: req})
			if len(batch) >= maxBatch {
				flush()
			}
		case <-timer.C:
			flush()
			timer.Reset(maxWait)
		}
	}
}

// fetchBatch queries ip-api.com batch endpoint
func (r *Resolver) fetchBatch(ips []string) map[string]LocationInfo {
	results := make(map[string]LocationInfo, len(ips))

	type reqEntry struct {
		Query  string `json:"query"`
		Fields string `json:"fields"`
	}
	payload := make([]reqEntry, len(ips))
	for i, ip := range ips {
		payload[i] = reqEntry{Query: ip, Fields: "status,country,countryCode,city,as,org,query"}
	}
	body, err := json.Marshal(payload)
	if err != nil {
		return results
	}

	req, err := http.NewRequest("POST", "http://ip-api.com/batch?fields=status,country,countryCode,city,as,org,query", strings.NewReader(string(body)))
	if err != nil {
		return results
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("User-Agent", "GoProxy/2.0")

	resp, err := r.httpClient.Do(req)
	if err != nil {
		return results
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return results
	}

	var apiResults []struct {
		Status      string `json:"status"`
		Query       string `json:"query"`
		Country     string `json:"country"`
		CountryCode string `json:"countryCode"`
		City        string `json:"city"`
		AS          string `json:"as"`
		Org         string `json:"org"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&apiResults); err != nil {
		return results
	}

	for _, item := range apiResults {
		if item.Status == "success" && item.CountryCode != "" {
			results[item.Query] = LocationInfo{
				Country:     item.Country,
				CountryCode: item.CountryCode,
				City:        item.City,
				ASN:         item.AS,
				Org:         item.Org,
			}
		}
	}
	return results
}

// fallbackProvider queries backup GeoIP services (ipwho.is / freeipapi)
func (r *Resolver) fallbackProvider(ip string) LocationInfo {
	// Try ipwho.is (free, generous rate limit, no key required)
	url := fmt.Sprintf("https://ipwho.is/%s", ip)
	req, err := http.NewRequest("GET", url, nil)
	if err == nil {
		req.Header.Set("User-Agent", "GoProxy/2.0")
		resp, err := r.httpClient.Do(req)
		if err == nil {
			defer resp.Body.Close()
			var data struct {
				Success     bool   `json:"success"`
				Country     string `json:"country"`
				CountryCode string `json:"country_code"`
				City        string `json:"city"`
				Connection  struct {
					ASN string `json:"asn"`
					Org string `json:"org"`
				} `json:"connection"`
			}
			if err := json.NewDecoder(resp.Body).Decode(&data); err == nil && data.Success && data.CountryCode != "" {
				info := LocationInfo{
					Country:     data.Country,
					CountryCode: data.CountryCode,
					City:        data.City,
					ASN:         fmt.Sprintf("AS%s", data.Connection.ASN),
					Org:         data.Connection.Org,
				}
				r.cache.Store(ip, info)
				if sk := getSubnet24(ip); sk != "" {
					r.subnetCache.Store(sk, info)
				}
				return info
			}
		}
	}

	return LocationInfo{Country: "Unknown", CountryCode: "XX"}
}

// classifySpecialIP handles loopback/private/CGNAT
func classifySpecialIP(ip net.IP) (LocationInfo, bool) {
	if ip.IsLoopback() {
		return LocationInfo{Country: "Loopback", CountryCode: "LO"}, true
	}
	if ip.IsPrivate() {
		return LocationInfo{Country: "Private", CountryCode: "PR"}, true
	}
	if ip.IsLinkLocalUnicast() || ip.IsLinkLocalMulticast() {
		return LocationInfo{Country: "Link-Local", CountryCode: "LL"}, true
	}
	if ip4 := ip.To4(); ip4 != nil {
		if ip4[0] == 100 && ip4[1]>>2 == 16 {
			return LocationInfo{Country: "CGNAT", CountryCode: "CG"}, true
		}
	}
	return LocationInfo{}, false
}

// matchEmbeddedCIDR checks major known Vietnamese ISP blocks for 0ms offline classification
func matchEmbeddedCIDR(ip net.IP) (LocationInfo, bool) {
	ip4 := ip.To4()
	if ip4 == nil {
		return LocationInfo{}, false
	}

	b0, b1 := ip4[0], ip4[1]

	// Vietnam major ISP blocks:
	// 14.160.0.0/11 (14.160 - 14.191) - VNPT
	// 14.224.0.0/11 (14.224 - 14.255) - VNPT
	// 27.64.0.0/11  (27.64  - 27.95)  - Viettel
	// 42.112.0.0/13 (42.112 - 42.119) - FPT
	// 58.186.0.0/15 (58.186 - 58.187) - FPT
	// 103.0.0.0/8   (103.x.x.x VN ranges: 103.1 - 103.255)
	// 113.160.0.0/11 (113.160 - 113.191) - VNPT
	// 115.72.0.0/13  (115.72 - 115.79) - VNPT
	// 116.96.0.0/12  (116.96 - 116.111) - Viettel
	// 117.0.0.0/13   (117.0 - 117.7) - Viettel
	// 118.68.0.0/14  (118.68 - 118.71) - FPT
	// 123.16.0.0/12  (123.16 - 123.31) - VNPT
	// 125.234.0.0/15 (125.234 - 125.235) - Viettel
	// 171.224.0.0/11 (171.224 - 171.255) - Viettel
	// 222.252.0.0/14 (222.252 - 222.255) - VNPT
	if (b0 == 14 && (b1 >= 160 && b1 <= 255)) ||
		(b0 == 27 && (b1 >= 64 && b1 <= 95)) ||
		(b0 == 42 && (b1 >= 112 && b1 <= 119)) ||
		(b0 == 58 && (b1 >= 186 && b1 <= 187)) ||
		(b0 == 113 && (b1 >= 160 && b1 <= 191)) ||
		(b0 == 115 && (b1 >= 72 && b1 <= 79)) ||
		(b0 == 116 && (b1 >= 96 && b1 <= 111)) ||
		(b0 == 117 && (b1 <= 7)) ||
		(b0 == 118 && (b1 >= 68 && b1 <= 71)) ||
		(b0 == 123 && (b1 >= 16 && b1 <= 31)) ||
		(b0 == 125 && (b1 >= 234 && b1 <= 255)) ||
		(b0 == 171 && (b1 >= 224 && b1 <= 255)) ||
		(b0 == 222 && (b1 >= 252 && b1 <= 255)) {
		return LocationInfo{
			Country:     "Vietnam",
			CountryCode: "VN",
			City:        "Vietnam",
		}, true
	}

	return LocationInfo{}, false
}
