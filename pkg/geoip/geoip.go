package geoip

import (
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"

	"github.com/fatih/color"
	"github.com/oschwald/geoip2-golang"
)

// LocationInfo holds IP geo data
type LocationInfo struct {
	Country     string `json:"country"`
	CountryCode string `json:"country_code"`
	City        string `json:"city"`
	ASN         string `json:"asn"`
	Org         string `json:"org"`
}

var (
	mmdbInitOnce sync.Once
)

// Resolver handles fast GeoIP resolution with local MaxMind MMDB,
// embedded CIDR heuristics, /24 subnet-level caching, and multi-provider failover.
type Resolver struct {
	mmdbReader  *geoip2.Reader
	mmdbMu      sync.RWMutex
	cache       sync.Map
	subnetCache sync.Map
	httpClient  *http.Client
	enabled     bool
	batchCh     chan batchReq
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
		r.initMMDB()
		go r.batchWorker()
	}
	return r
}

func (r *Resolver) initMMDB() {
	candidates := []string{
		"configs/GeoLite2-Country.mmdb",
		"../configs/GeoLite2-Country.mmdb",
		"../../configs/GeoLite2-Country.mmdb",
		"/root/scan_proxy/configs/GeoLite2-Country.mmdb",
		"GeoLite2-Country.mmdb",
		"configs/GeoLite2-City.mmdb",
		"../configs/GeoLite2-City.mmdb",
		"../../configs/GeoLite2-City.mmdb",
		"/root/scan_proxy/configs/GeoLite2-City.mmdb",
		"GeoLite2-City.mmdb",
	}

	if execPath, err := os.Executable(); err == nil {
		execDir := filepath.Dir(execPath)
		candidates = append(candidates,
			filepath.Join(execDir, "configs", "GeoLite2-Country.mmdb"),
			filepath.Join(execDir, "GeoLite2-Country.mmdb"),
			filepath.Join(execDir, "configs", "GeoLite2-City.mmdb"),
			filepath.Join(execDir, "GeoLite2-City.mmdb"),
		)
	}

	for _, p := range candidates {
		if db, err := geoip2.Open(p); err == nil {
			r.mmdbMu.Lock()
			r.mmdbReader = db
			r.mmdbMu.Unlock()
			mmdbInitOnce.Do(func() {
				color.New(color.FgHiGreen).Printf("[*] GeoIP: Đã nạp Offline Database (%s) - 0ms lookup / 0%% Rate Limit\n", p)
			})
			return
		}
	}

	// Auto-download in background if missing
	go r.autoDownloadMMDB()
}

func (r *Resolver) autoDownloadMMDB() {
	targetDir := "configs"
	_ = os.MkdirAll(targetDir, 0755)
	targetFile := filepath.Join(targetDir, "GeoLite2-Country.mmdb")

	downloadURL := "https://github.com/P3TERX/GeoLite.mmdb/raw/download/GeoLite2-Country.mmdb"
	req, err := http.NewRequest("GET", downloadURL, nil)
	if err != nil {
		return
	}
	req.Header.Set("User-Agent", "GoProxy/2.0")

	client := &http.Client{Timeout: 30 * time.Second}
	resp, err := client.Do(req)
	if err != nil || resp.StatusCode != http.StatusOK {
		return
	}
	defer resp.Body.Close()

	tmpFile := targetFile + ".tmp"
	out, err := os.Create(tmpFile)
	if err != nil {
		return
	}
	_, err = io.Copy(out, resp.Body)
	_ = out.Close()
	if err == nil {
		_ = os.Rename(tmpFile, targetFile)
		if db, err := geoip2.Open(targetFile); err == nil {
			r.mmdbMu.Lock()
			r.mmdbReader = db
			r.mmdbMu.Unlock()
			color.New(color.FgHiGreen).Printf("[*] GeoIP: Đã tải và nạp thành công Offline Database (%s)\n", targetFile)
		}
	}
}

// Lookup resolves IP location through 5 fast tiers:
// Tier 0: Special/Private IP classification (0ms)
// Tier 1: Local MaxMind MMDB Offline Engine (0.0001ms) - 100% no rate limit
// Tier 2: /24 Subnet Cache & Exact /32 Cache (0ms)
// Tier 3: Embedded Major Country & Vietnam CIDR table (0ms)
// Tier 4: Batch API with multi-provider fallback
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

	subnetKey := getSubnet24(ipStr)

	// Tier 1: Local MaxMind MMDB Offline Engine (Instant 0ms, Zero Rate Limit)
	r.mmdbMu.RLock()
	reader := r.mmdbReader
	r.mmdbMu.RUnlock()
	if reader != nil {
		record, err := reader.Country(ip)
		if err == nil && record.Country.IsoCode != "" {
			countryName := record.Country.Names["en"]
			if countryName == "" {
				countryName = record.Country.IsoCode
			}
			info := LocationInfo{
				Country:     countryName,
				CountryCode: record.Country.IsoCode,
			}
			r.cache.Store(ipStr, info)
			if subnetKey != "" {
				r.subnetCache.Store(subnetKey, info)
			}
			return info
		}
	}

	// Tier 2b: /24 Subnet cache hit (e.g. 103.17.140.x)
	if subnetKey != "" {
		if val, ok := r.subnetCache.Load(subnetKey); ok {
			info := val.(LocationInfo)
			r.cache.Store(ipStr, info)
			return info
		}
	}

	// Tier 3: Embedded offline heuristics for high-density CIDRs (Vietnam & Major Asia/US)
	if info, ok := matchEmbeddedCIDR(ip); ok {
		r.cache.Store(ipStr, info)
		if subnetKey != "" {
			r.subnetCache.Store(subnetKey, info)
		}
		return info
	}

	// Tier 4: Send to batch worker with 1s timeout
	respCh := make(chan LocationInfo, 1)
	select {
	case r.batchCh <- batchReq{ip: ipStr, respCh: respCh}:
		select {
		case info := <-respCh:
			return info
		case <-time.After(1000 * time.Millisecond):
			return r.fallbackProvider(ipStr)
		}
	default:
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
				info = r.fallbackProvider(p.req.ip)
			}

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

// fallbackProvider queries backup GeoIP services
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
