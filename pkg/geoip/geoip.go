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

// Resolver handles fast GeoIP resolution with multi-tier caching and batch lookups
type Resolver struct {
	// L1: in-memory cache (unlimited in-session)
	cache      sync.Map
	httpClient *http.Client
	enabled    bool

	// Batch request channel
	batchCh chan batchReq
}

type batchReq struct {
	ip     string
	respCh chan LocationInfo
}

// NewResolver initializes a GeoIP Resolver with batch support
func NewResolver(enabled bool) *Resolver {
	r := &Resolver{
		enabled: enabled,
		batchCh: make(chan batchReq, 10000),
		httpClient: &http.Client{
			Timeout: 4 * time.Second,
			Transport: &http.Transport{
				MaxIdleConns:        200,
				MaxIdleConnsPerHost: 50,
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

// Lookup resolves IP location with L1 cache, then batch queue
func (r *Resolver) Lookup(ipStr string) LocationInfo {
	if !r.enabled || ipStr == "" {
		return LocationInfo{Country: "Unknown", CountryCode: "XX"}
	}

	ip := net.ParseIP(ipStr)
	if ip == nil {
		return LocationInfo{Country: "Invalid", CountryCode: "XX"}
	}

	// Fast path: detect private/reserved IPs without any HTTP call
	if info, ok := classifySpecialIP(ip); ok {
		return info
	}

	// L1 cache hit
	if val, ok := r.cache.Load(ipStr); ok {
		return val.(LocationInfo)
	}

	// Send to batch worker and wait
	respCh := make(chan LocationInfo, 1)
	select {
	case r.batchCh <- batchReq{ip: ipStr, respCh: respCh}:
		select {
		case info := <-respCh:
			return info
		case <-time.After(5 * time.Second):
			return LocationInfo{Country: "Unknown", CountryCode: "XX"}
		}
	default:
		// Batch queue full — direct lookup
		return r.fetchDirect(ipStr)
	}
}

// batchWorker accumulates up to 100 IPs or 50ms window and sends them in one API call
func (r *Resolver) batchWorker() {
	const maxBatch = 100
	const maxWait = 50 * time.Millisecond

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

		// Separate already-cached from those needing lookup
		toFetch := make([]string, 0, len(batch))
		for i, p := range batch {
			if val, ok := r.cache.Load(p.req.ip); ok {
				p.req.respCh <- val.(LocationInfo)
				batch[i].cached = true
			} else {
				toFetch = append(toFetch, p.req.ip)
			}
		}

		// Batch fetch from ip-api.com
		results := map[string]LocationInfo{}
		if len(toFetch) > 0 {
			results = r.fetchBatch(toFetch)
		}

		// Respond to all pending requests
		for _, p := range batch {
			if p.cached {
				continue
			}
			info, ok := results[p.req.ip]
			if !ok || info.CountryCode == "" {
				info = LocationInfo{Country: "Unknown", CountryCode: "XX"}
			}
			r.cache.Store(p.req.ip, info)
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

// fetchBatch queries ip-api.com batch endpoint (up to 100 IPs per call)
func (r *Resolver) fetchBatch(ips []string) map[string]LocationInfo {
	results := make(map[string]LocationInfo, len(ips))

	// Build request body
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

	resp, err := r.httpClient.Do(req)
	if err != nil {
		// Fallback: fetch one by one
		for _, ip := range ips {
			results[ip] = r.fetchDirect(ip)
		}
		return results
	}
	defer resp.Body.Close()

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
		if item.Status == "success" {
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

// fetchDirect does a single IP lookup (fallback when batch is unavailable)
func (r *Resolver) fetchDirect(ip string) LocationInfo {
	url := fmt.Sprintf("http://ip-api.com/json/%s?fields=status,country,countryCode,city,as,org", ip)
	resp, err := r.httpClient.Get(url)
	if err != nil {
		return LocationInfo{Country: "Unknown", CountryCode: "XX"}
	}
	defer resp.Body.Close()

	var data struct {
		Status      string `json:"status"`
		Country     string `json:"country"`
		CountryCode string `json:"countryCode"`
		City        string `json:"city"`
		AS          string `json:"as"`
		Org         string `json:"org"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&data); err != nil || data.Status != "success" {
		return LocationInfo{Country: "Unknown", CountryCode: "XX"}
	}
	info := LocationInfo{
		Country:     data.Country,
		CountryCode: data.CountryCode,
		City:        data.City,
		ASN:         data.AS,
		Org:         data.Org,
	}
	r.cache.Store(ip, info)
	return info
}

// classifySpecialIP returns location info for private/reserved/loopback IPs
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
	// CGNAT range 100.64.0.0/10
	if ip4 := ip.To4(); ip4 != nil {
		if ip4[0] == 100 && ip4[1]>>2 == 16 { // 100.64.x.x
			return LocationInfo{Country: "CGNAT", CountryCode: "CG"}, true
		}
	}
	return LocationInfo{}, false
}
