package daemon

import (
	"context"
	"sort"
	"sync"
	"time"

	"github.com/fatih/color"
	"goproxy/pkg/checker"
	"goproxy/pkg/model"
	"goproxy/pkg/storage"
)

// Daemon handles background continuous rechecking, quality decay, and pool maintenance
type Daemon struct {
	config   *model.Config
	storage  *storage.SQLiteStore
	exporter *storage.Exporter
	checker  *checker.Checker
	interval time.Duration
	workers  int
}

// NewDaemon initializes a health-check daemon
func NewDaemon(cfg *model.Config, store *storage.SQLiteStore, exp *storage.Exporter, interval time.Duration, workers int) *Daemon {
	if interval <= 0 {
		interval = 5 * time.Minute
	}
	if workers <= 0 {
		workers = 500
	}
	return &Daemon{
		config:   cfg,
		storage:  store,
		exporter: exp,
		checker:  checker.NewChecker(cfg),
		interval: interval,
		workers:  workers,
	}
}

// Run starts the daemon loop until context cancellation
func (d *Daemon) Run(ctx context.Context) {
	color.New(color.FgHiCyan, color.Bold).Printf("[*] Health Daemon started. Interval: %v | Workers: %d\n", d.interval, d.workers)

	// Run initial recheck immediately
	d.recheckPool(ctx)

	ticker := time.NewTicker(d.interval)
	defer ticker.Stop()

	for {
		select {
		case <-ctx.Done():
			color.New(color.FgYellow).Println("[!] Health Daemon shutting down…")
			return
		case <-ticker.C:
			d.recheckPool(ctx)
		}
	}
}

// priorityScore determines how urgently a proxy needs to be rechecked.
// Higher = recheck sooner.
func priorityScore(p *model.Proxy) float64 {
	score := 0.0

	// Flapping proxies (low score, recent failures) → high priority
	score += float64(100 - p.Score)

	// Consecutive failures → urgent
	score += float64(p.ConsecutiveFail * 15)

	// Long inactive → high priority
	if !p.LastChecked.IsZero() {
		hoursAgo := time.Since(p.LastChecked).Hours()
		score += hoursAgo * 5
	}

	// Low uptime → priority
	if p.UptimePercent < 80 {
		score += (80 - p.UptimePercent) * 0.5
	}

	return score
}

func (d *Daemon) recheckPool(ctx context.Context) {
	color.New(color.FgHiBlue).Printf("\n[*] Recheck cycle at %s…\n", time.Now().Format("15:04:05"))

	// Retrieve all proxies (alive + recently dead) for recheck
	proxies, err := d.storage.QueryProxies(storage.ProxyFilter{
		Limit: 15000,
	})
	if err != nil {
		color.New(color.FgRed).Printf("[-] DB query failed: %v\n", err)
		return
	}
	if len(proxies) == 0 {
		color.New(color.FgYellow).Println("[*] No proxies in pool to recheck.")
		return
	}

	// Sort by priority: most urgent first
	sort.Slice(proxies, func(i, j int) bool {
		return priorityScore(proxies[i]) > priorityScore(proxies[j])
	})

	color.New(color.FgGreen).Printf("[*] Rechecking %d proxies (priority-ordered)…\n", len(proxies))

	jobs := make(chan *model.Proxy, len(proxies))
	var wg sync.WaitGroup

	numWorkers := d.workers
	if numWorkers > len(proxies) {
		numWorkers = len(proxies)
	}

	var (
		aliveCount int
		deadCount  int
		mu         sync.Mutex
		aliveList  []*model.Proxy
	)

	for i := 0; i < numWorkers; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for p := range jobs {
				select {
				case <-ctx.Done():
					return
				default:
				}

				res := d.checker.CheckIPPort(ctx, p.IP, p.Port, p.Protocol)
				if res.Success {
					p.IsAlive = true
					p.Latency = res.Latency
					p.LatencyMs = res.LatencyMs
					p.Anonymity = res.Anonymity
					p.LastAlive = time.Now()
					p.ConsecutiveFail = 0 // Reset on success
					p.Score = checker.CalculateScore(p)
					mu.Lock()
					aliveCount++
					aliveList = append(aliveList, p)
					mu.Unlock()
				} else {
					p.IsAlive = false
					p.ConsecutiveFail++
					// Apply score decay on failure
					p.Score = checker.CalculateScore(p)
					mu.Lock()
					deadCount++
					mu.Unlock()
				}

				_ = d.storage.SaveOrUpdateProxy(p)
			}
		}()
	}

	for _, p := range proxies {
		jobs <- p
	}
	close(jobs)
	wg.Wait()

	// Flush pending async DB writes
	d.storage.Flush()

	// Smart purge: proxies with ≥5 consecutive fails OR dead >48h
	purged, _ := d.storage.PurgeDeadProxies(5, 48*time.Hour)

	// Diff-based file sync: only update if there are alive proxies to write
	if d.exporter != nil && len(aliveList) > 0 {
		_ = d.exporter.SyncAliveFiles(aliveList)
	}

	totalAlive, _ := d.storage.TotalAliveCount()
	color.New(color.FgHiGreen, color.Bold).Printf(
		"[+] Cycle done: %d Alive | %d Dead | Purged: %d | Pool Total: %d\n",
		aliveCount, deadCount, purged, totalAlive,
	)
}
