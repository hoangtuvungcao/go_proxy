package pipeline

import (
	"context"
	"fmt"
	"sort"
	"strings"
	"sync/atomic"
	"time"

	"github.com/fatih/color"
	"goproxy/pkg/model"
)

// StartLiveDashboard launches a background goroutine updating a rich block dashboard
func StartLiveDashboard(ctx context.Context, stats *model.Stats, interval time.Duration) {
	if interval <= 0 {
		interval = 500 * time.Millisecond
	}

	ticker := time.NewTicker(interval)
	go func() {
		defer ticker.Stop()
		printDashboardHeader()
		for {
			select {
			case <-ctx.Done():
				return
			case <-ticker.C:
				stats.PushHistoryPoint()
				printDashboard(stats)
			}
		}
	}()
}

func printDashboardHeader() {
	fmt.Print("\033[2J\033[H") // Clear screen and move to top
}

// printDashboard renders a compact multi-line terminal dashboard
func printDashboard(stats *model.Stats) {
	scanned := atomic.LoadInt64(&stats.TotalScanned)
	queued := atomic.LoadInt64(&stats.TotalQueued)
	alive := atomic.LoadInt64(&stats.TotalAlive)
	dead := atomic.LoadInt64(&stats.TotalDead)
	httpAlive := atomic.LoadInt64(&stats.HTTPAlive)
	httpsAlive := atomic.LoadInt64(&stats.HTTPSAlive)
	s5Alive := atomic.LoadInt64(&stats.SOCKS5Alive)
	s4Alive := atomic.LoadInt64(&stats.SOCKS4Alive)
	elite := atomic.LoadInt64(&stats.EliteAlive)
	anon := atomic.LoadInt64(&stats.AnonymousAlive)
	transp := atomic.LoadInt64(&stats.TransparentAlive)
	speed := stats.Speed()

	elapsed := time.Since(stats.StartTime)
	hours := int(elapsed.Hours())
	minutes := int(elapsed.Minutes()) % 60
	seconds := int(elapsed.Seconds()) % 60

	remaining := queued - scanned
	if remaining < 0 {
		remaining = 0
	}

	// Speed bar (50 chars wide)
	maxSpeed := 5000.0
	barLen := int(speed / maxSpeed * 50)
	if barLen > 50 {
		barLen = 50
	}
	speedBar := strings.Repeat("█", barLen) + strings.Repeat("░", 50-barLen)

	// Rate percentage
	aliveRate := 0.0
	if scanned > 0 {
		aliveRate = float64(alive) / float64(scanned) * 100.0
	}

	// Top countries
	stats.Snapshot() // warm the lock
	topCountries := getTopCountries(stats, 6)

	// Move cursor to home position and draw (in-place refresh)
	fmt.Print("\033[H")

	bold := color.New(color.Bold)
	cyan := color.New(color.FgHiCyan, color.Bold)
	green := color.New(color.FgHiGreen, color.Bold)
	yellow := color.New(color.FgHiYellow)
	red := color.New(color.FgHiRed)
	magenta := color.New(color.FgHiMagenta)
	blue := color.New(color.FgHiBlue)
	white := color.New(color.FgWhite)
	dim := color.New(color.FgHiBlack)

	line := strings.Repeat("─", 72)
	fmt.Println()
	cyan.Printf("  ╔%s╗\n", strings.Repeat("═", 70))
	cyan.Printf("  ║")
	bold.Printf("  %-20s", "  GoProxy 2026 Pro")
	white.Printf("│ Runtime: %02d:%02d:%02d │ Speed: ", hours, minutes, seconds)
	green.Printf("%-10s", fmt.Sprintf("%.0f/s", speed))
	cyan.Printf("              ║\n")
	cyan.Printf("  ╠%s╣\n", strings.Repeat("═", 70))

	// Row 1: Main counters
	cyan.Printf("  ║  ")
	yellow.Printf("Scanned: %-10d", scanned)
	green.Printf("│ Alive: %-8d", alive)
	dim.Printf("(%.1f%%)", aliveRate)
	red.Printf("│ Dead: %-8d", dead)
	white.Printf("│ Queue: %-7d", remaining)
	cyan.Printf("  ║\n")

	// Row 2: Protocol breakdown
	cyan.Printf("  ║  ")
	blue.Printf("HTTP: %-7d", httpAlive)
	cyan.Printf("│ HTTPS: %-6d", httpsAlive)
	magenta.Printf("│ SOCKS5: %-6d", s5Alive)
	yellow.Printf("│ SOCKS4: %-6d", s4Alive)
	white.Printf("                 ")
	cyan.Printf("║\n")

	// Row 3: Anonymity breakdown
	cyan.Printf("  ║  ")
	green.Printf("Elite: %-8d", elite)
	yellow.Printf("│ Anonymous: %-5d", anon)
	red.Printf("│ Transparent: %-4d", transp)
	white.Printf("                   ")
	cyan.Printf("║\n")

	// Row 4: Top Countries
	cyan.Printf("  ║  ")
	white.Printf("Top: %-61s", topCountries)
	cyan.Printf("║\n")

	// Row 5: Speed bar
	cyan.Printf("  ║  ")
	white.Printf("Speed [")
	green.Printf("%s", speedBar[:barLen])
	dim.Printf("%s", speedBar[barLen:])
	white.Printf("] ")
	green.Printf("%.0f/s", speed)
	cyan.Printf("     ║\n")

	cyan.Printf("  ╚%s╝\n", strings.Repeat("═", 70))
	_ = line
}

// getTopCountries returns a formatted string of the top N countries by count
func getTopCountries(stats *model.Stats, n int) string {
	snap := stats.Snapshot()
	countries, ok := snap["top_countries"].(map[string]int64)
	if !ok || len(countries) == 0 {
		return "—"
	}

	type kv struct {
		Key   string
		Value int64
	}
	var sorted []kv
	for k, v := range countries {
		sorted = append(sorted, kv{k, v})
	}
	sort.Slice(sorted, func(i, j int) bool {
		return sorted[i].Value > sorted[j].Value
	})

	var parts []string
	for i, item := range sorted {
		if i >= n {
			break
		}
		parts = append(parts, fmt.Sprintf("%s:%d", item.Key, item.Value))
	}
	return strings.Join(parts, "  ")
}

// PrintFinalSummary prints a comprehensive end-of-scan report
func PrintFinalSummary(stats *model.Stats) {
	snap := stats.Snapshot()

	fmt.Println()
	color.New(color.FgHiCyan, color.Bold).Println("╔══════════════════════  SCAN COMPLETE  ══════════════════════╗")
	fmt.Printf("  Total Queued    : %d\n", snap["total_queued"])
	fmt.Printf("  Total Scanned   : %d\n", snap["total_scanned"])
	color.New(color.FgHiGreen, color.Bold).Printf("  Total Alive     : %d\n", snap["total_alive"])
	color.New(color.FgHiRed).Printf("  Total Dead      : %d\n", snap["total_dead"])
	fmt.Printf("  Throughput      : %.2f IPs/sec\n", snap["speed_ips_sec"])
	fmt.Printf("  Duration        : %d seconds\n", snap["uptime_seconds"])
	fmt.Println("  ─────────────────────────────────────────────────────────────")
	fmt.Printf("  Protocols       : HTTP: %v | HTTPS: %v | SOCKS5: %v | SOCKS4: %v\n",
		snap["http_alive"], snap["https_alive"], snap["socks5_alive"], snap["socks4_alive"])
	fmt.Printf("  Anonymity       : Elite: %v | Anonymous: %v | Transparent: %v\n",
		snap["elite_alive"], snap["anonymous_alive"], snap["transparent_alive"])

	countries, ok := snap["top_countries"].(map[string]int64)
	if ok && len(countries) > 0 {
		fmt.Println("  ─────────────────────────────────────────────────────────────")
		fmt.Print("  Top Countries   : ")

		type kv struct {
			Key   string
			Value int64
		}
		var sorted []kv
		for k, v := range countries {
			sorted = append(sorted, kv{k, v})
		}
		sort.Slice(sorted, func(i, j int) bool {
			return sorted[i].Value > sorted[j].Value
		})

		var parts []string
		for i, item := range sorted {
			if i >= 10 {
				break
			}
			parts = append(parts, fmt.Sprintf("%s: %d", item.Key, item.Value))
		}
		color.New(color.FgHiYellow).Println(strings.Join(parts, " | "))
	}
	color.New(color.FgHiCyan, color.Bold).Println("╚══════════════════════════════════════════════════════════════╝")
}
