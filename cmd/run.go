package cmd

import (
	"context"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/fatih/color"
	"github.com/spf13/cobra"
	"goproxy/pkg/daemon"
	"goproxy/pkg/server"
	"goproxy/pkg/storage"
)

var (
	allInOneAPIPort  string
	allInOneInterval time.Duration
	allInOneWorkers  int
)

var runCmd = &cobra.Command{
	Use:   "run",
	Short: "Khởi chạy hệ thống Dashboard và Background Health Daemon",
	Long: `Chế độ vận hành tự động:
Khởi chạy đồng thời REST API, Web Dashboard
và Background Health Daemon tự động lọc proxy chết định kỳ.`,
	Run: runAllInOne,
}

func init() {
	rootCmd.AddCommand(runCmd)

	runCmd.Flags().StringVar(&allInOneAPIPort, "api-addr", ":8080", "Dia chi lang nghe Web Dashboard va REST API")
	runCmd.Flags().DurationVar(&allInOneInterval, "recheck-interval", 5*time.Minute, "Chu ky tu dong quet lai proxy chet")
	runCmd.Flags().IntVar(&allInOneWorkers, "recheck-workers", 300, "So worker kiem tra lai dinh ky")
}

func runAllInOne(cmd *cobra.Command, args []string) {
	ShowBanner()
	cfg := GetConfig()

	// 1. Initialize SQLite Database
	store, err := storage.NewSQLiteStore(cfg.Storage.DBPath)
	if err != nil {
		color.New(color.FgRed).Printf("[-] Loi khoi tao SQLite %s: %v\n", cfg.Storage.DBPath, err)
		os.Exit(1)
	}
	defer store.Close()

	// 2. Initialize File Exporter
	exporter, _ := storage.NewExporter(cfg.Storage)
	if exporter != nil {
		defer exporter.Close()
	}

	totalAlive, _ := store.TotalAliveCount()
	color.New(color.FgHiGreen, color.Bold).Printf("[*] Co so du lieu san sang. Tong proxy hoat dong hien tai: %d\n", totalAlive)

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	// 3. Start REST API & Web Dashboard
	apiServer := server.NewAPIServer(allInOneAPIPort, store, nil)
	go func() {
		if err := apiServer.Start(); err != nil {
			color.New(color.FgRed).Printf("[-] API server error: %v\n", err)
		}
	}()
	defer apiServer.Close()

	// 4. Start Background Health Daemon in background goroutine
	d := daemon.NewDaemon(cfg, store, exporter, allInOneInterval, allInOneWorkers)
	go d.Run(ctx)

	color.New(color.FgHiCyan, color.Bold).Println("[+] He thong GoProxy da khoi dong thanh cong!")
	color.New(color.FgHiWhite).Printf("    - Web Dashboard:     http://localhost%s\n", allInOneAPIPort)
	color.New(color.FgHiWhite).Printf("    - Prometheus Metric: http://localhost%s/metrics\n", allInOneAPIPort)
	color.New(color.FgHiWhite).Printf("    - Health Daemon:     Tu dong loc & dong bo file moi %v\n\n", allInOneInterval)

	sigChan := make(chan os.Signal, 1)
	signal.Notify(sigChan, os.Interrupt, syscall.SIGTERM)
	<-sigChan

	color.New(color.FgYellow, color.Bold).Println("\n[!] Dang dung he thong an toan...")
}

