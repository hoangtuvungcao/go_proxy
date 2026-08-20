package cmd

import (
	"context"
	"io"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/fatih/color"
	"github.com/spf13/cobra"
	"goproxy/pkg/model"
	"goproxy/pkg/pipeline"
	"goproxy/pkg/server"
	"goproxy/pkg/storage"
)

var (
	portFlag     int
	workersFlag  int
	protoFlag    string
	fileFlag     string
	timeoutFlag  time.Duration
	outputDir    string
	quietFlag    bool
	noDBFlag     bool
	serveWithAPI bool
	apiPortFlag  string
)

var checkCmd = &cobra.Command{
	Use:   "check",
	Short: "Check proxies from Stdin pipeline (ZMap/Masscan) or file",
	Long: `The check command processes a stream of IP addresses or IP:Port pairs
from standard input (e.g., piped from zmap) or a file, validates them across
protocols, detects anonymity, resolves GeoIP, and exports healthy proxies.

Examples:
  # ZMap pipeline check
  zmap -p 8080 1.0.0.0/8 | goproxy check -p 8080 -w 3000 --protocol http

  # Check SOCKS5 from ZMap on port 1080
  zmap -p 1080 103.0.0.0/8 | goproxy check -p 1080 --protocol socks5

  # Check from file containing IP or IP:PORT list
  goproxy check -f targets.txt -w 2000

  # Check with Web UI & REST API enabled at the same time
  zmap -p 8080 | goproxy check -p 8080 --serve`,
	Run: runCheck,
}

func init() {
	rootCmd.AddCommand(checkCmd)

	checkCmd.Flags().IntVarP(&portFlag, "port", "p", 8080, "Default port if input contains only IP addresses (from ZMap)")
	checkCmd.Flags().IntVarP(&workersFlag, "workers", "w", 2000, "Number of concurrent worker goroutines")
	checkCmd.Flags().StringVarP(&protoFlag, "protocol", "P", "auto", "Protocol to check (http, https, socks4, socks5, auto)")
	checkCmd.Flags().StringVarP(&fileFlag, "file", "f", "", "Input file path (default: reads from STDIN)")
	checkCmd.Flags().DurationVarP(&timeoutFlag, "timeout", "t", 2000*time.Millisecond, "Network timeout per check")
	checkCmd.Flags().StringVarP(&outputDir, "output", "o", "output", "Directory to write alive proxies and reports")
	checkCmd.Flags().BoolVarP(&quietFlag, "quiet", "q", false, "Quiet mode: only show live dashboard progress bar")
	checkCmd.Flags().BoolVar(&noDBFlag, "no-db", false, "Disable SQLite database saving")
	checkCmd.Flags().BoolVar(&serveWithAPI, "serve", false, "Start REST API & Web Dashboard in background during scan")
	checkCmd.Flags().StringVar(&apiPortFlag, "api-port", ":8080", "Address/port for background API server")
}

func runCheck(cmd *cobra.Command, args []string) {
	ShowBanner()
	cfg := GetConfig()

	// Apply CLI overrides
	if workersFlag > 0 {
		cfg.Engine.Workers = workersFlag
	}
	if timeoutFlag > 0 {
		cfg.Engine.ConnectTimeout = timeoutFlag
		cfg.Engine.ReadWriteTimeout = timeoutFlag
	}
	if outputDir != "" {
		cfg.Storage.OutputDir = outputDir
	}

	// Setup SQLite
	var store *storage.SQLiteStore
	var err error
	if !noDBFlag && cfg.Storage.SaveSQLite {
		store, err = storage.NewSQLiteStore(cfg.Storage.DBPath)
		if err != nil {
			color.New(color.FgRed).Printf("[-] Warning: Failed to init SQLite database: %v. Continuing without DB.\n", err)
		} else {
			defer store.Close()
		}
	}

	// Setup File Exporter
	exporter, err := storage.NewExporter(cfg.Storage)
	if err != nil {
		color.New(color.FgRed).Printf("[-] Failed to init file exporter: %v\n", err)
		os.Exit(1)
	}
	defer exporter.Close()

	// Determine input stream
	var inputReader io.Reader
	if fileFlag != "" {
		f, err := os.Open(fileFlag)
		if err != nil {
			color.New(color.FgRed).Printf("[-] Failed to open input file %s: %v\n", fileFlag, err)
			os.Exit(1)
		}
		defer f.Close()
		inputReader = f
		color.New(color.FgHiCyan).Printf("[*] Ingesting targets from file: %s\n", fileFlag)
	} else {
		// Check if stdin has data
		stat, _ := os.Stdin.Stat()
		if (stat.Mode() & os.ModeCharDevice) != 0 {
			color.New(color.FgYellow).Println("[!] No STDIN pipe detected. Waiting for input (e.g. zmap -p 8080 | goproxy check -p 8080)...")
		} else {
			color.New(color.FgHiCyan).Println("[*] Streaming targets from STDIN (ZMap pipe)...")
		}
		inputReader = os.Stdin
	}

	// Protocol selection
	selectedProto := model.Protocol(protoFlag)
	if protoFlag == "auto" {
		selectedProto = model.ProtoUnknown
	}

	// Setup graceful interrupt handling
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	// Initialize pipeline
	p := pipeline.NewPipeline(cfg, store, exporter, quietFlag)
	p.Start(cfg.Engine.Workers)

	sigChan := make(chan os.Signal, 2)
	signal.Notify(sigChan, os.Interrupt, syscall.SIGTERM)
	go func() {
		<-sigChan
		color.New(color.FgYellow, color.Bold).Println("\n[!] Đang dừng quét và hoàn tất lưu dữ liệu... (Nhấn Ctrl+C lần nữa để buộc thoát)")
		p.Cancel()
		cancel()

		// Tự động ép thoát sau tối đa 2 giây nếu có luồng bị kẹt I/O
		go func() {
			time.Sleep(2 * time.Second)
			os.Exit(0)
		}()

		// Nhấn Ctrl+C lần 2 sẽ buộc thoát ngay lập tức
		<-sigChan
		color.New(color.FgRed, color.Bold).Println("\n[!] Buộc dừng ngay lập tức!")
		os.Exit(0)
	}()

	// Launch optional REST API & Dashboard
	if serveWithAPI && store != nil {
		apiServer := server.NewAPIServer(apiPortFlag, store, p.Stats())
		go func() {
			if err := apiServer.Start(); err != nil {
				color.New(color.FgRed).Printf("[-] API server error: %v\n", err)
			}
		}()
		defer apiServer.Close()
	}

	// Launch live terminal dashboard if quiet mode
	if quietFlag {
		pipeline.StartLiveDashboard(ctx, p.Stats(), 500*time.Millisecond)
	}

	color.New(color.FgHiGreen, color.Bold).Printf("[*] Worker pool started with %d workers | Port: %d | Protocol: %s\n", cfg.Engine.Workers, portFlag, protoFlag)
	startTime := time.Now()

	// Ingest stream in goroutine so cancellation doesn't block on stdin read
	ingestDone := make(chan error, 1)
	go func() {
		ingestDone <- p.IngestFromReader(inputReader, portFlag, selectedProto)
	}()

	select {
	case err = <-ingestDone:
		if err != nil && err != io.EOF && err != context.Canceled {
			color.New(color.FgRed).Printf("[-] Error while reading input: %v\n", err)
		}
	case <-ctx.Done():
	}

	// Stop workers and finish
	p.Stop()
	if store != nil {
		store.Flush()
		_ = store.Close()
	}
	exporter.Close()
	elapsed := time.Since(startTime)

	// Final Summary Report
	pipeline.PrintFinalSummary(p.Stats())
	color.New(color.FgHiGreen, color.Bold).Printf("[SUCCESS] Scan completed in %s. Alive proxies saved to '%s/'\n", elapsed.Round(time.Millisecond), cfg.Storage.OutputDir)
	os.Exit(0)
}
