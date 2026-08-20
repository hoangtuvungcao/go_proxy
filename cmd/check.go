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
	loopFlag     bool
	retryFlag    bool
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
	checkCmd.Flags().BoolVarP(&loopFlag, "loop", "l", false, "Chế độ vòng lặp vô tận: tự động quét lại từ đầu khi hết danh sách IP")
	checkCmd.Flags().BoolVarP(&retryFlag, "retry", "r", false, "Tương đương --loop: tự động quét lại vòng lặp")
}

func runCheck(cmd *cobra.Command, args []string) {
	ShowBanner()
	cfg := GetConfig()

	if loadedPath := GetLoadedConfigFile(); loadedPath != "" {
		color.New(color.FgHiGreen).Printf("[*] Đã nạp cấu hình từ: %s\n", loadedPath)
	}

	// Áp dụng cờ lệnh CLI CHỈ KHI người dùng nhập tường minh trên dòng lệnh
	if cmd.Flags().Changed("workers") {
		cfg.Engine.Workers = workersFlag
	}
	if cmd.Flags().Changed("timeout") {
		cfg.Engine.ConnectTimeout = timeoutFlag
		cfg.Engine.ReadWriteTimeout = timeoutFlag
	}
	if cmd.Flags().Changed("output") {
		cfg.Storage.OutputDir = outputDir
	}
	if cmd.Flags().Changed("port") {
		cfg.Engine.AutoPort = portFlag
	}
	if cmd.Flags().Changed("protocol") {
		if protoFlag != "auto" {
			cfg.Protocol.Protocols = []model.Protocol{model.Protocol(protoFlag)}
			cfg.Protocol.AutoDetect = false
		}
	}
	if cmd.Flags().Changed("loop") || cmd.Flags().Changed("retry") {
		cfg.Engine.Loop = loopFlag || retryFlag
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

	if fileFlag != "" {
		color.New(color.FgHiCyan).Printf("[*] Ingesting targets from file: %s\n", fileFlag)
	} else {
		// Check if stdin has data
		stat, _ := os.Stdin.Stat()
		if (stat.Mode() & os.ModeCharDevice) != 0 {
			color.New(color.FgYellow).Println("[!] No STDIN pipe detected. Waiting for input (e.g. zmap -p 8080 | goproxy check -p 8080)...")
		} else {
			color.New(color.FgHiCyan).Println("[*] Streaming targets from STDIN (ZMap pipe)...")
		}
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
	if cfg.Engine.Loop {
		color.New(color.FgHiYellow, color.Bold).Println("[*] Chế độ vòng lặp vô tận (--loop/--retry) ĐÃ BẬT: Sẽ tự động quét lại khi hết danh sách!")
	}
	startTime := time.Now()

	// Ingest stream in goroutine so cancellation doesn't block on stdin read
	ingestDone := make(chan error, 1)
	go func() {
		loopCount := 1
		for {
			var reader io.Reader = os.Stdin
			var f *os.File
			if fileFlag != "" {
				var errOpen error
				f, errOpen = os.Open(fileFlag)
				if errOpen != nil {
					ingestDone <- errOpen
					return
				}
				reader = f
			}

			errIngest := p.IngestFromReader(reader, portFlag, selectedProto)
			if f != nil {
				_ = f.Close()
			}

			if errIngest != nil && errIngest != io.EOF && errIngest != context.Canceled {
				ingestDone <- errIngest
				return
			}

			// Nếu không bật chế độ vòng lặp hoặc đọc từ STDIN, kết thúc chu kỳ
			if !cfg.Engine.Loop || fileFlag == "" {
				ingestDone <- nil
				return
			}

			loopCount++
			color.New(color.FgHiYellow, color.Bold).Printf("\n[*] Đã hoàn tất danh sách %s! Bắt đầu vòng lặp quét lại lần %d (--loop)...\n", fileFlag, loopCount)
			select {
			case <-ctx.Done():
				ingestDone <- nil
				return
			case <-time.After(2 * time.Second):
			}
		}
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
