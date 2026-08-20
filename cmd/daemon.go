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
	"goproxy/pkg/storage"
)

var (
	daemonInterval time.Duration
	daemonWorkers  int
)

var daemonCmd = &cobra.Command{
	Use:   "daemon",
	Short: "Run continuous background health rechecker for proxy pool",
	Long: `Daemon runs in background, periodically re-verifying all stored proxies
in the SQLite database, updating their uptime percentages, latency scores, and
purging dead proxies to maintain high reliability.`,
	Run: runDaemon,
}

func init() {
	rootCmd.AddCommand(daemonCmd)

	daemonCmd.Flags().DurationVarP(&daemonInterval, "interval", "i", 5*time.Minute, "Recheck interval (e.g. 5m, 10m)")
	daemonCmd.Flags().IntVarP(&daemonWorkers, "workers", "w", 500, "Concurrent recheck workers")
}

func runDaemon(cmd *cobra.Command, args []string) {
	ShowBanner()
	cfg := GetConfig()

	store, err := storage.NewSQLiteStore(cfg.Storage.DBPath)
	if err != nil {
		color.New(color.FgRed).Printf("[-] Failed to open database %s: %v\n", cfg.Storage.DBPath, err)
		os.Exit(1)
	}
	defer store.Close()

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	sigChan := make(chan os.Signal, 1)
	signal.Notify(sigChan, os.Interrupt, syscall.SIGTERM)
	go func() {
		<-sigChan
		cancel()
	}()

	exporter, _ := storage.NewExporter(cfg.Storage)
	if exporter != nil {
		defer exporter.Close()
	}

	d := daemon.NewDaemon(cfg, store, exporter, daemonInterval, daemonWorkers)
	d.Run(ctx)
}
