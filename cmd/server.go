package cmd

import (
	"os"
	"os/signal"
	"syscall"

	"github.com/fatih/color"
	"github.com/spf13/cobra"
	"goproxy/pkg/server"
	"goproxy/pkg/storage"
)

var (
	srvAPIPort string
)

var serverCmd = &cobra.Command{
	Use:   "server",
	Short: "Start REST API & Web Dashboard",
	Long:  `Starts the HTTP REST API server and modern Web Dashboard to view and export scanned proxies.`,
	Run:   runServer,
}

func init() {
	rootCmd.AddCommand(serverCmd)

	serverCmd.Flags().StringVar(&srvAPIPort, "api-addr", ":8080", "REST API & Web UI listen address")
}

func runServer(cmd *cobra.Command, args []string) {
	ShowBanner()
	cfg := GetConfig()

	store, err := storage.NewSQLiteStore(cfg.Storage.DBPath)
	if err != nil {
		color.New(color.FgRed).Printf("[-] Failed to open database %s: %v\n", cfg.Storage.DBPath, err)
		os.Exit(1)
	}
	defer store.Close()

	totalAlive, _ := store.TotalAliveCount()
	color.New(color.FgHiGreen).Printf("[*] Database loaded. Active verified proxies in pool: %d\n", totalAlive)

	// Start REST API & Dashboard
	apiServer := server.NewAPIServer(srvAPIPort, store, nil)
	go func() {
		if err := apiServer.Start(); err != nil {
			color.New(color.FgRed).Printf("[-] API server error: %v\n", err)
		}
	}()
	defer apiServer.Close()

	color.New(color.FgHiCyan).Println("[*] System operational. Press Ctrl+C to terminate.")

	sigChan := make(chan os.Signal, 1)
	signal.Notify(sigChan, os.Interrupt, syscall.SIGTERM)
	<-sigChan
	color.New(color.FgYellow).Println("\n[!] Shutting down server...")
}

