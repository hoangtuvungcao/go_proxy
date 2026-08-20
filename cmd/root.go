package cmd

import (
	"fmt"
	"os"

	"github.com/spf13/cobra"
	"gopkg.in/yaml.v3"
	"goproxy/internal/banner"
	"goproxy/pkg/model"
)

var (
	cfgFile string
	globalConfig *model.Config
)

var rootCmd = &cobra.Command{
	Use:   "goproxy",
	Short: "GoProxy — High Performance Proxy Scanner & Checker Pool",
	Long: `GoProxy is an ultra-fast, multi-protocol proxy checking engine designed
specifically for piping ZMap/Masscan outputs at high throughput (10,000+ IPs/sec).
Supports HTTP, HTTPS CONNECT, SOCKS4, SOCKS5, Anonymity scoring, GeoIP, REST API,
and Web Dashboard.`,
}

// Execute runs the root command
func Execute() {
	if err := rootCmd.Execute(); err != nil {
		fmt.Fprintf(os.Stderr, "Error: %v\n", err)
		os.Exit(1)
	}
}

func init() {
	cobra.OnInitialize(initConfig)
	rootCmd.PersistentFlags().StringVarP(&cfgFile, "config", "c", "", "Config file (default: configs/config.yaml)")
}

func initConfig() {
	globalConfig = model.DefaultConfig()

	if cfgFile != "" {
		data, err := os.ReadFile(cfgFile)
		if err == nil {
			_ = yaml.Unmarshal(data, globalConfig)
		}
	} else {
		// Try default config file path
		data, err := os.ReadFile("configs/config.yaml")
		if err == nil {
			_ = yaml.Unmarshal(data, globalConfig)
		}
	}
}

// GetConfig returns loaded config
func GetConfig() *model.Config {
	if globalConfig == nil {
		globalConfig = model.DefaultConfig()
	}
	return globalConfig
}

// ShowBanner displays the startup ASCII art
func ShowBanner() {
	banner.PrintBanner()
}
