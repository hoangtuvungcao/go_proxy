package cmd

import (
	"fmt"
	"os"
	"path/filepath"

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

var loadedConfigFile string

func initConfig() {
	globalConfig = model.DefaultConfig()

	candidates := []string{}
	if cfgFile != "" {
		candidates = append(candidates, cfgFile)
	} else {
		candidates = append(candidates, "configs/config.yaml", "config.yaml")
		if execPath, err := os.Executable(); err == nil {
			execDir := filepath.Dir(execPath)
			candidates = append(candidates, filepath.Join(execDir, "configs", "config.yaml"), filepath.Join(execDir, "config.yaml"))
		}
	}

	for _, p := range candidates {
		if data, err := os.ReadFile(p); err == nil {
			if err := yaml.Unmarshal(data, globalConfig); err == nil {
				loadedConfigFile = p
				break
			}
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

// GetLoadedConfigFile returns the path of the loaded config file, if any
func GetLoadedConfigFile() string {
	return loadedConfigFile
}

// ShowBanner displays the startup ASCII art
func ShowBanner() {
	banner.PrintBanner()
}
