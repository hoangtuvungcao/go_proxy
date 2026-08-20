package cmd

import (
	"os"

	"github.com/fatih/color"
	"github.com/spf13/cobra"
	"goproxy/pkg/judge"
)

var judgePort string

var judgeCmd = &cobra.Command{
	Use:   "judge",
	Short: "Start a lightweight local HTTP Judge server",
	Long: `Starts a standalone ultra-fast HTTP Judge server responding with /ip, /json,
and /azenv.php endpoints to test proxy anonymity at high throughput without external rate limits.`,
	Run: runJudge,
}

func init() {
	rootCmd.AddCommand(judgeCmd)
	judgeCmd.Flags().StringVarP(&judgePort, "addr", "a", ":8000", "HTTP Judge server listen address")
}

func runJudge(cmd *cobra.Command, args []string) {
	ShowBanner()
	color.New(color.FgHiGreen, color.Bold).Printf("[*] Starting Local HTTP Judge on %s (Endpoints: /ip, /json, /azenv.php)\n", judgePort)
	if err := judge.StartJudgeServer(judgePort); err != nil {
		color.New(color.FgRed).Printf("[-] Judge server error: %v\n", err)
		os.Exit(1)
	}
}
