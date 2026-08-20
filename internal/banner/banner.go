package banner

import (
	"github.com/fatih/color"
)

const BannerText = `
   ______      ____                      ____            
  / ____/___  / __ \_________  _  ____  __/ __ \_________  
 / / __/ __ \/ /_/ / ___/ __ \| |/_/ / / / /_/ / ___/ __ \ 
/ /_/ / /_/ / ____/ /  / /_/ />  </ /_/ / ____/ /  / /_/ / 
\____/\____/_/   /_/   \____/_/|_|\__, /_/   /_/   \____/  
                                 /____/  v2.0.0 [PRO PRODUCTION]
`

// PrintBanner prints the styled startup banner
func PrintBanner() {
	color.New(color.FgHiCyan, color.Bold).Print(BannerText)
	color.New(color.FgHiBlack).Println(" Ultra-Fast ZMap Stream Ingestion & Multi-Protocol Proxy Health Engine")
	color.New(color.FgHiBlack).Println("----------------------------------------------------------------------")
	color.New(color.FgHiBlack).Println()
}
