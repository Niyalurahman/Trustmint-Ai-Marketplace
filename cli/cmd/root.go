package cmd

import (
	"fmt"
	"os"

	link "github.com/Niyalurahman/trustmint/cmd/link"
	"github.com/Niyalurahman/trustmint/internal/config"
	"github.com/spf13/cobra"
)

var (
	cfg *config.Config
)

var rootCmd = &cobra.Command{
	Use:   "trustmint",
	Short: "TrustMint CLI",
	PersistentPreRunE: func(cmd *cobra.Command, args []string) error {
		if _, err := os.Stat("trustmint.yaml"); err == nil {
			var loadErr error
			cfg, loadErr = config.LoadConfig("trustmint.yaml")
			if loadErr != nil {
				return loadErr
			}
			fmt.Println("✅ Loaded config for wallet:", cfg.WalletAddress)
		} else {
			fmt.Println("⚠️ No trustmint.yaml found. Run `trustmint init` first.")
		}
		return nil
	},
}

func init() {
	link.Register(rootCmd)
}

// Execute runs the root command
func Execute() {
	if err := rootCmd.Execute(); err != nil {
		fmt.Println(err)
		os.Exit(1)
	}
}
