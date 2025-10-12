package cmd

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"github.com/Niyalurahman/trustmint/internal/pinata"

	"github.com/joho/godotenv"
	"github.com/spf13/cobra"
)

var uploadCmd = &cobra.Command{
	Use:   "upload",
	Short: "Upload metadata to Pinata/IPFS and produce payload.json",
	Run: func(cmd *cobra.Command, args []string) {
		// load root .env if present (silently ignore missing)
		_ = godotenv.Load()

		metadataPath, _ := cmd.Flags().GetString("metadata")
		outDir, _ := cmd.Flags().GetString("out")

		if metadataPath == "" {
			fmt.Println("metadata path required")
			os.Exit(1)
		}
		if outDir == "" {
			outDir = filepath.Dir(metadataPath)
		}

		// Read environment for pinata keys (the pinata package will fallback to env)
		pinataKey := os.Getenv("PINATA_API_KEY")
		pinataSecret := os.Getenv("PINATA_SECRET_API_KEY")

		// Upload file
		fmt.Println("🔗 Uploading metadata to Pinata...")
		cid, err := pinata.UploadFileToPinata(pinataKey, pinataSecret, metadataPath)
		if err != nil {
			fmt.Println("Error: failed to upload metadata to Pinata:", err)
			os.Exit(1)
		}
		metadataCid := "ipfs://" + cid + "/" + filepath.Base(metadataPath)
		fmt.Println("✅ Uploaded metadata CID:", metadataCid)

		// get CLI private key from env CLI_PRIV_HEX or default path ~/.trustmint/cli_priv.hex
		cliPriv := strings.TrimSpace(os.Getenv("CLI_PRIV_HEX"))
		if cliPriv == "" {
			home, _ := os.UserHomeDir()
			privPath := filepath.Join(home, ".trustmint", "cli_priv.hex")
			b, err := os.ReadFile(privPath)
			if err != nil {
				fmt.Println("Error: CLI private key not found; set CLI_PRIV_HEX env or run `trustmint link` first")
				os.Exit(1)
			}
			cliPriv = strings.TrimSpace(string(b))
		}

		payload, err := pinata.SignAndWritePayload(metadataCid, cliPriv, outDir)
		if err != nil {
			fmt.Println("Error signing/writing payload:", err)
			os.Exit(1)
		}

		fmt.Println("✅ payload.json written to", filepath.Join(outDir, "payload.json"))
		fmt.Printf("Payload summary: metadataCid=%s metadataHash=%s\n", payload["metadataCid"], payload["metadataHash"])
	},
}

func init() {
	uploadCmd.Flags().String("metadata", "output/metadata.json", "Path to metadata JSON produced by train")
	uploadCmd.Flags().String("out", "", "Output directory for payload.json (default: same dir as metadata)")
	rootCmd.AddCommand(uploadCmd)
}
