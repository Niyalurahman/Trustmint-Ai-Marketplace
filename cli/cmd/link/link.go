// file: cli/cmd/link/link.go
package link

import (
	"crypto/ecdsa"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"

	"github.com/ethereum/go-ethereum/crypto"
	"github.com/spf13/cobra"
)

// (same constants & types as before)
const (
	trustmintDirName = ".trustmint"
	keyFileName      = "cli_priv.hex"
	payloadFileName  = "payload.json"
)

type Payload struct {
	MetadataCID    string `json:"metadataCid"`
	MetadataHash   string `json:"metadataHash"`
	CLISignature   string `json:"cliSignature"`
	ArtifactSHA256 string `json:"artifactSha256,omitempty"`
}

// Define the command (exported name)
var LinkCmd = &cobra.Command{
	Use:   "link",
	Short: "Generate/show CLI keypair and Ethereum-style address",
	RunE: func(cmd *cobra.Command, args []string) error {
		keyfilePath, err := ensureKeyFilePath()
		if err != nil {
			return err
		}
		priv, created, err := loadOrCreateKey(keyfilePath)
		if err != nil {
			return err
		}
		if created {
			fmt.Printf("Generated new CLI key and saved to %s\n", keyfilePath)
		} else {
			fmt.Printf("Loaded existing CLI key from %s\n", keyfilePath)
		}
		addr := crypto.PubkeyToAddress(priv.PublicKey)
		fmt.Println("CLI public (eth) address:", addr.Hex())
		fmt.Println()
		fmt.Println("Next step: visit TrustMint website, connect MetaMask, and call registerDeveloper(<CLI address>) from your wallet.")
		return nil
	},
}

// Register attaches the command to the provided root command
func Register(root *cobra.Command) {
	root.AddCommand(LinkCmd)
}

// --- helpers (same as before) ---

func ensureKeyFilePath() (string, error) {
	home, err := os.UserHomeDir()
	if err != nil {
		return "", err
	}
	dir := filepath.Join(home, trustmintDirName)
	if err := os.MkdirAll(dir, 0700); err != nil {
		return "", err
	}
	return filepath.Join(dir, keyFileName), nil
}

func loadOrCreateKey(path string) (*ecdsa.PrivateKey, bool, error) {
	if _, err := os.Stat(path); os.IsNotExist(err) {
		priv, err := crypto.GenerateKey()
		if err != nil {
			return nil, false, err
		}
		privHex := hex.EncodeToString(crypto.FromECDSA(priv))
		if err := os.WriteFile(path, []byte(privHex), 0600); err != nil {
			return nil, false, err
		}
		return priv, true, nil
	}
	b, err := os.ReadFile(path)
	if err != nil {
		return nil, false, err
	}
	priv, err := crypto.HexToECDSA(string(b))
	if err != nil {
		return nil, false, err
	}
	return priv, false, nil
}

func SignMetadataCID(metadataCID string, priv *ecdsa.PrivateKey) (string, error) {
	if metadataCID == "" {
		return "", errors.New("metadataCID required")
	}
	hash := crypto.Keccak256([]byte(metadataCID))
	sig, err := crypto.Sign(hash, priv)
	if err != nil {
		return "", err
	}
	if len(sig) != 65 {
		return "", fmt.Errorf("unexpected signature length: %d", len(sig))
	}
	sigCopy := make([]byte, 65)
	copy(sigCopy, sig)
	if sigCopy[64] < 27 {
		sigCopy[64] += 27
	}
	return "0x" + hex.EncodeToString(sigCopy), nil
}

func SignAndWritePayload(metadataCID string, optionalArtifactPath string) (string, error) {
	keyfilePath, err := ensureKeyFilePath()
	if err != nil {
		return "", err
	}
	priv, _, err := loadOrCreateKey(keyfilePath)
	if err != nil {
		return "", err
	}
	hash := crypto.Keccak256([]byte(metadataCID))
	hashHex := "0x" + hex.EncodeToString(hash)
	sigHex, err := SignMetadataCID(metadataCID, priv)
	if err != nil {
		return "", err
	}
	payload := Payload{
		MetadataCID:  metadataCID,
		MetadataHash: hashHex,
		CLISignature: sigHex,
	}
	if optionalArtifactPath != "" {
		if shaHex, err := computeKeccakHex(optionalArtifactPath); err == nil {
			payload.ArtifactSHA256 = shaHex
		}
	}
	home, _ := os.UserHomeDir()
	dir := filepath.Join(home, trustmintDirName)
	outPath := filepath.Join(dir, payloadFileName)
	outB, _ := json.MarshalIndent(payload, "", "  ")
	if err := os.WriteFile(outPath, outB, 0644); err != nil {
		return "", err
	}
	return outPath, nil
}

func computeKeccakHex(filePath string) (string, error) {
	data, err := os.ReadFile(filePath)
	if err != nil {
		return "", err
	}
	sum := crypto.Keccak256(data)
	return "0x" + hex.EncodeToString(sum), nil
}

func GetCLIAddress() (string, error) {
	keyfilePath, err := ensureKeyFilePath()
	if err != nil {
		return "", err
	}
	priv, _, err := loadOrCreateKey(keyfilePath)
	if err != nil {
		return "", err
	}
	addr := crypto.PubkeyToAddress(priv.PublicKey)
	return addr.Hex(), nil
}
