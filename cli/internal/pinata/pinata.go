package pinata

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"mime/multipart"
	"net/http"
	"os"
	"path/filepath"
	"strings"

	"github.com/ethereum/go-ethereum/crypto"
)

// PinataPinFileResponse represents pinFileToIPFS response snippet
type PinataPinFileResponse struct {
	IpfsHash  string `json:"IpfsHash"`
	PinSize   int    `json:"PinSize"`
	Timestamp string `json:"Timestamp"`
}

// getEnvOrReturn returns value if not empty otherwise tries env key
func getEnvOrReturn(val, envKey string) string {
	if strings.TrimSpace(val) != "" {
		return val
	}
	return strings.TrimSpace(os.Getenv(envKey))
}

// UploadFileToPinata uploads a file to Pinata using pinFileToIPFS and returns the CID (Qm...)
func UploadFileToPinata(apiKey, apiSecret, filePath string) (string, error) {
	apiKey = getEnvOrReturn(apiKey, "PINATA_API_KEY")
	apiSecret = getEnvOrReturn(apiSecret, "PINATA_SECRET_API_KEY")
	if apiKey == "" || apiSecret == "" {
		return "", fmt.Errorf("pinata api key/secret missing; set env PINATA_API_KEY and PINATA_SECRET_API_KEY")
	}

	f, err := os.Open(filePath)
	if err != nil {
		return "", err
	}
	defer f.Close()

	var b bytes.Buffer
	writer := multipart.NewWriter(&b)
	part, err := writer.CreateFormFile("file", filepath.Base(filePath))
	if err != nil {
		return "", err
	}
	if _, err := io.Copy(part, f); err != nil {
		return "", err
	}
	_ = writer.Close()

	req, err := http.NewRequest("POST", "https://api.pinata.cloud/pinning/pinFileToIPFS", &b)
	if err != nil {
		return "", err
	}
	req.Header.Set("Content-Type", writer.FormDataContentType())
	req.Header.Set("pinata_api_key", apiKey)
	req.Header.Set("pinata_secret_api_key", apiSecret)

	client := &http.Client{}
	resp, err := client.Do(req)
	if err != nil {
		return "", err
	}
	defer resp.Body.Close()

	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		body, _ := io.ReadAll(resp.Body)
		return "", fmt.Errorf("pinata file upload failed: status=%d body=%s", resp.StatusCode, string(body))
	}

	var pr PinataPinFileResponse
	if err := json.NewDecoder(resp.Body).Decode(&pr); err != nil {
		return "", err
	}
	return pr.IpfsHash, nil
}

// UploadJSONToPinata uploads a JSON payload (object) to Pinata via pinJSONToIPFS
func UploadJSONToPinata(apiKey, apiSecret string, jsonBody interface{}) (string, error) {
	apiKey = getEnvOrReturn(apiKey, "PINATA_API_KEY")
	apiSecret = getEnvOrReturn(apiSecret, "PINATA_SECRET_API_KEY")
	if apiKey == "" || apiSecret == "" {
		return "", fmt.Errorf("pinata api key/secret missing; set env PINATA_API_KEY and PINATA_SECRET_API_KEY")
	}

	bodyBytes, err := json.Marshal(jsonBody)
	if err != nil {
		return "", err
	}
	req, err := http.NewRequest("POST", "https://api.pinata.cloud/pinning/pinJSONToIPFS", bytes.NewReader(bodyBytes))
	if err != nil {
		return "", err
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("pinata_api_key", apiKey)
	req.Header.Set("pinata_secret_api_key", apiSecret)

	client := &http.Client{}
	resp, err := client.Do(req)
	if err != nil {
		return "", err
	}
	defer resp.Body.Close()

	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		body, _ := io.ReadAll(resp.Body)
		return "", fmt.Errorf("pinata json upload failed: status=%d body=%s", resp.StatusCode, string(body))
	}
	var pr PinataPinFileResponse
	if err := json.NewDecoder(resp.Body).Decode(&pr); err != nil {
		return "", err
	}
	return pr.IpfsHash, nil
}

// SignAndWritePayload signs the metadataCid (keccak256) using cli private key (hex), writes payload.json in outDir
// and returns the payload map.
func SignAndWritePayload(metadataCid string, cliPrivHex string, outDir string) (map[string]string, error) {
	// normalize CLI private key: allow 0x prefix
	cliPrivHex = strings.TrimSpace(cliPrivHex)
	if strings.HasPrefix(cliPrivHex, "0x") {
		cliPrivHex = cliPrivHex[2:]
	}

	// keccak256 hash of metadataCid
	hash := crypto.Keccak256([]byte(metadataCid))
	hashHex := "0x" + hex.EncodeToString(hash)

	// sign with private key (expect priv key hex without 0x)
	priv, err := crypto.HexToECDSA(cliPrivHex)
	if err != nil {
		return nil, fmt.Errorf("invalid cli private key: %w", err)
	}
	sig, err := crypto.Sign(hash, priv)
	if err != nil {
		return nil, err
	}
	// Convert V to 27/28 for solidity's ecrecover
	if sig[64] < 27 {
		sig[64] += 27
	}
	sigHex := "0x" + hex.EncodeToString(sig)

	// compute SHA256 of metadataCid string as additional local verification (optional)
	sha := sha256.Sum256([]byte(metadataCid))
	shaHex := hex.EncodeToString(sha[:])

	payload := map[string]string{
		"metadataCid":  metadataCid,
		"metadataHash": hashHex,
		"cliSignature": sigHex,
		"sha256":       shaHex,
	}

	// write payload.json
	if err := os.MkdirAll(outDir, 0700); err != nil {
		return nil, err
	}
	outPath := filepath.Join(outDir, "payload.json")
	f, err := os.Create(outPath)
	if err != nil {
		return nil, err
	}
	enc := json.NewEncoder(f)
	enc.SetIndent("", "  ")
	if err := enc.Encode(payload); err != nil {
		_ = f.Close()
		return nil, err
	}
	_ = f.Close()
	return payload, nil
}
