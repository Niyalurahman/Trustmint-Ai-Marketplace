package crypto

import (
	"encoding/hex"
	"fmt"

	"github.com/ethereum/go-ethereum/crypto"
)

// SignKeccak256Hex signs the keccak256 hash of the input hex string (e.g. metadataCid)
// It returns a 0x-prefixed signature hex (R||S||V).
func SignKeccak256Hex(message []byte, privKeyHex string) (string, error) {
	priv, err := crypto.HexToECDSA(privKeyHex)
	if err != nil {
		return "", err
	}

	hash := crypto.Keccak256(message)   // bytes32
	sig, err := crypto.Sign(hash, priv) // r||s||v (v 0/1)
	if err != nil {
		return "", err
	}

	// crypto.Sign returns V as 0/1 — convert to 27/28
	if len(sig) != 65 {
		return "", fmt.Errorf("unexpected signature length: %d", len(sig))
	}
	if sig[64] < 27 {
		sig[64] += 27
	}
	return "0x" + hex.EncodeToString(sig), nil
}
