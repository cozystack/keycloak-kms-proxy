package crypto

import (
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"fmt"
	"io"
	"math"
)

// BlindIndexKeyBytes is the HMAC-SHA-256 key length used by BlindIndex.
const BlindIndexKeyBytes = 32

// BlindIndex computes the keyed HMAC-SHA-256 of column values for the shadow
// hash columns. Equal normalized plaintexts hash to
// equal values under the same key, which lets admin LIKE searches that strip
// to a wildcard-free term match on the hash column without the proxy ever
// exposing the plaintext to the database. The HMAC key is wrapped by the same
// KMS as the DEKs and rotated alongside them.
type BlindIndex struct {
	key []byte
}

// NewBlindIndex builds a BlindIndex from a 32-byte HMAC key.
func NewBlindIndex(key []byte) *BlindIndex {
	out := make([]byte, len(key))
	copy(out, key)
	return &BlindIndex{key: out}
}

// Compute returns the hex-encoded HMAC of plaintext, with associatedData bound
// into the MAC so the same plaintext under different column contexts produces
// different hashes (mirrors the AEAD AAD discipline). The hex form fits inside
// a `VARCHAR(64)` column.
func (b *BlindIndex) Compute(plaintext, associatedData []byte) (string, error) {
	if len(associatedData) > math.MaxUint32 {
		return "", fmt.Errorf("crypto: associated data too long (%d bytes)", len(associatedData))
	}
	mac := hmac.New(sha256.New, b.key)
	var lengthPrefix [4]byte
	binary.BigEndian.PutUint32(lengthPrefix[:], uint32(len(associatedData))) //nolint:gosec // bounds-checked above.
	mac.Write(lengthPrefix[:])
	mac.Write(associatedData)
	mac.Write(plaintext)
	return hex.EncodeToString(mac.Sum(nil)), nil
}

// GenerateBlindIndexKey returns a fresh random 32-byte HMAC key, for use as the
// blind-index key in a DEK set.
func GenerateBlindIndexKey() ([]byte, error) {
	key := make([]byte, BlindIndexKeyBytes)
	if _, err := io.ReadFull(rand.Reader, key); err != nil {
		return nil, err
	}
	return key, nil
}
