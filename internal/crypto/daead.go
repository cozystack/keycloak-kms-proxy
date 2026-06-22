package crypto

import (
	"fmt"
	"strings"

	"github.com/tink-crypto/tink-go/v2/daead"
	"github.com/tink-crypto/tink-go/v2/keyset"
	"github.com/tink-crypto/tink-go/v2/tink"
)

// DeterministicAEAD is AES-SIV: equal plaintext (with equal associated data)
// always yields equal ciphertext, which keeps Keycloak's equality search
// working on encrypted searched columns (username, email). It
// leaks equality but those columns are unique, so the leak is minimal.
type DeterministicAEAD struct {
	daead tink.DeterministicAEAD
}

// NewDeterministicAEAD builds the AES-SIV primitive from a DEK keyset.
func NewDeterministicAEAD(h *keyset.Handle) (*DeterministicAEAD, error) {
	d, err := daead.New(h)
	if err != nil {
		return nil, fmt.Errorf("crypto: build AES-SIV primitive: %w", err)
	}
	return &DeterministicAEAD{daead: d}, nil
}

// Encrypt deterministically encrypts plaintext, binding associatedData into the
// synthetic IV. The associated data must be stable across encryptions of the
// same logical value for equality search to match.
func (d *DeterministicAEAD) Encrypt(plaintext, associatedData []byte) ([]byte, error) {
	return d.daead.EncryptDeterministically(plaintext, associatedData)
}

// Decrypt deterministically decrypts ciphertext, verifying associatedData.
func (d *DeterministicAEAD) Decrypt(ciphertext, associatedData []byte) ([]byte, error) {
	return d.daead.DecryptDeterministically(ciphertext, associatedData)
}

// Scheme reports SchemeDeterministic.
func (d *DeterministicAEAD) Scheme() Scheme { return SchemeDeterministic }

// NormalizeLowercase folds a value to lower case for deterministic columns that
// Keycloak searches case-insensitively (username, email). Applied
// before encryption so equality search matches regardless of input case.
func NormalizeLowercase(s string) string { return strings.ToLower(s) }
