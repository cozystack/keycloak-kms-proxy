package crypto

import (
	"fmt"

	"github.com/tink-crypto/tink-go/v2/aead"
	"github.com/tink-crypto/tink-go/v2/keyset"
	"github.com/tink-crypto/tink-go/v2/tink"
)

// Primitive is the encrypt/decrypt contract shared by both schemes; the Cipher
// facade (C4) selects one per field. associatedData is authenticated but not
// encrypted (it binds a ciphertext to its column context).
type Primitive interface {
	Encrypt(plaintext, associatedData []byte) ([]byte, error)
	Decrypt(ciphertext, associatedData []byte) ([]byte, error)
	// Scheme reports which scheme this primitive implements (for the marker).
	Scheme() Scheme
}

// NonDeterministicAEAD is AES-256-GCM: a fresh nonce per encryption (embedded
// in the output), so equal plaintexts yield distinct ciphertexts. Used for
// unsearched PII columns.
type NonDeterministicAEAD struct {
	aead tink.AEAD
}

// NewNonDeterministicAEAD builds the AES-GCM primitive from a DEK keyset.
func NewNonDeterministicAEAD(h *keyset.Handle) (*NonDeterministicAEAD, error) {
	a, err := aead.New(h)
	if err != nil {
		return nil, fmt.Errorf("crypto: build AES-GCM primitive: %w", err)
	}
	return &NonDeterministicAEAD{aead: a}, nil
}

// Encrypt encrypts plaintext, authenticating associatedData.
func (a *NonDeterministicAEAD) Encrypt(plaintext, associatedData []byte) ([]byte, error) {
	return a.aead.Encrypt(plaintext, associatedData)
}

// Decrypt decrypts ciphertext, verifying associatedData.
func (a *NonDeterministicAEAD) Decrypt(ciphertext, associatedData []byte) ([]byte, error) {
	return a.aead.Decrypt(ciphertext, associatedData)
}

// Scheme reports SchemeNonDeterministic.
func (a *NonDeterministicAEAD) Scheme() Scheme { return SchemeNonDeterministic }
