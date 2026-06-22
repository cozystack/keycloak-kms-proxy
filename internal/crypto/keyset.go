package crypto

import (
	"fmt"

	"github.com/tink-crypto/tink-go/v2/aead"
	"github.com/tink-crypto/tink-go/v2/daead"
	"github.com/tink-crypto/tink-go/v2/keyset"
)

// GenerateDEK creates a fresh data-encryption-key keyset for the given scheme:
// AES-SIV for deterministic, AES-256-GCM for non-deterministic. The DEK is
// wrapped by the KEK before storage and is never persisted in cleartext.
func GenerateDEK(scheme Scheme) (*keyset.Handle, error) {
	switch scheme {
	case SchemeDeterministic:
		return keyset.NewHandle(daead.AESSIVKeyTemplate())
	case SchemeNonDeterministic:
		return keyset.NewHandle(aead.AES256GCMKeyTemplate())
	default:
		return nil, fmt.Errorf("%w: %d", ErrUnknownScheme, uint8(scheme))
	}
}
