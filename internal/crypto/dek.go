package crypto

import (
	"bytes"
	"fmt"

	"github.com/tink-crypto/tink-go/v2/insecurecleartextkeyset"
	"github.com/tink-crypto/tink-go/v2/keyset"
)

// MarshalDEK serializes a DEK keyset to cleartext bytes. The cleartext keyset
// exists only transiently in proxy memory (inside the trust boundary); callers
// wrap it with the KMS before it is ever persisted.
func MarshalDEK(h *keyset.Handle) ([]byte, error) {
	var buf bytes.Buffer
	if err := insecurecleartextkeyset.Write(h, keyset.NewBinaryWriter(&buf)); err != nil {
		return nil, fmt.Errorf("crypto: marshal DEK: %w", err)
	}
	return buf.Bytes(), nil
}

// UnmarshalDEK reconstructs a DEK keyset handle from MarshalDEK output.
func UnmarshalDEK(b []byte) (*keyset.Handle, error) {
	h, err := insecurecleartextkeyset.Read(keyset.NewBinaryReader(bytes.NewReader(b)))
	if err != nil {
		return nil, fmt.Errorf("crypto: unmarshal DEK: %w", err)
	}
	return h, nil
}
