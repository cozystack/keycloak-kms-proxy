package kms

import "context"

// KMS wraps and unwraps a data encryption key (DEK) with a key encryption key
// (KEK) that lives inside the KMS (Kubernetes KMS v2 envelope
// model). The plaintext DEK never persists at rest — only the wrapped DEK is
// stored alongside the proxy. The byte-blob contract mirrors Vault Transit's
// encrypt/decrypt so the same interface serves both the fake and Vault backends.
type KMS interface {
	// Wrap encrypts the plaintext DEK with the current KEK.
	Wrap(ctx context.Context, plaintextDEK []byte) ([]byte, error)
	// Unwrap decrypts a previously wrapped DEK with the KEK.
	Unwrap(ctx context.Context, wrappedDEK []byte) ([]byte, error)
}
