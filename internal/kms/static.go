package kms

import (
	"context"
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"errors"
	"fmt"
	"io"
)

// kekSize is the KEK length in bytes (AES-256).
const kekSize = 32

// ErrInvalidKEKSize is returned when the KEK is not the expected length.
var ErrInvalidKEKSize = fmt.Errorf("kms: KEK must be %d bytes (AES-256)", kekSize)

// StaticKMS is a fake KMS whose KEK is a fixed key supplied at construction
// (a static key or one read from a Kubernetes Secret). It wraps the DEK with
// AES-256-GCM. It is a real cryptographic implementation — suitable for tests
// and bootstrap — but offers no rotation of the KEK itself.
type StaticKMS struct {
	gcm cipher.AEAD
}

// NewStaticKMS builds a StaticKMS from a 32-byte KEK.
func NewStaticKMS(kek []byte) (*StaticKMS, error) {
	if len(kek) != kekSize {
		return nil, ErrInvalidKEKSize
	}
	block, err := aes.NewCipher(kek)
	if err != nil {
		return nil, fmt.Errorf("kms: new cipher: %w", err)
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, fmt.Errorf("kms: new GCM: %w", err)
	}
	return &StaticKMS{gcm: gcm}, nil
}

// Wrap encrypts the plaintext DEK; the random nonce is prepended to the output.
func (k *StaticKMS) Wrap(_ context.Context, plaintextDEK []byte) ([]byte, error) {
	nonce := make([]byte, k.gcm.NonceSize())
	if _, err := io.ReadFull(rand.Reader, nonce); err != nil {
		return nil, fmt.Errorf("kms: read nonce: %w", err)
	}
	return k.gcm.Seal(nonce, nonce, plaintextDEK, nil), nil
}

// Unwrap decrypts a wrapped DEK produced by Wrap.
func (k *StaticKMS) Unwrap(_ context.Context, wrappedDEK []byte) ([]byte, error) {
	ns := k.gcm.NonceSize()
	if len(wrappedDEK) < ns {
		return nil, errors.New("kms: wrapped DEK is too short")
	}
	nonce, ciphertext := wrappedDEK[:ns], wrappedDEK[ns:]
	plaintext, err := k.gcm.Open(nil, nonce, ciphertext, nil)
	if err != nil {
		return nil, fmt.Errorf("kms: unwrap: %w", err)
	}
	return plaintext, nil
}

// GenerateKEK returns a fresh random 32-byte KEK, for tests and bootstrap.
func GenerateKEK() ([]byte, error) {
	kek := make([]byte, kekSize)
	if _, err := io.ReadFull(rand.Reader, kek); err != nil {
		return nil, fmt.Errorf("kms: generate KEK: %w", err)
	}
	return kek, nil
}
