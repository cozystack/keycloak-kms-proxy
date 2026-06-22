package kms

import (
	"context"
	"fmt"

	"github.com/cozystack/keycloak-kms-proxy/internal/crypto"
)

// DEKSet is the pair of KMS-wrapped DEKs (one per scheme) at a single key
// version, plus the optional blind-index HMAC key.
// Only the wrapped material is persisted; the KEK that wraps it lives in the
// KMS and the plaintext keys never reach storage. BlindIndexKey
// is optional: existing DEK sets without it remain valid and yield a Cipher
// without blind-index support.
type DEKSet struct {
	KeyVersion       uint32
	Deterministic    []byte
	NonDeterministic []byte
	BlindIndexKey    []byte `json:",omitempty"`
}

// GenerateDEKSet mints fresh DEKs for both schemes plus a blind-index HMAC key
// and wraps each with the KMS.
func GenerateDEKSet(ctx context.Context, k KMS, keyVersion uint32) (DEKSet, error) {
	det, err := wrapFreshDEK(ctx, k, crypto.SchemeDeterministic)
	if err != nil {
		return DEKSet{}, err
	}
	nondet, err := wrapFreshDEK(ctx, k, crypto.SchemeNonDeterministic)
	if err != nil {
		return DEKSet{}, err
	}
	indexKey, err := crypto.GenerateBlindIndexKey()
	if err != nil {
		return DEKSet{}, err
	}
	wrappedIndex, err := k.Wrap(ctx, indexKey)
	if err != nil {
		return DEKSet{}, err
	}
	return DEKSet{
		KeyVersion:       keyVersion,
		Deterministic:    det,
		NonDeterministic: nondet,
		BlindIndexKey:    wrappedIndex,
	}, nil
}

func wrapFreshDEK(ctx context.Context, k KMS, scheme crypto.Scheme) ([]byte, error) {
	h, err := crypto.GenerateDEK(scheme)
	if err != nil {
		return nil, err
	}
	raw, err := crypto.MarshalDEK(h)
	if err != nil {
		return nil, err
	}
	return k.Wrap(ctx, raw)
}

// OpenCipher unwraps a DEKSet and builds a ready-to-use crypto.Cipher. Each
// key is unwrapped exactly once here; the returned Cipher caches the
// primitives so column encrypt/decrypt and blind-index hashing never call the
// KMS again (KMSv2 DEK caching). The blind-index key is optional — older DEK
// sets do not carry one and the resulting Cipher reports no
// blind index.
func OpenCipher(ctx context.Context, k KMS, set DEKSet) (*crypto.Cipher, error) {
	det, err := openDeterministic(ctx, k, set.Deterministic)
	if err != nil {
		return nil, err
	}
	nondet, err := openNonDeterministic(ctx, k, set.NonDeterministic)
	if err != nil {
		return nil, err
	}
	var index *crypto.BlindIndex
	if len(set.BlindIndexKey) > 0 {
		raw, err := k.Unwrap(ctx, set.BlindIndexKey)
		if err != nil {
			return nil, fmt.Errorf("kms: open blind-index key: %w", err)
		}
		index = crypto.NewBlindIndex(raw)
	}
	return crypto.NewCipher(set.KeyVersion, index, det, nondet)
}

func openDeterministic(ctx context.Context, k KMS, wrapped []byte) (*crypto.DeterministicAEAD, error) {
	raw, err := k.Unwrap(ctx, wrapped)
	if err != nil {
		return nil, err
	}
	h, err := crypto.UnmarshalDEK(raw)
	if err != nil {
		return nil, fmt.Errorf("kms: open deterministic DEK: %w", err)
	}
	return crypto.NewDeterministicAEAD(h)
}

func openNonDeterministic(ctx context.Context, k KMS, wrapped []byte) (*crypto.NonDeterministicAEAD, error) {
	raw, err := k.Unwrap(ctx, wrapped)
	if err != nil {
		return nil, err
	}
	h, err := crypto.UnmarshalDEK(raw)
	if err != nil {
		return nil, fmt.Errorf("kms: open non-deterministic DEK: %w", err)
	}
	return crypto.NewNonDeterministicAEAD(h)
}

// RotateKEK re-wraps a DEKSet from oldKMS's KEK to newKMS's KEK without
// re-encrypting any column data: the DEKs themselves are unchanged, so the key
// version and every existing ciphertext marker remain valid.
func RotateKEK(ctx context.Context, oldKMS, newKMS KMS, set DEKSet) (DEKSet, error) {
	det, err := rewrapDEK(ctx, oldKMS, newKMS, set.Deterministic)
	if err != nil {
		return DEKSet{}, err
	}
	nondet, err := rewrapDEK(ctx, oldKMS, newKMS, set.NonDeterministic)
	if err != nil {
		return DEKSet{}, err
	}
	return DEKSet{KeyVersion: set.KeyVersion, Deterministic: det, NonDeterministic: nondet}, nil
}

func rewrapDEK(ctx context.Context, oldKMS, newKMS KMS, wrapped []byte) ([]byte, error) {
	raw, err := oldKMS.Unwrap(ctx, wrapped)
	if err != nil {
		return nil, fmt.Errorf("kms: unwrap under old KEK: %w", err)
	}
	return newKMS.Wrap(ctx, raw)
}
