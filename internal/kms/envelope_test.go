package kms

import (
	"bytes"
	"context"
	"testing"

	"github.com/cozystack/keycloak-kms-proxy/internal/crypto"
)

// countingKMS wraps a KMS and counts calls, to assert the DEK-caching property.
type countingKMS struct {
	inner          KMS
	wraps, unwraps int
}

func (c *countingKMS) Wrap(ctx context.Context, p []byte) ([]byte, error) {
	c.wraps++
	return c.inner.Wrap(ctx, p)
}

func (c *countingKMS) Unwrap(ctx context.Context, w []byte) ([]byte, error) {
	c.unwraps++
	return c.inner.Unwrap(ctx, w)
}

func newTestKMS(t *testing.T) KMS {
	t.Helper()

	kek, err := GenerateKEK()
	if err != nil {
		t.Fatalf("GenerateKEK: %v", err)
	}
	k, err := NewStaticKMS(kek)
	if err != nil {
		t.Fatalf("NewStaticKMS: %v", err)
	}
	return k
}

func TestGenerateAndOpenCipherRoundTrip(t *testing.T) {
	t.Parallel()

	ctx := context.Background()
	k := newTestKMS(t)

	set, err := GenerateDEKSet(ctx, k, 1)
	if err != nil {
		t.Fatalf("GenerateDEKSet: %v", err)
	}
	c, err := OpenCipher(ctx, k, set)
	if err != nil {
		t.Fatalf("OpenCipher: %v", err)
	}

	for _, scheme := range []crypto.Scheme{crypto.SchemeDeterministic, crypto.SchemeNonDeterministic} {
		stored, err := c.Encrypt(scheme, []byte("alice@example.com"), []byte("aad"))
		if err != nil {
			t.Fatalf("Encrypt(%v): %v", scheme, err)
		}
		got, err := c.Decrypt(stored, []byte("aad"))
		if err != nil {
			t.Fatalf("Decrypt(%v): %v", scheme, err)
		}
		if string(got) != "alice@example.com" {
			t.Fatalf("round-trip(%v): got %q", scheme, got)
		}
	}
}

func TestOpenCipherCachesDEKs(t *testing.T) {
	t.Parallel()

	ctx := context.Background()
	counting := &countingKMS{inner: newTestKMS(t)}

	set, err := GenerateDEKSet(ctx, counting, 1)
	if err != nil {
		t.Fatalf("GenerateDEKSet: %v", err)
	}
	if counting.wraps != 3 {
		t.Fatalf("GenerateDEKSet wraps: got %d, want 3 (det DEK + nondet DEK + blind-index key)", counting.wraps)
	}

	c, err := OpenCipher(ctx, counting, set)
	if err != nil {
		t.Fatalf("OpenCipher: %v", err)
	}
	if counting.unwraps != 3 {
		t.Fatalf("OpenCipher unwraps: got %d, want 3 (det DEK + nondet DEK + blind-index key)", counting.unwraps)
	}

	// Column operations must not touch the KMS again (DEK caching).
	before := counting.unwraps + counting.wraps
	stored, _ := c.Encrypt(crypto.SchemeNonDeterministic, []byte("x"), nil)
	if _, err := c.Decrypt(stored, nil); err != nil {
		t.Fatalf("Decrypt: %v", err)
	}
	if after := counting.unwraps + counting.wraps; after != before {
		t.Fatalf("crypto ops triggered %d extra KMS calls", after-before)
	}
}

func TestRotateKEKKeepsDataDecryptable(t *testing.T) {
	t.Parallel()

	ctx := context.Background()
	kmsA := newTestKMS(t)
	kmsB := newTestKMS(t)

	set, err := GenerateDEKSet(ctx, kmsA, 1)
	if err != nil {
		t.Fatalf("GenerateDEKSet: %v", err)
	}
	cipherA, err := OpenCipher(ctx, kmsA, set)
	if err != nil {
		t.Fatalf("OpenCipher A: %v", err)
	}
	stored, err := cipherA.Encrypt(crypto.SchemeDeterministic, []byte("alice"), []byte("aad"))
	if err != nil {
		t.Fatalf("Encrypt: %v", err)
	}

	// Rotate the KEK: re-wrap the DEKs under kmsB without re-encrypting data.
	rotated, err := RotateKEK(ctx, kmsA, kmsB, set)
	if err != nil {
		t.Fatalf("RotateKEK: %v", err)
	}
	if rotated.KeyVersion != set.KeyVersion {
		t.Errorf("KEK rotation changed the key version: %d -> %d", set.KeyVersion, rotated.KeyVersion)
	}
	if bytes.Equal(rotated.Deterministic, set.Deterministic) {
		t.Error("rotated wrapped DEK is identical to the original")
	}

	cipherB, err := OpenCipher(ctx, kmsB, rotated)
	if err != nil {
		t.Fatalf("OpenCipher B: %v", err)
	}
	got, err := cipherB.Decrypt(stored, []byte("aad"))
	if err != nil {
		t.Fatalf("Decrypt after rotation: %v", err)
	}
	if string(got) != "alice" {
		t.Fatalf("post-rotation decrypt: got %q, want %q", got, "alice")
	}
}

func TestOpenCipherWrongKMSFails(t *testing.T) {
	t.Parallel()

	ctx := context.Background()
	set, err := GenerateDEKSet(ctx, newTestKMS(t), 1)
	if err != nil {
		t.Fatalf("GenerateDEKSet: %v", err)
	}
	if _, err := OpenCipher(ctx, newTestKMS(t), set); err == nil {
		t.Fatal("OpenCipher succeeded with the wrong KMS")
	}
}
