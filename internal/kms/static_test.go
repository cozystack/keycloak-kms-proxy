package kms

import (
	"bytes"
	"context"
	"testing"
)

func TestStaticKMSRoundTrip(t *testing.T) {
	t.Parallel()

	kek, err := GenerateKEK()
	if err != nil {
		t.Fatalf("GenerateKEK: %v", err)
	}
	k, err := NewStaticKMS(kek)
	if err != nil {
		t.Fatalf("NewStaticKMS: %v", err)
	}

	dek := []byte("serialized-data-encryption-key")
	wrapped, err := k.Wrap(context.Background(), dek)
	if err != nil {
		t.Fatalf("Wrap: %v", err)
	}
	if bytes.Contains(wrapped, dek) {
		t.Fatal("wrapped DEK contains the plaintext DEK")
	}
	got, err := k.Unwrap(context.Background(), wrapped)
	if err != nil {
		t.Fatalf("Unwrap: %v", err)
	}
	if !bytes.Equal(got, dek) {
		t.Fatalf("round-trip mismatch: got %q, want %q", got, dek)
	}
}

func TestStaticKMSWrapIsRandomized(t *testing.T) {
	t.Parallel()

	kek, _ := GenerateKEK()
	k, _ := NewStaticKMS(kek)

	dek := []byte("dek")
	w1, _ := k.Wrap(context.Background(), dek)
	w2, _ := k.Wrap(context.Background(), dek)
	if bytes.Equal(w1, w2) {
		t.Fatal("two wraps of the same DEK are identical (nonce reuse)")
	}
}

func TestStaticKMSTamperDetection(t *testing.T) {
	t.Parallel()

	kek, _ := GenerateKEK()
	k, _ := NewStaticKMS(kek)

	wrapped, err := k.Wrap(context.Background(), []byte("dek"))
	if err != nil {
		t.Fatalf("Wrap: %v", err)
	}
	tampered := bytes.Clone(wrapped)
	tampered[len(tampered)-1] ^= 0xff
	if _, err := k.Unwrap(context.Background(), tampered); err == nil {
		t.Fatal("Unwrap accepted a tampered wrapped DEK")
	}
}

func TestStaticKMSWrongKEKFails(t *testing.T) {
	t.Parallel()

	kek1, _ := GenerateKEK()
	kek2, _ := GenerateKEK()
	k1, _ := NewStaticKMS(kek1)
	k2, _ := NewStaticKMS(kek2)

	wrapped, _ := k1.Wrap(context.Background(), []byte("dek"))
	if _, err := k2.Unwrap(context.Background(), wrapped); err == nil {
		t.Fatal("Unwrap under a different KEK succeeded")
	}
}

func TestStaticKMSStableAcrossInstances(t *testing.T) {
	t.Parallel()

	// The same KEK material (e.g. read from a Kubernetes Secret on restart)
	// must unwrap a previously wrapped DEK.
	kek, _ := GenerateKEK()
	k1, _ := NewStaticKMS(kek)
	wrapped, _ := k1.Wrap(context.Background(), []byte("dek"))

	k2, _ := NewStaticKMS(kek)
	got, err := k2.Unwrap(context.Background(), wrapped)
	if err != nil {
		t.Fatalf("Unwrap on a fresh instance: %v", err)
	}
	if !bytes.Equal(got, []byte("dek")) {
		t.Fatalf("got %q, want %q", got, "dek")
	}
}

func TestNewStaticKMSValidatesKEKSize(t *testing.T) {
	t.Parallel()

	if _, err := NewStaticKMS([]byte("too-short")); err == nil {
		t.Fatal("NewStaticKMS accepted an undersized KEK")
	}
}

func TestStaticKMSUnwrapTooShort(t *testing.T) {
	t.Parallel()

	kek, _ := GenerateKEK()
	k, _ := NewStaticKMS(kek)
	if _, err := k.Unwrap(context.Background(), []byte{0x00}); err == nil {
		t.Fatal("Unwrap accepted a truncated input")
	}
}

// StaticKMS must satisfy the KMS interface.
var _ KMS = (*StaticKMS)(nil)
