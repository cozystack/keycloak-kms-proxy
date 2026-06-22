package crypto

import (
	"bytes"
	"testing"
)

func TestDeterministicRoundTrip(t *testing.T) {
	t.Parallel()

	h, err := GenerateDEK(SchemeDeterministic)
	if err != nil {
		t.Fatalf("GenerateDEK: %v", err)
	}
	d, err := NewDeterministicAEAD(h)
	if err != nil {
		t.Fatalf("NewDeterministicAEAD: %v", err)
	}
	if d.Scheme() != SchemeDeterministic {
		t.Fatalf("Scheme()=%v, want %v", d.Scheme(), SchemeDeterministic)
	}

	plaintext := []byte("alice")
	aad := []byte("USER_ENTITY.USERNAME")

	ct, err := d.Encrypt(plaintext, aad)
	if err != nil {
		t.Fatalf("Encrypt: %v", err)
	}
	pt, err := d.Decrypt(ct, aad)
	if err != nil {
		t.Fatalf("Decrypt: %v", err)
	}
	if !bytes.Equal(pt, plaintext) {
		t.Fatalf("round-trip mismatch: got %q, want %q", pt, plaintext)
	}
}

func TestDeterministicIsDeterministic(t *testing.T) {
	t.Parallel()

	h, _ := GenerateDEK(SchemeDeterministic)
	d, _ := NewDeterministicAEAD(h)

	aad := []byte("USER_ENTITY.EMAIL")
	ct1, err := d.Encrypt([]byte("alice@example.com"), aad)
	if err != nil {
		t.Fatalf("Encrypt #1: %v", err)
	}
	ct2, err := d.Encrypt([]byte("alice@example.com"), aad)
	if err != nil {
		t.Fatalf("Encrypt #2: %v", err)
	}
	if !bytes.Equal(ct1, ct2) {
		t.Fatal("deterministic AEAD produced different ciphertexts for equal plaintext+aad")
	}

	// Distinct plaintexts must not collide.
	ct3, _ := d.Encrypt([]byte("bob@example.com"), aad)
	if bytes.Equal(ct1, ct3) {
		t.Fatal("distinct plaintexts produced identical ciphertext")
	}

	// Associated data is bound into the synthetic IV: differing aad differs.
	ct4, _ := d.Encrypt([]byte("alice@example.com"), []byte("OTHER.COLUMN"))
	if bytes.Equal(ct1, ct4) {
		t.Fatal("differing associated data produced identical ciphertext")
	}
}

func TestDeterministicTamperDetection(t *testing.T) {
	t.Parallel()

	h, _ := GenerateDEK(SchemeDeterministic)
	d, _ := NewDeterministicAEAD(h)

	ct, err := d.Encrypt([]byte("alice"), []byte("aad"))
	if err != nil {
		t.Fatalf("Encrypt: %v", err)
	}
	tampered := bytes.Clone(ct)
	tampered[len(tampered)-1] ^= 0xff
	if _, err := d.Decrypt(tampered, []byte("aad")); err == nil {
		t.Fatal("Decrypt accepted tampered ciphertext")
	}
}

func TestNormalizeLowercaseEnablesCaseInsensitiveMatch(t *testing.T) {
	t.Parallel()

	if got := NormalizeLowercase("Alice@Example.COM"); got != "alice@example.com" {
		t.Fatalf("NormalizeLowercase: got %q", got)
	}

	h, _ := GenerateDEK(SchemeDeterministic)
	d, _ := NewDeterministicAEAD(h)
	aad := []byte("USER_ENTITY.EMAIL")

	mixed, err := d.Encrypt([]byte(NormalizeLowercase("Alice@Example.COM")), aad)
	if err != nil {
		t.Fatalf("Encrypt mixed: %v", err)
	}
	lower, err := d.Encrypt([]byte(NormalizeLowercase("alice@example.com")), aad)
	if err != nil {
		t.Fatalf("Encrypt lower: %v", err)
	}
	if !bytes.Equal(mixed, lower) {
		t.Fatal("normalized case variants did not encrypt to equal ciphertext")
	}
}
