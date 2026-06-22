package crypto

import (
	"bytes"
	"testing"
)

func TestNonDeterministicRoundTrip(t *testing.T) {
	t.Parallel()

	h, err := GenerateDEK(SchemeNonDeterministic)
	if err != nil {
		t.Fatalf("GenerateDEK: %v", err)
	}
	a, err := NewNonDeterministicAEAD(h)
	if err != nil {
		t.Fatalf("NewNonDeterministicAEAD: %v", err)
	}
	if a.Scheme() != SchemeNonDeterministic {
		t.Fatalf("Scheme()=%v, want %v", a.Scheme(), SchemeNonDeterministic)
	}

	plaintext := []byte("secret-credential-data")
	aad := []byte("USER_ENTITY.FIRST_NAME")

	ct, err := a.Encrypt(plaintext, aad)
	if err != nil {
		t.Fatalf("Encrypt: %v", err)
	}
	pt, err := a.Decrypt(ct, aad)
	if err != nil {
		t.Fatalf("Decrypt: %v", err)
	}
	if !bytes.Equal(pt, plaintext) {
		t.Fatalf("round-trip mismatch: got %q, want %q", pt, plaintext)
	}
}

func TestNonDeterministicProducesDistinctCiphertexts(t *testing.T) {
	t.Parallel()

	h, err := GenerateDEK(SchemeNonDeterministic)
	if err != nil {
		t.Fatalf("GenerateDEK: %v", err)
	}
	a, err := NewNonDeterministicAEAD(h)
	if err != nil {
		t.Fatalf("NewNonDeterministicAEAD: %v", err)
	}

	plaintext := []byte("alice@example.com")
	ct1, err := a.Encrypt(plaintext, nil)
	if err != nil {
		t.Fatalf("Encrypt #1: %v", err)
	}
	ct2, err := a.Encrypt(plaintext, nil)
	if err != nil {
		t.Fatalf("Encrypt #2: %v", err)
	}
	if bytes.Equal(ct1, ct2) {
		t.Fatal("non-deterministic AEAD produced identical ciphertexts for equal plaintext")
	}
}

func TestNonDeterministicTamperDetection(t *testing.T) {
	t.Parallel()

	h, err := GenerateDEK(SchemeNonDeterministic)
	if err != nil {
		t.Fatalf("GenerateDEK: %v", err)
	}
	a, err := NewNonDeterministicAEAD(h)
	if err != nil {
		t.Fatalf("NewNonDeterministicAEAD: %v", err)
	}

	ct, err := a.Encrypt([]byte("data"), []byte("aad"))
	if err != nil {
		t.Fatalf("Encrypt: %v", err)
	}

	// Flip a byte: decryption must fail.
	tampered := bytes.Clone(ct)
	tampered[len(tampered)-1] ^= 0xff
	if _, err := a.Decrypt(tampered, []byte("aad")); err == nil {
		t.Fatal("Decrypt accepted tampered ciphertext")
	}

	// Wrong associated data: decryption must fail (AAD binding).
	if _, err := a.Decrypt(ct, []byte("other-aad")); err == nil {
		t.Fatal("Decrypt accepted mismatched associated data")
	}
}

func TestNonDeterministicWrongKeyFails(t *testing.T) {
	t.Parallel()

	h1, _ := GenerateDEK(SchemeNonDeterministic)
	h2, _ := GenerateDEK(SchemeNonDeterministic)
	a1, _ := NewNonDeterministicAEAD(h1)
	a2, _ := NewNonDeterministicAEAD(h2)

	ct, err := a1.Encrypt([]byte("data"), nil)
	if err != nil {
		t.Fatalf("Encrypt: %v", err)
	}
	if _, err := a2.Decrypt(ct, nil); err == nil {
		t.Fatal("Decrypt under a different key succeeded")
	}
}

func TestGenerateDEKUnknownScheme(t *testing.T) {
	t.Parallel()

	if _, err := GenerateDEK(Scheme(42)); err == nil {
		t.Fatal("GenerateDEK accepted an unknown scheme")
	}
}
