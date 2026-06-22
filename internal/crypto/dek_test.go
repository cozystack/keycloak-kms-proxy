package crypto

import (
	"bytes"
	"testing"
)

func TestMarshalDEKRoundTripNonDeterministic(t *testing.T) {
	t.Parallel()

	h, err := GenerateDEK(SchemeNonDeterministic)
	if err != nil {
		t.Fatalf("GenerateDEK: %v", err)
	}
	orig, err := NewNonDeterministicAEAD(h)
	if err != nil {
		t.Fatalf("NewNonDeterministicAEAD: %v", err)
	}
	ct, err := orig.Encrypt([]byte("data"), []byte("aad"))
	if err != nil {
		t.Fatalf("Encrypt: %v", err)
	}

	raw, err := MarshalDEK(h)
	if err != nil {
		t.Fatalf("MarshalDEK: %v", err)
	}
	restoredHandle, err := UnmarshalDEK(raw)
	if err != nil {
		t.Fatalf("UnmarshalDEK: %v", err)
	}
	restored, err := NewNonDeterministicAEAD(restoredHandle)
	if err != nil {
		t.Fatalf("NewNonDeterministicAEAD(restored): %v", err)
	}

	pt, err := restored.Decrypt(ct, []byte("aad"))
	if err != nil {
		t.Fatalf("Decrypt with restored DEK: %v", err)
	}
	if !bytes.Equal(pt, []byte("data")) {
		t.Fatalf("round-trip mismatch: got %q", pt)
	}
}

func TestMarshalDEKRoundTripDeterministic(t *testing.T) {
	t.Parallel()

	h, _ := GenerateDEK(SchemeDeterministic)
	orig, _ := NewDeterministicAEAD(h)
	want, err := orig.Encrypt([]byte("alice"), []byte("aad"))
	if err != nil {
		t.Fatalf("Encrypt: %v", err)
	}

	raw, err := MarshalDEK(h)
	if err != nil {
		t.Fatalf("MarshalDEK: %v", err)
	}
	restoredHandle, err := UnmarshalDEK(raw)
	if err != nil {
		t.Fatalf("UnmarshalDEK: %v", err)
	}
	restored, _ := NewDeterministicAEAD(restoredHandle)

	// Determinism must survive serialization: same key → same ciphertext.
	got, err := restored.Encrypt([]byte("alice"), []byte("aad"))
	if err != nil {
		t.Fatalf("Encrypt with restored DEK: %v", err)
	}
	if !bytes.Equal(got, want) {
		t.Fatal("restored DEK produced a different deterministic ciphertext")
	}
}

func TestUnmarshalDEKRejectsGarbage(t *testing.T) {
	t.Parallel()

	if _, err := UnmarshalDEK([]byte("not a keyset")); err == nil {
		t.Fatal("UnmarshalDEK accepted garbage input")
	}
}
