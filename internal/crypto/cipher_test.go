package crypto

import (
	"bytes"
	"errors"
	"strings"
	"testing"
)

func newTestCipher(t *testing.T, keyVersion uint32) *Cipher {
	t.Helper()

	dh, err := GenerateDEK(SchemeDeterministic)
	if err != nil {
		t.Fatalf("GenerateDEK(det): %v", err)
	}
	det, err := NewDeterministicAEAD(dh)
	if err != nil {
		t.Fatalf("NewDeterministicAEAD: %v", err)
	}
	nh, err := GenerateDEK(SchemeNonDeterministic)
	if err != nil {
		t.Fatalf("GenerateDEK(nondet): %v", err)
	}
	nondet, err := NewNonDeterministicAEAD(nh)
	if err != nil {
		t.Fatalf("NewNonDeterministicAEAD: %v", err)
	}
	c, err := NewCipher(keyVersion, nil, det, nondet)
	if err != nil {
		t.Fatalf("NewCipher: %v", err)
	}
	return c
}

func TestCipherRoundTrip(t *testing.T) {
	t.Parallel()

	c := newTestCipher(t, 1)
	aad := []byte("USER_ENTITY.EMAIL")

	for _, scheme := range []Scheme{SchemeDeterministic, SchemeNonDeterministic} {
		stored, err := c.Encrypt(scheme, []byte("alice@example.com"), aad)
		if err != nil {
			t.Fatalf("Encrypt(%v): %v", scheme, err)
		}
		if !strings.HasPrefix(stored, sentinel) {
			t.Fatalf("stored value %q lacks marker", stored)
		}
		pt, err := c.Decrypt(stored, aad)
		if err != nil {
			t.Fatalf("Decrypt(%v): %v", scheme, err)
		}
		if !bytes.Equal(pt, []byte("alice@example.com")) {
			t.Fatalf("round-trip(%v): got %q", scheme, pt)
		}
	}
}

func TestCipherDeterministicStableNonDeterministicFresh(t *testing.T) {
	t.Parallel()

	c := newTestCipher(t, 1)
	aad := []byte("col")

	d1, _ := c.Encrypt(SchemeDeterministic, []byte("v"), aad)
	d2, _ := c.Encrypt(SchemeDeterministic, []byte("v"), aad)
	if d1 != d2 {
		t.Errorf("deterministic stored values differ: %q vs %q", d1, d2)
	}

	n1, _ := c.Encrypt(SchemeNonDeterministic, []byte("v"), aad)
	n2, _ := c.Encrypt(SchemeNonDeterministic, []byte("v"), aad)
	if n1 == n2 {
		t.Error("non-deterministic stored values are identical")
	}
}

func TestCipherDecryptPlaintextPassthrough(t *testing.T) {
	t.Parallel()

	c := newTestCipher(t, 1)

	// No marker → not-yet-migrated plaintext, passed through untouched.
	for _, p := range []string{"", "alice", "alice@example.com"} {
		got, err := c.Decrypt(p, []byte("aad"))
		if err != nil {
			t.Fatalf("Decrypt(%q): %v", p, err)
		}
		if string(got) != p {
			t.Errorf("Decrypt(%q)=%q, want passthrough", p, got)
		}
	}

	// A plaintext that collides with the sentinel is escaped on write and must
	// come back as the original on read.
	collide := sentinel + "1.d.1.AAAA"
	if got, err := c.Decrypt(Escape(collide), []byte("aad")); err != nil || string(got) != collide {
		t.Fatalf("Decrypt(Escape(%q))=(%q,%v), want (%q,nil)", collide, got, err, collide)
	}
}

func TestCipherDecryptMalformed(t *testing.T) {
	t.Parallel()

	c := newTestCipher(t, 1)
	if _, err := c.Decrypt(sentinel+"1.d.notnum.AAAA", nil); !errors.Is(err, ErrMalformedEnvelope) {
		t.Fatalf("Decrypt malformed: err=%v, want ErrMalformedEnvelope", err)
	}
}

func TestCipherKeyVersionMismatch(t *testing.T) {
	t.Parallel()

	c1 := newTestCipher(t, 1)
	stored, err := c1.Encrypt(SchemeDeterministic, []byte("v"), nil)
	if err != nil {
		t.Fatalf("Encrypt: %v", err)
	}

	// A cipher pinned to a different key version must refuse the value so the
	// rotation layer can route it.
	c2 := newTestCipher(t, 2)
	if _, err := c2.Decrypt(stored, nil); !errors.Is(err, ErrKeyVersionMismatch) {
		t.Fatalf("Decrypt across versions: err=%v, want ErrKeyVersionMismatch", err)
	}
}

func TestCipherUnknownScheme(t *testing.T) {
	t.Parallel()

	// A cipher that only knows the non-deterministic scheme rejects requests
	// for the deterministic one.
	nh, _ := GenerateDEK(SchemeNonDeterministic)
	nondet, _ := NewNonDeterministicAEAD(nh)
	c, err := NewCipher(1, nil, nondet)
	if err != nil {
		t.Fatalf("NewCipher: %v", err)
	}
	if _, err := c.Encrypt(SchemeDeterministic, []byte("v"), nil); !errors.Is(err, ErrUnknownScheme) {
		t.Fatalf("Encrypt unknown scheme: err=%v, want ErrUnknownScheme", err)
	}
}

func TestNewCipherRejectsDuplicateAndNil(t *testing.T) {
	t.Parallel()

	nh, _ := GenerateDEK(SchemeNonDeterministic)
	n1, _ := NewNonDeterministicAEAD(nh)
	n2, _ := NewNonDeterministicAEAD(nh)
	if _, err := NewCipher(1, nil, n1, n2); err == nil {
		t.Error("NewCipher accepted duplicate scheme")
	}
	if _, err := NewCipher(1, nil, nil); err == nil {
		t.Error("NewCipher accepted nil primitive")
	}
}
