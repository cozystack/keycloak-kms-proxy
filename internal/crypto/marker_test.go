package crypto

import (
	"errors"
	"strings"
	"testing"
)

func TestEnvelopeRoundTrip(t *testing.T) {
	t.Parallel()

	cases := []struct {
		name string
		env  Envelope
	}{
		{
			name: "deterministic v1",
			env:  Envelope{Scheme: SchemeDeterministic, KeyVersion: 1, Ciphertext: []byte("siv-output")},
		},
		{
			name: "non-deterministic with embedded nonce",
			env:  Envelope{Scheme: SchemeNonDeterministic, KeyVersion: 7, Ciphertext: []byte{0x00, 0x01, 0xff, 0xfe, 0x10}},
		},
		{
			name: "empty ciphertext",
			env:  Envelope{Scheme: SchemeDeterministic, KeyVersion: 0, Ciphertext: nil},
		},
		{
			name: "high key version",
			env:  Envelope{Scheme: SchemeNonDeterministic, KeyVersion: 4294967295, Ciphertext: []byte("x")},
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			s, err := tc.env.Marshal()
			if err != nil {
				t.Fatalf("Marshal: %v", err)
			}
			if !strings.HasPrefix(s, sentinel) {
				t.Fatalf("marshaled value %q lacks sentinel %q", s, sentinel)
			}

			got, ok, err := Parse(s)
			if err != nil {
				t.Fatalf("Parse(%q): %v", s, err)
			}
			if !ok {
				t.Fatalf("Parse(%q): ok=false, want true", s)
			}
			if got.Scheme != tc.env.Scheme {
				t.Errorf("scheme: got %v, want %v", got.Scheme, tc.env.Scheme)
			}
			if got.KeyVersion != tc.env.KeyVersion {
				t.Errorf("key version: got %d, want %d", got.KeyVersion, tc.env.KeyVersion)
			}
			if string(got.Ciphertext) != string(tc.env.Ciphertext) {
				t.Errorf("ciphertext: got %x, want %x", got.Ciphertext, tc.env.Ciphertext)
			}
		})
	}
}

func TestParsePlaintextPassthrough(t *testing.T) {
	t.Parallel()

	// Values without the sentinel are plaintext (backfill coexistence):
	// Parse reports ok=false and no error so the proxy passes them through.
	plaintexts := []string{
		"",
		"alice",
		"alice@example.com",
		"$KKP",           // partial sentinel
		"prefix$KKP$mid", // sentinel not at start
		"$ not our marker",
	}
	for _, p := range plaintexts {
		_, ok, err := Parse(p)
		if err != nil {
			t.Errorf("Parse(%q): unexpected error %v", p, err)
		}
		if ok {
			t.Errorf("Parse(%q): ok=true, want false (plaintext)", p)
		}
	}
}

func TestSentinelCollisionEscaping(t *testing.T) {
	t.Parallel()

	// A legitimate plaintext that starts with the sentinel must survive an
	// escape/unescape round-trip and must NOT be mistaken for an envelope.
	collisions := []string{
		sentinel,
		sentinel + "1.d.1.AAAA", // looks exactly like a real envelope
		sentinel + "=already",   // looks like an escaped value
		sentinel + "anything",
	}
	for _, p := range collisions {
		esc := Escape(p)
		if !strings.HasPrefix(esc, sentinel) {
			t.Fatalf("Escape(%q)=%q lost sentinel", p, esc)
		}

		// An escaped value must not parse as a ciphertext envelope.
		if _, ok, err := Parse(esc); ok || err != nil {
			t.Errorf("Parse(escaped %q)=(ok=%v,err=%v), want (false,nil)", esc, ok, err)
		}

		if got := Unescape(esc); got != p {
			t.Errorf("Unescape(Escape(%q))=%q, want %q", p, got, p)
		}
	}
}

func TestEscapeNoopForNonColliding(t *testing.T) {
	t.Parallel()

	for _, p := range []string{"", "alice", "no marker here"} {
		if esc := Escape(p); esc != p {
			t.Errorf("Escape(%q)=%q, want unchanged", p, esc)
		}
		if got := Unescape(p); got != p {
			t.Errorf("Unescape(%q)=%q, want unchanged", p, got)
		}
	}
}

func TestParseMalformed(t *testing.T) {
	t.Parallel()

	cases := []struct {
		name   string
		stored string
		want   error
	}{
		{"bare sentinel", sentinel, ErrMalformedEnvelope},
		{"too few fields", sentinel + "1.d", ErrMalformedEnvelope},
		{"bad format version", sentinel + "9.d.1.AAAA", ErrUnsupportedFormat},
		{"non-numeric format", sentinel + "x.d.1.AAAA", ErrMalformedEnvelope},
		{"unknown scheme", sentinel + "1.z.1.AAAA", ErrUnknownScheme},
		{"bad key version", sentinel + "1.d.notanum.AAAA", ErrMalformedEnvelope},
		{"bad base64", sentinel + "1.d.1.!!!!", ErrMalformedEnvelope},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			_, ok, err := Parse(tc.stored)
			if ok {
				t.Fatalf("Parse(%q): ok=true, want false", tc.stored)
			}
			if !errors.Is(err, tc.want) {
				t.Fatalf("Parse(%q): err=%v, want %v", tc.stored, err, tc.want)
			}
		})
	}
}

func TestMarshalUnknownScheme(t *testing.T) {
	t.Parallel()

	e := Envelope{Scheme: Scheme(99), KeyVersion: 1}
	if _, err := e.Marshal(); !errors.Is(err, ErrUnknownScheme) {
		t.Fatalf("Marshal unknown scheme: err=%v, want %v", err, ErrUnknownScheme)
	}
}
