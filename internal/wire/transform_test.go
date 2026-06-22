package wire

import (
	"bytes"
	"strings"
	"testing"

	"github.com/jackc/pgproto3/v2"

	"github.com/cozystack/keycloak-kms-proxy/internal/config"
	"github.com/cozystack/keycloak-kms-proxy/internal/rewrite"
)

func newEncryptingSession(t *testing.T) *Session {
	t.Helper()
	return NewSession(rewrite.NewPlanner(config.Default()), newTestCipher(t))
}

func TestEncryptBindEncryptsEmail(t *testing.T) {
	t.Parallel()

	s := newEncryptingSession(t)
	if err := s.OnParse(&pgproto3.Parse{Name: "ins", Query: "INSERT INTO user_entity (id, email) VALUES ($1, $2)"}); err != nil {
		t.Fatalf("OnParse: %v", err)
	}
	b := &pgproto3.Bind{
		PreparedStatement: "ins",
		Parameters:        [][]byte{[]byte("uuid-1"), []byte("Alice@Example.COM")},
	}
	if err := s.EncryptBind(b); err != nil {
		t.Fatalf("EncryptBind: %v", err)
	}

	if string(b.Parameters[0]) != "uuid-1" {
		t.Errorf("non-PII param mutated: %q", b.Parameters[0])
	}
	if !strings.HasPrefix(string(b.Parameters[1]), "$KKP$") {
		t.Fatalf("email param not encrypted: %q", b.Parameters[1])
	}
	// Decrypting recovers the lower-cased plaintext (deterministic normalization).
	got, err := s.cipher.Decrypt(string(b.Parameters[1]), rewrite.AAD("USER_ENTITY", "EMAIL"))
	if err != nil {
		t.Fatalf("Decrypt: %v", err)
	}
	if string(got) != "alice@example.com" {
		t.Fatalf("decrypted email = %q, want alice@example.com", got)
	}
}

func TestEncryptBindDeterministicSearchMatchesStored(t *testing.T) {
	t.Parallel()

	s := newEncryptingSession(t)
	_ = s.OnParse(&pgproto3.Parse{Name: "ins", Query: "INSERT INTO user_entity (email) VALUES ($1)"})
	_ = s.OnParse(&pgproto3.Parse{Name: "sel", Query: "SELECT id FROM user_entity WHERE email = $1"})

	ins := &pgproto3.Bind{PreparedStatement: "ins", Parameters: [][]byte{[]byte("Bob@Example.com")}}
	sel := &pgproto3.Bind{PreparedStatement: "sel", Parameters: [][]byte{[]byte("bob@example.COM")}}
	if err := s.EncryptBind(ins); err != nil {
		t.Fatalf("EncryptBind(ins): %v", err)
	}
	if err := s.EncryptBind(sel); err != nil {
		t.Fatalf("EncryptBind(sel): %v", err)
	}

	// Deterministic encryption + normalization: the stored value and the
	// search term encrypt identically, so equality search matches.
	if !bytes.Equal(ins.Parameters[0], sel.Parameters[0]) {
		t.Fatal("insert and search ciphertexts differ; deterministic search would not match")
	}
}

func TestDecryptDataRowRoundTrip(t *testing.T) {
	t.Parallel()

	s := newEncryptingSession(t)
	_ = s.OnParse(&pgproto3.Parse{Name: "sel", Query: "SELECT id, email FROM user_entity WHERE id = $1"})
	s.OnBind(&pgproto3.Bind{DestinationPortal: "p", PreparedStatement: "sel"})
	s.OnExecute(&pgproto3.Execute{Portal: "p"})
	s.OnRowDescription(&pgproto3.RowDescription{Fields: []pgproto3.FieldDescription{
		{Name: []byte("id")}, {Name: []byte("email")},
	}})

	// Produce a stored ciphertext for the email value as the backend would hold.
	stored, err := s.cipher.Encrypt(0 /*deterministic*/, []byte("carol@example.com"), rewrite.AAD("USER_ENTITY", "EMAIL"))
	if err != nil {
		t.Fatalf("Encrypt: %v", err)
	}
	dr := &pgproto3.DataRow{Values: [][]byte{[]byte("uuid-2"), []byte(stored)}}
	if err := s.DecryptDataRow(dr); err != nil {
		t.Fatalf("DecryptDataRow: %v", err)
	}
	if string(dr.Values[0]) != "uuid-2" {
		t.Errorf("non-PII field mutated: %q", dr.Values[0])
	}
	if string(dr.Values[1]) != "carol@example.com" {
		t.Fatalf("decrypted email = %q", dr.Values[1])
	}
}

func TestDecryptDataRowPassthroughPlaintext(t *testing.T) {
	t.Parallel()

	s := newEncryptingSession(t)
	_ = s.OnParse(&pgproto3.Parse{Name: "sel", Query: "SELECT email FROM user_entity WHERE id = $1"})
	s.OnBind(&pgproto3.Bind{DestinationPortal: "p", PreparedStatement: "sel"})
	s.OnExecute(&pgproto3.Execute{Portal: "p"})
	s.OnRowDescription(&pgproto3.RowDescription{Fields: []pgproto3.FieldDescription{{Name: []byte("email")}}})

	// A not-yet-migrated plaintext value (no marker) passes through unchanged.
	dr := &pgproto3.DataRow{Values: [][]byte{[]byte("legacy@plaintext.example")}}
	if err := s.DecryptDataRow(dr); err != nil {
		t.Fatalf("DecryptDataRow: %v", err)
	}
	if string(dr.Values[0]) != "legacy@plaintext.example" {
		t.Fatalf("plaintext not passed through: %q", dr.Values[0])
	}
}

func TestEncryptBindAttributeConditional(t *testing.T) {
	t.Parallel()

	s := newEncryptingSession(t)
	_ = s.OnParse(&pgproto3.Parse{Name: "attr", Query: "INSERT INTO user_attribute (name, value) VALUES ($1, $2)"})

	// A pii- attribute encrypts its value.
	pii := &pgproto3.Bind{PreparedStatement: "attr", Parameters: [][]byte{[]byte("pii-ssn"), []byte("123-45-6789")}}
	if err := s.EncryptBind(pii); err != nil {
		t.Fatalf("EncryptBind(pii): %v", err)
	}
	if !strings.HasPrefix(string(pii.Parameters[1]), "$KKP$") {
		t.Fatalf("pii- attribute value not encrypted: %q", pii.Parameters[1])
	}

	// A non-pii attribute leaves the value plaintext.
	plain := &pgproto3.Bind{PreparedStatement: "attr", Parameters: [][]byte{[]byte("phone"), []byte("555-1234")}}
	if err := s.EncryptBind(plain); err != nil {
		t.Fatalf("EncryptBind(plain): %v", err)
	}
	if string(plain.Parameters[1]) != "555-1234" {
		t.Fatalf("non-pii attribute value mutated: %q", plain.Parameters[1])
	}
}

func TestEncryptBindEscapesCollidingPlaintext(t *testing.T) {
	t.Parallel()

	s := newEncryptingSession(t)
	_ = s.OnParse(&pgproto3.Parse{Name: "attr", Query: "INSERT INTO user_attribute (name, value) VALUES ($1, $2)"})

	// A non-pii value that collides with the sentinel must be escaped so a
	// later read does not mistake it for ciphertext.
	collide := "$KKP$1.d.1.AAAA"
	b := &pgproto3.Bind{PreparedStatement: "attr", Parameters: [][]byte{[]byte("phone"), []byte(collide)}}
	if err := s.EncryptBind(b); err != nil {
		t.Fatalf("EncryptBind: %v", err)
	}
	if string(b.Parameters[1]) == collide {
		t.Fatal("colliding plaintext was not escaped")
	}
	// The read path recovers the original via the cipher's plaintext passthrough.
	got, err := s.cipher.Decrypt(string(b.Parameters[1]), rewrite.AAD("USER_ATTRIBUTE", "VALUE"))
	if err != nil {
		t.Fatalf("Decrypt: %v", err)
	}
	if string(got) != collide {
		t.Fatalf("escaped value did not round-trip: got %q", got)
	}
}

func TestEncryptBindLikeWithoutWildcards(t *testing.T) {
	t.Parallel()

	// LIKE on a deterministic PII column with a wildcard-free pattern is
	// rewritten to an effective equality search.
	s := newEncryptingSession(t)
	if err := s.OnParse(&pgproto3.Parse{Name: "sel", Query: "SELECT id FROM user_entity WHERE email LIKE $1"}); err != nil {
		t.Fatalf("OnParse: %v", err)
	}
	b := &pgproto3.Bind{PreparedStatement: "sel", Parameters: [][]byte{[]byte("Alice@Example.com")}}
	if err := s.EncryptBind(b); err != nil {
		t.Fatalf("EncryptBind: %v", err)
	}
	if !strings.HasPrefix(string(b.Parameters[0]), "$KKP$") {
		t.Fatalf("wildcard-free LIKE param not encrypted: %q", b.Parameters[0])
	}
	got, err := s.cipher.Decrypt(string(b.Parameters[0]), rewrite.AAD("USER_ENTITY", "EMAIL"))
	if err != nil || string(got) != "alice@example.com" {
		t.Fatalf("encrypted LIKE param decrypts to %q (err=%v), want alice@example.com", got, err)
	}
}

func TestEncryptBindLikeWithWildcardsPassthrough(t *testing.T) {
	t.Parallel()

	// A LIKE pattern carrying % or _ is forwarded unchanged; the search will
	// simply not match encrypted rows (same behavior as before).
	s := newEncryptingSession(t)
	_ = s.OnParse(&pgproto3.Parse{Name: "sel", Query: "SELECT id FROM user_entity WHERE email LIKE $1"})

	cases := []string{"%alice@example.com%", "alice_test", "%"}
	for _, p := range cases {
		b := &pgproto3.Bind{PreparedStatement: "sel", Parameters: [][]byte{[]byte(p)}}
		if err := s.EncryptBind(b); err != nil {
			t.Fatalf("EncryptBind(%q): %v", p, err)
		}
		if string(b.Parameters[0]) != p {
			t.Errorf("wildcard LIKE %q encrypted (got %q); should pass through", p, b.Parameters[0])
		}
	}
}

func TestEncryptBindLikeEscapedWildcardsTreatedLiteral(t *testing.T) {
	t.Parallel()

	// Backslash-escaped wildcards (\%, \_) are literal: the pattern still
	// has no live wildcards, so the proxy encrypts it.
	s := newEncryptingSession(t)
	_ = s.OnParse(&pgproto3.Parse{Name: "sel", Query: "SELECT id FROM user_entity WHERE email LIKE $1"})

	b := &pgproto3.Bind{PreparedStatement: "sel", Parameters: [][]byte{[]byte("alice\\%example.com")}}
	if err := s.EncryptBind(b); err != nil {
		t.Fatalf("EncryptBind: %v", err)
	}
	if !strings.HasPrefix(string(b.Parameters[0]), "$KKP$") {
		t.Fatalf("escaped-wildcard LIKE param not encrypted: %q", b.Parameters[0])
	}
}

func TestEncryptBindNullPassthrough(t *testing.T) {
	t.Parallel()

	s := newEncryptingSession(t)
	_ = s.OnParse(&pgproto3.Parse{Name: "ins", Query: "INSERT INTO user_entity (email) VALUES ($1)"})
	b := &pgproto3.Bind{PreparedStatement: "ins", Parameters: [][]byte{nil}}
	if err := s.EncryptBind(b); err != nil {
		t.Fatalf("EncryptBind: %v", err)
	}
	if b.Parameters[0] != nil {
		t.Fatalf("NULL parameter mutated: %q", b.Parameters[0])
	}
}
