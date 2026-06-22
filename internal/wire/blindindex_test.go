package wire

import (
	"bytes"
	"encoding/hex"
	"net"
	"strings"
	"testing"
	"time"

	"github.com/jackc/pgproto3/v2"

	"github.com/cozystack/keycloak-kms-proxy/internal/config"
	"github.com/cozystack/keycloak-kms-proxy/internal/crypto"
	"github.com/cozystack/keycloak-kms-proxy/internal/rewrite"
)

// newBlindIndexCipher builds a Cipher with a blind-index key configured.
func newBlindIndexCipher(t *testing.T) *crypto.Cipher {
	t.Helper()

	dh, _ := crypto.GenerateDEK(crypto.SchemeDeterministic)
	det, _ := crypto.NewDeterministicAEAD(dh)
	nh, _ := crypto.GenerateDEK(crypto.SchemeNonDeterministic)
	nondet, _ := crypto.NewNonDeterministicAEAD(nh)
	key, err := crypto.GenerateBlindIndexKey()
	if err != nil {
		t.Fatalf("GenerateBlindIndexKey: %v", err)
	}
	c, err := crypto.NewCipher(1, crypto.NewBlindIndex(key), det, nondet)
	if err != nil {
		t.Fatalf("NewCipher: %v", err)
	}
	return c
}

func newBlindIndexSession(t *testing.T) (*Session, *crypto.Cipher) {
	t.Helper()

	fs := config.New()
	fs.SetColumn(config.TableUserEntity, "EMAIL", config.Rule{
		Scheme: crypto.SchemeDeterministic, LowercaseNormalize: true, BlindIndex: "EMAIL_HASH",
	})
	c := newBlindIndexCipher(t)
	return NewSession(rewrite.NewPlanner(fs), c), c
}

func TestOnParseRewritesBlindIndexLike(t *testing.T) {
	t.Parallel()

	s, _ := newBlindIndexSession(t)
	p := &pgproto3.Parse{Name: "search", Query: "SELECT id FROM user_entity WHERE email LIKE $1"}
	if err := s.OnParse(p); err != nil {
		t.Fatalf("OnParse: %v", err)
	}
	want := "SELECT id FROM user_entity WHERE email_hash = $1"
	if p.Query != want {
		t.Fatalf("Parse.Query:\n got %q\nwant %q", p.Query, want)
	}
}

func TestEncryptBindReplacesLikeValueWithHMAC(t *testing.T) {
	t.Parallel()

	s, c := newBlindIndexSession(t)
	if err := s.OnParse(&pgproto3.Parse{Name: "search", Query: "SELECT id FROM user_entity WHERE LOWER(email) LIKE $1"}); err != nil {
		t.Fatalf("OnParse: %v", err)
	}

	// Admin UI wraps user input in %term%; the proxy must strip and hash.
	b := &pgproto3.Bind{PreparedStatement: "search", Parameters: [][]byte{[]byte("%Alice@Example.com%")}}
	if err := s.EncryptBind(b); err != nil {
		t.Fatalf("EncryptBind: %v", err)
	}

	wantHash, err := c.BlindIndex().Compute([]byte("alice@example.com"), rewrite.AAD("USER_ENTITY", "EMAIL"))
	if err != nil {
		t.Fatalf("Compute: %v", err)
	}
	if string(b.Parameters[0]) != wantHash {
		t.Fatalf("bound value:\n got %q\nwant HMAC %q", b.Parameters[0], wantHash)
	}
	if _, err := hex.DecodeString(string(b.Parameters[0])); err != nil {
		t.Errorf("hash is not hex: %v", err)
	}
}

func TestEncryptBindBlindIndexInternalWildcardPassthrough(t *testing.T) {
	t.Parallel()

	// A pattern with a wildcard *inside* the term (after stripping outer `%`)
	// degrades to passthrough — no hash is computed and the query simply
	// returns no rows.
	s, _ := newBlindIndexSession(t)
	_ = s.OnParse(&pgproto3.Parse{Name: "search", Query: "SELECT id FROM user_entity WHERE email LIKE $1"})

	b := &pgproto3.Bind{PreparedStatement: "search", Parameters: [][]byte{[]byte("%al_ce%")}}
	if err := s.EncryptBind(b); err != nil {
		t.Fatalf("EncryptBind: %v", err)
	}
	if string(b.Parameters[0]) != "%al_ce%" {
		t.Fatalf("internal wildcard should pass through: %q", b.Parameters[0])
	}
}

func TestEncryptBindBlindIndexExactNoWildcards(t *testing.T) {
	t.Parallel()

	s, c := newBlindIndexSession(t)
	_ = s.OnParse(&pgproto3.Parse{Name: "search", Query: "SELECT id FROM user_entity WHERE email LIKE $1"})
	b := &pgproto3.Bind{PreparedStatement: "search", Parameters: [][]byte{[]byte("ALICE@EXAMPLE.COM")}}
	if err := s.EncryptBind(b); err != nil {
		t.Fatalf("EncryptBind: %v", err)
	}
	want, _ := c.BlindIndex().Compute([]byte("alice@example.com"), rewrite.AAD("USER_ENTITY", "EMAIL"))
	if string(b.Parameters[0]) != want {
		t.Fatalf("exact bind: got %q want %q", b.Parameters[0], want)
	}
}

func TestOnParseRewritesBlindIndexInsert(t *testing.T) {
	t.Parallel()

	s, _ := newBlindIndexSession(t)
	p := &pgproto3.Parse{Name: "ins", Query: "INSERT INTO user_entity (id, email) VALUES ($1, $2)"}
	if err := s.OnParse(p); err != nil {
		t.Fatalf("OnParse: %v", err)
	}
	want := "INSERT INTO user_entity (id, email, email_hash) VALUES ($1, $2, $3)"
	if p.Query != want {
		t.Fatalf("Parse.Query:\n got %q\nwant %q", p.Query, want)
	}
}

func TestEncryptBindAppendsBlindIndexHash(t *testing.T) {
	t.Parallel()

	s, c := newBlindIndexSession(t)
	_ = s.OnParse(&pgproto3.Parse{Name: "ins", Query: "INSERT INTO user_entity (id, email) VALUES ($1, $2)"})

	b := &pgproto3.Bind{PreparedStatement: "ins", Parameters: [][]byte{[]byte("uuid-1"), []byte("Alice@Example.com")}}
	if err := s.EncryptBind(b); err != nil {
		t.Fatalf("EncryptBind: %v", err)
	}
	if len(b.Parameters) != 3 {
		t.Fatalf("expected 3 parameters after blind-index append, got %d: %+v", len(b.Parameters), b.Parameters)
	}
	if !strings.HasPrefix(string(b.Parameters[1]), "$KKP$") {
		t.Errorf("source email param not encrypted: %q", b.Parameters[1])
	}
	wantHash, _ := c.BlindIndex().Compute([]byte("alice@example.com"), rewrite.AAD("USER_ENTITY", "EMAIL"))
	if string(b.Parameters[2]) != wantHash {
		t.Errorf("appended hash:\n got %q\nwant %q", b.Parameters[2], wantHash)
	}
}

// TestRelayBlindIndexEndToEnd verifies the wire net.Pipe pump runs the full
// flow: Parse mutates the SQL, Bind carries the HMAC, and the backend
// receives the hash-column equality with the hashed parameter.
func TestRelayBlindIndexEndToEnd(t *testing.T) {
	t.Parallel()

	fs := config.New()
	fs.SetColumn(config.TableUserEntity, "EMAIL", config.Rule{
		Scheme: crypto.SchemeDeterministic, LowercaseNormalize: true, BlindIndex: "EMAIL_HASH",
	})
	cipher := newBlindIndexCipher(t)
	session := NewSession(rewrite.NewPlanner(fs), cipher)

	kcConn, proxyKC := net.Pipe()
	proxyDB, dbConn := net.Pipe()
	t.Cleanup(func() {
		_ = kcConn.Close()
		_ = proxyKC.Close()
		_ = proxyDB.Close()
		_ = dbConn.Close()
	})
	backend := pgproto3.NewBackend(pgproto3.NewChunkReader(proxyKC), proxyKC)
	frontend := pgproto3.NewFrontend(pgproto3.NewChunkReader(proxyDB), proxyDB)
	go func() { _ = Relay(session, backend, frontend) }()

	cnpg := pgproto3.NewBackend(pgproto3.NewChunkReader(dbConn), dbConn)
	type capture struct {
		query string
		param []byte
	}
	captured := make(chan capture, 1)
	go func() {
		var q string
		for {
			msg, err := cnpg.Receive()
			if err != nil {
				return
			}
			switch m := msg.(type) {
			case *pgproto3.Parse:
				q = m.Query
			case *pgproto3.Bind:
				select {
				case captured <- capture{query: q, param: append([]byte(nil), m.Parameters[0]...)}:
				default:
				}
			}
		}
	}()

	kc := pgproto3.NewFrontend(pgproto3.NewChunkReader(kcConn), kcConn)
	mustSend(t, kc, &pgproto3.Parse{Name: "s", Query: "SELECT id FROM user_entity WHERE LOWER(email) LIKE $1"})
	mustSend(t, kc, &pgproto3.Bind{PreparedStatement: "s", Parameters: [][]byte{[]byte("%alice@example.com%")}})
	mustSend(t, kc, &pgproto3.Execute{})
	mustSend(t, kc, &pgproto3.Sync{})

	select {
	case got := <-captured:
		if !strings.Contains(got.query, "email_hash = $1") {
			t.Errorf("backend Parse.Query was not rewritten: %q", got.query)
		}
		wantHash, _ := cipher.BlindIndex().Compute([]byte("alice@example.com"), rewrite.AAD("USER_ENTITY", "EMAIL"))
		if !bytes.Equal(got.param, []byte(wantHash)) {
			t.Errorf("bound value:\n got %q\nwant %q", got.param, wantHash)
		}
	case <-time.After(3 * time.Second):
		t.Fatal("backend never received a Bind")
	}
}
