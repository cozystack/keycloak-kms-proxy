package wire

import (
	"bytes"
	"net"
	"testing"
	"time"

	"github.com/jackc/pgproto3/v2"

	"github.com/cozystack/keycloak-kms-proxy/internal/config"
	"github.com/cozystack/keycloak-kms-proxy/internal/crypto"
	"github.com/cozystack/keycloak-kms-proxy/internal/rewrite"
)

// relayHarness wires a mock Keycloak frontend and a mock CNPG backend to a
// running proxy Relay over two net.Pipe pairs, sharing one cipher so the test
// can both verify encrypted writes and craft ciphertext for decrypted reads.
type relayHarness struct {
	kc     *pgproto3.Frontend // mock Keycloak
	cnpg   *pgproto3.Backend  // mock CNPG
	cipher *crypto.Cipher
	close  func()
}

func newRelayHarness(t *testing.T) *relayHarness {
	t.Helper()

	cipher := newTestCipher(t)
	session := NewSession(rewrite.NewPlanner(config.Default()), cipher)

	kcConn, proxyKC := net.Pipe()
	proxyDB, dbConn := net.Pipe()

	backend := pgproto3.NewBackend(pgproto3.NewChunkReader(proxyKC), proxyKC)
	frontend := pgproto3.NewFrontend(pgproto3.NewChunkReader(proxyDB), proxyDB)
	go func() { _ = Relay(session, backend, frontend) }()

	h := &relayHarness{
		kc:     pgproto3.NewFrontend(pgproto3.NewChunkReader(kcConn), kcConn),
		cnpg:   pgproto3.NewBackend(pgproto3.NewChunkReader(dbConn), dbConn),
		cipher: cipher,
	}
	h.close = func() {
		_ = kcConn.Close()
		_ = proxyKC.Close()
		_ = proxyDB.Close()
		_ = dbConn.Close()
	}
	t.Cleanup(h.close)
	return h
}

func TestRelayEncryptsBindReachingBackend(t *testing.T) {
	t.Parallel()

	h := newRelayHarness(t)

	captured := make(chan []byte, 1)
	go func() {
		// Drain every forwarded message so the proxy never blocks; capture the
		// first Bind's last parameter (the email).
		for {
			msg, err := h.cnpg.Receive()
			if err != nil {
				return
			}
			if b, ok := msg.(*pgproto3.Bind); ok {
				select {
				case captured <- b.Parameters[len(b.Parameters)-1]:
				default:
				}
			}
		}
	}()

	mustSend(t, h.kc, &pgproto3.Parse{Name: "ins", Query: "INSERT INTO user_entity (id, email) VALUES ($1, $2)"})
	mustSend(t, h.kc, &pgproto3.Bind{PreparedStatement: "ins", Parameters: [][]byte{[]byte("uuid-1"), []byte("Alice@Example.com")}})
	mustSend(t, h.kc, &pgproto3.Execute{})
	mustSend(t, h.kc, &pgproto3.Sync{})

	select {
	case got := <-captured:
		if !bytes.HasPrefix(got, []byte("$KKP$")) {
			t.Fatalf("email reached backend unencrypted: %q", got)
		}
		pt, err := h.cipher.Decrypt(string(got), rewrite.AAD("USER_ENTITY", "EMAIL"))
		if err != nil {
			t.Fatalf("decrypt captured value: %v", err)
		}
		if string(pt) != "alice@example.com" {
			t.Fatalf("captured value decrypts to %q, want alice@example.com", pt)
		}
	case <-time.After(3 * time.Second):
		t.Fatal("backend never received the bind")
	}
}

func TestRelayDecryptsDataRowReachingClient(t *testing.T) {
	t.Parallel()

	h := newRelayHarness(t)

	// Pre-encrypt the value the backend will "return" for the email column.
	stored, err := h.cipher.Encrypt(crypto.SchemeDeterministic, []byte("carol@example.com"), rewrite.AAD("USER_ENTITY", "EMAIL"))
	if err != nil {
		t.Fatalf("Encrypt: %v", err)
	}

	go func() {
		for {
			msg, err := h.cnpg.Receive()
			if err != nil {
				return
			}
			if _, ok := msg.(*pgproto3.Sync); !ok {
				continue
			}
			_ = h.cnpg.Send(&pgproto3.RowDescription{Fields: []pgproto3.FieldDescription{
				{Name: []byte("id")}, {Name: []byte("email")},
			}})
			_ = h.cnpg.Send(&pgproto3.DataRow{Values: [][]byte{[]byte("uuid-1"), []byte(stored)}})
			_ = h.cnpg.Send(&pgproto3.CommandComplete{CommandTag: []byte("SELECT 1")})
			_ = h.cnpg.Send(&pgproto3.ReadyForQuery{TxStatus: 'I'})
			return
		}
	}()

	mustSend(t, h.kc, &pgproto3.Parse{Name: "sel", Query: "SELECT id, email FROM user_entity WHERE id = $1"})
	mustSend(t, h.kc, &pgproto3.Bind{PreparedStatement: "sel", Parameters: [][]byte{[]byte("uuid-1")}})
	mustSend(t, h.kc, &pgproto3.Execute{})
	mustSend(t, h.kc, &pgproto3.Sync{})

	row := awaitDataRow(t, h.kc)
	if string(row.Values[1]) != "carol@example.com" {
		t.Fatalf("client received email %q, want decrypted carol@example.com", row.Values[1])
	}
}

func TestRelayLikeWithoutWildcardsArrivesEncrypted(t *testing.T) {
	t.Parallel()

	// End-to-end: a LIKE filter with a wildcard-free value reaches the
	// backend as ciphertext, so equality against stored deterministic
	// ciphertext can match.
	h := newRelayHarness(t)

	captured := make(chan []byte, 1)
	go func() {
		for {
			msg, err := h.cnpg.Receive()
			if err != nil {
				return
			}
			if b, ok := msg.(*pgproto3.Bind); ok {
				select {
				case captured <- b.Parameters[len(b.Parameters)-1]:
				default:
				}
			}
		}
	}()

	mustSend(t, h.kc, &pgproto3.Parse{Name: "sel", Query: "SELECT id FROM user_entity WHERE email LIKE $1"})
	mustSend(t, h.kc, &pgproto3.Bind{PreparedStatement: "sel", Parameters: [][]byte{[]byte("Alice@Example.com")}})
	mustSend(t, h.kc, &pgproto3.Execute{})
	mustSend(t, h.kc, &pgproto3.Sync{})

	select {
	case got := <-captured:
		if !bytes.HasPrefix(got, []byte("$KKP$")) {
			t.Fatalf("LIKE param reached backend unencrypted: %q", got)
		}
		pt, err := h.cipher.Decrypt(string(got), rewrite.AAD("USER_ENTITY", "EMAIL"))
		if err != nil || string(pt) != "alice@example.com" {
			t.Fatalf("decrypt: %q (err=%v)", pt, err)
		}
	case <-time.After(3 * time.Second):
		t.Fatal("backend never received the LIKE bind")
	}
}

func mustSend(t *testing.T, fe *pgproto3.Frontend, msg pgproto3.FrontendMessage) {
	t.Helper()
	if err := fe.Send(msg); err != nil {
		t.Fatalf("send %T: %v", msg, err)
	}
}

func awaitDataRow(t *testing.T, fe *pgproto3.Frontend) *pgproto3.DataRow {
	t.Helper()

	done := make(chan *pgproto3.DataRow, 1)
	go func() {
		for {
			msg, err := fe.Receive()
			if err != nil {
				return
			}
			if dr, ok := msg.(*pgproto3.DataRow); ok {
				done <- dr
				return
			}
		}
	}()
	select {
	case dr := <-done:
		return dr
	case <-time.After(3 * time.Second):
		t.Fatal("client never received a DataRow")
		return nil
	}
}
