package wire

import (
	"encoding/base64"
	"testing"
)

func TestScramClientRFCVector(t *testing.T) {
	t.Parallel()

	c := NewScramClient("user", "pencil", nil)
	c.nonce = func() (string, error) { return "rOprNGfwEbeRWgbNEkqO", nil }

	clientFirst, err := c.ClientFirst()
	if err != nil {
		t.Fatalf("ClientFirst: %v", err)
	}
	if string(clientFirst) != rfcClientFirst {
		t.Fatalf("client-first:\n got %q\nwant %q", clientFirst, rfcClientFirst)
	}

	clientFinal, err := c.ClientFinal([]byte(rfcServerFirst))
	if err != nil {
		t.Fatalf("ClientFinal: %v", err)
	}
	if string(clientFinal) != rfcClientFinal {
		t.Fatalf("client-final:\n got %q\nwant %q", clientFinal, rfcClientFinal)
	}

	if err := c.VerifyServerFinal([]byte(rfcServerFinal)); err != nil {
		t.Fatalf("VerifyServerFinal: %v", err)
	}
}

func TestScramClientRejectsBadServerSignature(t *testing.T) {
	t.Parallel()

	c := NewScramClient("user", "pencil", nil)
	c.nonce = func() (string, error) { return "rOprNGfwEbeRWgbNEkqO", nil }
	_, _ = c.ClientFirst()
	_, _ = c.ClientFinal([]byte(rfcServerFirst))

	if err := c.VerifyServerFinal([]byte("v=AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=")); err == nil {
		t.Fatal("VerifyServerFinal accepted a wrong server signature")
	}
}

func TestScramClientRejectsBadServerNonce(t *testing.T) {
	t.Parallel()

	c := NewScramClient("user", "pencil", nil)
	c.nonce = func() (string, error) { return "clientnonce", nil }
	_, _ = c.ClientFirst()

	// Server-first whose nonce does not begin with the client nonce.
	bad := "r=different,s=" + base64.StdEncoding.EncodeToString([]byte("salt")) + ",i=4096"
	if _, err := c.ClientFinal([]byte(bad)); err == nil {
		t.Fatal("ClientFinal accepted a server nonce not extending the client nonce")
	}
}

// TestScramClientServerHandshake runs the proxy's two legs against each other
// end to end: the client (downstream) authenticates to the server (upstream),
// and the server authenticates back via the server signature.
func TestScramClientServerHandshake(t *testing.T) {
	t.Parallel()

	const password = "s3cr3t-db-pw"
	salt := []byte("0123456789abcdef")
	verifier := MakeScramVerifier(password, salt, 4096)

	server := NewScramServer(func(u string) (ScramVerifier, bool) { return verifier, u == "proxy" }, nil)
	client := NewScramClient("proxy", password, nil)

	clientFirst, err := client.ClientFirst()
	if err != nil {
		t.Fatalf("ClientFirst: %v", err)
	}
	serverFirst, err := server.ServerFirst(clientFirst)
	if err != nil {
		t.Fatalf("ServerFirst: %v", err)
	}
	clientFinal, err := client.ClientFinal(serverFirst)
	if err != nil {
		t.Fatalf("ClientFinal: %v", err)
	}
	serverFinal, err := server.ServerFinal(clientFinal)
	if err != nil {
		t.Fatalf("ServerFinal: %v", err)
	}
	if err := client.VerifyServerFinal(serverFinal); err != nil {
		t.Fatalf("VerifyServerFinal: %v", err)
	}
}

func TestScramClientServerHandshakeWrongPassword(t *testing.T) {
	t.Parallel()

	salt := []byte("0123456789abcdef")
	verifier := MakeScramVerifier("correct", salt, 4096)
	server := NewScramServer(func(string) (ScramVerifier, bool) { return verifier, true }, nil)
	client := NewScramClient("proxy", "wrong", nil)

	cf, _ := client.ClientFirst()
	sf, _ := server.ServerFirst(cf)
	clientFinal, _ := client.ClientFinal(sf)
	if _, err := server.ServerFinal(clientFinal); err == nil {
		t.Fatal("server accepted a client with the wrong password")
	}
}

// TestScramClientServerChannelBinding runs a full PLUS handshake where both
// legs share the same channel-binding data (the proxy's view of each cert).
func TestScramClientServerChannelBinding(t *testing.T) {
	t.Parallel()

	const password = "pw"
	salt := []byte("saltsaltsaltsalt")
	verifier := MakeScramVerifier(password, salt, 4096)
	cbind := []byte("server-cert-hash")

	server := NewScramServer(func(string) (ScramVerifier, bool) { return verifier, true }, cbind)
	client := NewScramClient("proxy", password, cbind)

	cf, err := client.ClientFirst()
	if err != nil {
		t.Fatalf("ClientFirst: %v", err)
	}
	sf, err := server.ServerFirst(cf)
	if err != nil {
		t.Fatalf("ServerFirst: %v", err)
	}
	clientFinal, err := client.ClientFinal(sf)
	if err != nil {
		t.Fatalf("ClientFinal: %v", err)
	}
	serverFinal, err := server.ServerFinal(clientFinal)
	if err != nil {
		t.Fatalf("ServerFinal: %v", err)
	}
	if err := client.VerifyServerFinal(serverFinal); err != nil {
		t.Fatalf("VerifyServerFinal: %v", err)
	}
}
