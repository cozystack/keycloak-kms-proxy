package wire

import (
	"net"
	"testing"
	"time"

	"github.com/jackc/pgproto3/v2"
)

// mockKeycloak drives the client side of the upstream handshake using the
// proxy's own SCRAM client as a stand-in for Keycloak's pgjdbc. It returns an
// error on any unexpected message (including the proxy's ErrorResponse on auth
// failure) rather than blocking.
func mockKeycloak(conn net.Conn, user, password string, params map[string]string) error {
	fe := pgproto3.NewFrontend(pgproto3.NewChunkReader(conn), conn)
	if err := fe.Send(&pgproto3.StartupMessage{ProtocolVersion: pgproto3.ProtocolVersionNumber, Parameters: params}); err != nil {
		return err
	}

	client := NewScramClient(user, password, nil)
	if _, err := expectBackend[*pgproto3.AuthenticationSASL](fe); err != nil {
		return err
	}
	clientFirst, err := client.ClientFirst()
	if err != nil {
		return err
	}
	if err = fe.Send(&pgproto3.SASLInitialResponse{AuthMechanism: scramMechanism, Data: clientFirst}); err != nil {
		return err
	}

	cont, err := expectBackend[*pgproto3.AuthenticationSASLContinue](fe)
	if err != nil {
		return err
	}
	clientFinal, err := client.ClientFinal(cont.Data)
	if err != nil {
		return err
	}
	if err = fe.Send(&pgproto3.SASLResponse{Data: clientFinal}); err != nil {
		return err
	}

	final, err := expectBackend[*pgproto3.AuthenticationSASLFinal](fe)
	if err != nil {
		return err
	}
	if err = client.VerifyServerFinal(final.Data); err != nil {
		return err
	}
	_, err = expectBackend[*pgproto3.AuthenticationOk](fe)
	return err
}

func TestAuthenticateUpstream(t *testing.T) {
	t.Parallel()

	clientConn, proxyConn := net.Pipe()
	t.Cleanup(func() { _ = clientConn.Close(); _ = proxyConn.Close() })

	salt := []byte("0123456789abcdef")
	verifier := MakeScramVerifier("kc-pw", salt, 4096)
	scram := NewScramServer(func(u string) (ScramVerifier, bool) { return verifier, u == "keycloak" }, nil)

	type result struct {
		params map[string]string
		err    error
	}
	done := make(chan result, 1)
	go func() {
		_, params, err := AuthenticateUpstream(proxyConn, scram)
		done <- result{params, err}
	}()

	clientErr := mockKeycloak(clientConn, "keycloak", "kc-pw", map[string]string{"user": "keycloak", "database": "kc"})
	if clientErr != nil {
		t.Fatalf("mock keycloak: %v", clientErr)
	}

	select {
	case res := <-done:
		if res.err != nil {
			t.Fatalf("AuthenticateUpstream: %v", res.err)
		}
		if res.params["user"] != "keycloak" || res.params["database"] != "kc" {
			t.Fatalf("startup params not returned: %+v", res.params)
		}
	case <-time.After(3 * time.Second):
		t.Fatal("AuthenticateUpstream did not complete")
	}
}

func TestAuthenticateUpstreamWrongPassword(t *testing.T) {
	t.Parallel()

	clientConn, proxyConn := net.Pipe()
	t.Cleanup(func() { _ = clientConn.Close(); _ = proxyConn.Close() })

	salt := []byte("0123456789abcdef")
	verifier := MakeScramVerifier("correct-pw", salt, 4096)
	scram := NewScramServer(func(string) (ScramVerifier, bool) { return verifier, true }, nil)

	done := make(chan error, 1)
	go func() {
		_, _, err := AuthenticateUpstream(proxyConn, scram)
		done <- err
	}()

	// The mock uses the wrong password; the proxy must reject the proof. The
	// client side fails when verifying the (absent) server-final.
	_ = mockKeycloak(clientConn, "keycloak", "wrong-pw", map[string]string{"user": "keycloak"})

	select {
	case err := <-done:
		if err == nil {
			t.Fatal("AuthenticateUpstream accepted a wrong password")
		}
	case <-time.After(3 * time.Second):
		t.Fatal("AuthenticateUpstream did not return")
	}
}

// TestAuthenticateDownstream runs the proxy's downstream client leg against a
// mock CNPG implemented by the upstream server leg, so the two legs validate
// each other over net.Pipe.
func TestAuthenticateDownstream(t *testing.T) {
	t.Parallel()

	proxyConn, cnpgConn := net.Pipe()
	t.Cleanup(func() { _ = proxyConn.Close(); _ = cnpgConn.Close() })

	salt := []byte("downstreamsalt!!")
	verifier := MakeScramVerifier("db-pw", salt, 4096)
	scramServer := NewScramServer(func(u string) (ScramVerifier, bool) { return verifier, u == "proxy" }, nil)

	srvDone := make(chan error, 1)
	go func() {
		_, _, err := AuthenticateUpstream(cnpgConn, scramServer)
		srvDone <- err
	}()

	client := NewScramClient("proxy", "db-pw", nil)
	fe, err := AuthenticateDownstream(proxyConn, map[string]string{"user": "proxy", "database": "kc"}, client)
	if err != nil {
		t.Fatalf("AuthenticateDownstream: %v", err)
	}
	if fe == nil {
		t.Fatal("nil frontend returned")
	}

	select {
	case err := <-srvDone:
		if err != nil {
			t.Fatalf("mock CNPG server: %v", err)
		}
	case <-time.After(3 * time.Second):
		t.Fatal("mock CNPG server did not complete")
	}
}

func TestAuthenticateDownstreamWrongPassword(t *testing.T) {
	t.Parallel()

	proxyConn, cnpgConn := net.Pipe()
	t.Cleanup(func() { _ = proxyConn.Close(); _ = cnpgConn.Close() })

	salt := []byte("downstreamsalt!!")
	verifier := MakeScramVerifier("correct-db-pw", salt, 4096)
	scramServer := NewScramServer(func(string) (ScramVerifier, bool) { return verifier, true }, nil)

	srvDone := make(chan error, 1)
	go func() {
		_, _, err := AuthenticateUpstream(cnpgConn, scramServer)
		srvDone <- err
	}()

	client := NewScramClient("proxy", "wrong-db-pw", nil)
	if _, err := AuthenticateDownstream(proxyConn, map[string]string{"user": "proxy"}, client); err == nil {
		t.Fatal("AuthenticateDownstream accepted a wrong password")
	}
	<-srvDone
}
