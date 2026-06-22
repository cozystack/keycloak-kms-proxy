package wire

import (
	"encoding/base64"
	"testing"
)

// RFC 7677 §3 SCRAM-SHA-256 test vector (user "user", password "pencil").
const (
	rfcClientFirst = "n,,n=user,r=rOprNGfwEbeRWgbNEkqO"
	rfcServerNonce = "%hvYDpWUa2RaTCAfuxFIlj)hNlF$k0"
	rfcSaltB64     = "W22ZaJ0SNY7soEsUEjb6gQ=="
	rfcIterations  = 4096
	rfcServerFirst = "r=rOprNGfwEbeRWgbNEkqO%hvYDpWUa2RaTCAfuxFIlj)hNlF$k0,s=W22ZaJ0SNY7soEsUEjb6gQ==,i=4096"
	rfcClientFinal = "c=biws,r=rOprNGfwEbeRWgbNEkqO%hvYDpWUa2RaTCAfuxFIlj)hNlF$k0,p=dHzbZapWIk4jUhN+Ute9ytag9zjfMHgsqmmiz7AndVQ="
	rfcServerFinal = "v=6rriTRBi23WpRR/wtup+mMhUZUn/dB5nLTJRsjl95G4="
)

func rfcServer(t *testing.T) *ScramServer {
	t.Helper()

	salt, err := base64.StdEncoding.DecodeString(rfcSaltB64)
	if err != nil {
		t.Fatalf("decode salt: %v", err)
	}
	verifier := MakeScramVerifier("pencil", salt, rfcIterations)
	lookup := func(user string) (ScramVerifier, bool) {
		return verifier, user == "user"
	}
	s := NewScramServer(lookup, nil)
	s.nonce = func() (string, error) { return rfcServerNonce, nil }
	return s
}

func TestScramServerRFCVector(t *testing.T) {
	t.Parallel()

	s := rfcServer(t)

	serverFirst, err := s.ServerFirst([]byte(rfcClientFirst))
	if err != nil {
		t.Fatalf("ServerFirst: %v", err)
	}
	if string(serverFirst) != rfcServerFirst {
		t.Fatalf("server-first:\n got %q\nwant %q", serverFirst, rfcServerFirst)
	}

	serverFinal, err := s.ServerFinal([]byte(rfcClientFinal))
	if err != nil {
		t.Fatalf("ServerFinal: %v", err)
	}
	if string(serverFinal) != rfcServerFinal {
		t.Fatalf("server-final:\n got %q\nwant %q", serverFinal, rfcServerFinal)
	}
}

func TestScramServerRejectsWrongProof(t *testing.T) {
	t.Parallel()

	s := rfcServer(t)
	if _, err := s.ServerFirst([]byte(rfcClientFirst)); err != nil {
		t.Fatalf("ServerFirst: %v", err)
	}
	// Flip the last proof character to a different valid base64 char.
	tampered := rfcClientFinal[:len(rfcClientFinal)-2] + "A="
	if _, err := s.ServerFinal([]byte(tampered)); err == nil {
		t.Fatal("ServerFinal accepted a wrong proof")
	}
}

func TestScramServerSetUsernameOverridesScramN(t *testing.T) {
	t.Parallel()

	// PostgreSQL clients send "n=*" in SCRAM; verifier lookup must use the
	// authoritative username set out-of-band (from the StartupMessage).
	salt, _ := base64.StdEncoding.DecodeString(rfcSaltB64)
	verifier := MakeScramVerifier("pencil", salt, rfcIterations)
	lookups := map[string]bool{}
	s := NewScramServer(func(u string) (ScramVerifier, bool) {
		lookups[u] = true
		return verifier, u == "real-user"
	}, nil)
	s.nonce = func() (string, error) { return rfcServerNonce, nil }
	s.SetUsername("real-user")

	if _, err := s.ServerFirst([]byte("n,,n=*,r=rOprNGfwEbeRWgbNEkqO")); err != nil {
		t.Fatalf("ServerFirst with n=* failed despite SetUsername: %v", err)
	}
	if !lookups["real-user"] {
		t.Fatal("lookup did not see the authoritative username")
	}
	if lookups["*"] {
		t.Fatal("lookup was called with the SCRAM n=* placeholder")
	}
}

func TestScramServerUnknownUser(t *testing.T) {
	t.Parallel()

	s := rfcServer(t)
	if _, err := s.ServerFirst([]byte("n,,n=nobody,r=rOprNGfwEbeRWgbNEkqO")); err == nil {
		t.Fatal("ServerFirst accepted an unknown user")
	}
}

func TestScramServerChannelBindingPolicy(t *testing.T) {
	t.Parallel()

	// Server with no channel binding must reject a client requesting it ("p=").
	s := rfcServer(t)
	if _, err := s.ServerFirst([]byte("p=tls-server-end-point,,n=user,r=abc")); err == nil {
		t.Fatal("ServerFirst accepted channel binding when none configured")
	}

	// Server requiring channel binding must reject a client that omits it.
	salt, _ := base64.StdEncoding.DecodeString(rfcSaltB64)
	verifier := MakeScramVerifier("pencil", salt, rfcIterations)
	bound := NewScramServer(func(string) (ScramVerifier, bool) { return verifier, true }, []byte("cert-hash"))
	if _, err := bound.ServerFirst([]byte(rfcClientFirst)); err == nil {
		t.Fatal("ServerFirst accepted missing channel binding when required")
	}
}

func TestScramServerWithChannelBindingRoundTrip(t *testing.T) {
	t.Parallel()

	salt, _ := base64.StdEncoding.DecodeString(rfcSaltB64)
	verifier := MakeScramVerifier("pencil", salt, rfcIterations)
	cbind := []byte("proxy-cert-hash")
	s := NewScramServer(func(string) (ScramVerifier, bool) { return verifier, true }, cbind)
	s.nonce = func() (string, error) { return rfcServerNonce, nil }

	gs2 := "p=tls-server-end-point,,"
	if _, err := s.ServerFirst([]byte(gs2 + "n=user,r=rOprNGfwEbeRWgbNEkqO")); err != nil {
		t.Fatalf("ServerFirst: %v", err)
	}

	// A correct client computes c= as base64(gs2-header || cbind-data).
	cbindField := base64.StdEncoding.EncodeToString(append([]byte(gs2), cbind...))
	withoutProof := "c=" + cbindField + ",r=rOprNGfwEbeRWgbNEkqO" + rfcServerNonce
	proof := clientProofFor(t, verifier, s.clientFirstBare, s.serverFirst, withoutProof)
	clientFinal := withoutProof + ",p=" + base64.StdEncoding.EncodeToString(proof)

	if _, err := s.ServerFinal([]byte(clientFinal)); err != nil {
		t.Fatalf("ServerFinal with channel binding: %v", err)
	}
}

// clientProofFor recomputes a valid client proof, exercising the same key
// schedule the server verifies against.
func clientProofFor(t *testing.T, v ScramVerifier, clientFirstBare, serverFirst, withoutProof string) []byte {
	t.Helper()

	// ClientKey is derivable only from the password; recompute it here.
	salted := saltedPassword("pencil", v.Salt, v.Iterations)
	clientKey := scramHMAC(salted, []byte("Client Key"))
	storedKey := scramH(clientKey)
	authMessage := clientFirstBare + "," + serverFirst + "," + withoutProof
	clientSignature := scramHMAC(storedKey, []byte(authMessage))
	return xorBytes(clientKey, clientSignature)
}
