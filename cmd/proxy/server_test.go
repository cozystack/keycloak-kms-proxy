package main

import (
	"context"
	"net"
	"testing"
	"time"

	"github.com/cozystack/keycloak-kms-proxy/internal/config"
)

func testProxyConfig() *config.ProxyConfig {
	return &config.ProxyConfig{
		ListenAddr:       "127.0.0.1:0",
		BackendAddr:      "127.0.0.1:5432",
		KEK:              make([]byte, 32),
		UpstreamUser:     "keycloak",
		UpstreamPassword: "kc-pw",
		BackendUser:      "proxy",
		BackendPassword:  "db-pw",
		Fields:           config.Default(),
	}
}

func TestBuildCipher(t *testing.T) {
	t.Parallel()

	cipher, err := buildCipher(context.Background(), testProxyConfig())
	if err != nil {
		t.Fatalf("buildCipher: %v", err)
	}
	stored, err := cipher.Encrypt(0, []byte("alice@example.com"), []byte("USER_ENTITY.EMAIL"))
	if err != nil {
		t.Fatalf("Encrypt: %v", err)
	}
	got, err := cipher.Decrypt(stored, []byte("USER_ENTITY.EMAIL"))
	if err != nil {
		t.Fatalf("Decrypt: %v", err)
	}
	if string(got) != "alice@example.com" {
		t.Fatalf("round-trip: got %q", got)
	}
}

func TestServerStartAcceptStop(t *testing.T) {
	t.Parallel()

	cipher, err := buildCipher(context.Background(), testProxyConfig())
	if err != nil {
		t.Fatalf("buildCipher: %v", err)
	}
	srv, err := newServer(testProxyConfig(), cipher)
	if err != nil {
		t.Fatalf("newServer: %v", err)
	}
	if err = srv.listen(); err != nil {
		t.Fatalf("listen: %v", err)
	}

	served := make(chan error, 1)
	go func() { served <- srv.serve() }()

	conn, err := net.DialTimeout("tcp", srv.addr(), 2*time.Second)
	if err != nil {
		t.Fatalf("dial: %v", err)
	}
	_ = conn.Close()

	if err = srv.close(); err != nil {
		t.Fatalf("close: %v", err)
	}
	select {
	case serveErr := <-served:
		if serveErr != nil {
			t.Fatalf("serve returned error: %v", serveErr)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("serve did not return after close")
	}
}

func TestNewServerDerivesVerifier(t *testing.T) {
	t.Parallel()

	cipher, _ := buildCipher(context.Background(), testProxyConfig())
	srv, err := newServer(testProxyConfig(), cipher)
	if err != nil {
		t.Fatalf("newServer: %v", err)
	}
	if _, ok := srv.upstreamVerifier("keycloak"); !ok {
		t.Error("verifier lookup failed for the configured upstream user")
	}
	if _, ok := srv.upstreamVerifier("someone-else"); ok {
		t.Error("verifier lookup accepted an unknown user")
	}
}
