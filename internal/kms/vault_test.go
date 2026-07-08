package kms

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/cozystack/keycloak-kms-proxy/internal/crypto"
)

const fakeVaultToken = "test-token"

// fakeVault is an in-memory stand-in for Vault Transit. Encrypt echoes the
// base64 plaintext into a "vault:v1:<plaintext>" token; decrypt reverses it.
func fakeVault(t *testing.T, key string) *httptest.Server {
	t.Helper()

	const prefix = "vault:v1:"
	mux := http.NewServeMux()
	mux.HandleFunc("/v1/transit/encrypt/"+key, func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("X-Vault-Token") != fakeVaultToken {
			http.Error(w, `{"errors":["permission denied"]}`, http.StatusForbidden)
			return
		}
		var req struct {
			Plaintext string `json:"plaintext"`
		}
		_ = json.NewDecoder(r.Body).Decode(&req)
		writeJSON(w, map[string]any{"data": map[string]string{"ciphertext": prefix + req.Plaintext}})
	})
	mux.HandleFunc("/v1/transit/decrypt/"+key, func(w http.ResponseWriter, r *http.Request) {
		var req struct {
			Ciphertext string `json:"ciphertext"`
		}
		_ = json.NewDecoder(r.Body).Decode(&req)
		if !strings.HasPrefix(req.Ciphertext, prefix) {
			http.Error(w, `{"errors":["invalid ciphertext"]}`, http.StatusBadRequest)
			return
		}
		writeJSON(w, map[string]any{"data": map[string]string{"plaintext": strings.TrimPrefix(req.Ciphertext, prefix)}})
	})
	srv := httptest.NewServer(mux)
	t.Cleanup(srv.Close)
	return srv
}

func writeJSON(w http.ResponseWriter, v any) {
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(v)
}

func newVault(t *testing.T) *VaultKMS {
	t.Helper()

	srv := fakeVault(t, "kms-proxy")
	v, err := NewVaultKMS(VaultConfig{
		Address:    srv.URL,
		Token:      fakeVaultToken,
		KeyName:    "kms-proxy",
		HTTPClient: srv.Client(),
	})
	if err != nil {
		t.Fatalf("NewVaultKMS: %v", err)
	}
	return v
}

func TestVaultKMSRoundTrip(t *testing.T) {
	t.Parallel()

	v := newVault(t)
	dek := []byte("serialized-dek-bytes")

	wrapped, err := v.Wrap(context.Background(), dek)
	if err != nil {
		t.Fatalf("Wrap: %v", err)
	}
	if !bytes.HasPrefix(wrapped, []byte("vault:")) {
		t.Fatalf("wrapped value %q is not a Vault ciphertext token", wrapped)
	}
	got, err := v.Unwrap(context.Background(), wrapped)
	if err != nil {
		t.Fatalf("Unwrap: %v", err)
	}
	if !bytes.Equal(got, dek) {
		t.Fatalf("round-trip mismatch: got %q, want %q", got, dek)
	}
}

func TestVaultKMSAuthError(t *testing.T) {
	t.Parallel()

	srv := fakeVault(t, "kms-proxy")
	v, err := NewVaultKMS(VaultConfig{
		Address:    srv.URL,
		Token:      "wrong-token",
		KeyName:    "kms-proxy",
		HTTPClient: srv.Client(),
	})
	if err != nil {
		t.Fatalf("NewVaultKMS: %v", err)
	}
	if _, err := v.Wrap(context.Background(), []byte("dek")); err == nil {
		t.Fatal("Wrap succeeded with a bad token")
	}
}

func TestVaultKMSConfigValidation(t *testing.T) {
	t.Parallel()

	cases := []VaultConfig{
		{Token: "t", KeyName: "k"},
		{Address: "http://v", KeyName: "k"},
		{Address: "http://v", Token: "t"},
	}
	for i, cfg := range cases {
		if _, err := NewVaultKMS(cfg); err == nil {
			t.Errorf("case %d: NewVaultKMS accepted an incomplete config", i)
		}
	}
}

func TestVaultKMSEnvelopeRoundTrip(t *testing.T) {
	t.Parallel()

	ctx := context.Background()
	v := newVault(t)

	// The envelope layer must work over Vault just like over the static KMS.
	set, err := GenerateDEKSet(ctx, v, 1)
	if err != nil {
		t.Fatalf("GenerateDEKSet: %v", err)
	}
	c, err := OpenCipher(ctx, v, set)
	if err != nil {
		t.Fatalf("OpenCipher: %v", err)
	}
	stored, err := c.Encrypt(crypto.SchemeNonDeterministic, []byte("alice@example.com"), nil)
	if err != nil {
		t.Fatalf("Encrypt: %v", err)
	}
	got, err := c.Decrypt(stored, nil)
	if err != nil {
		t.Fatalf("Decrypt: %v", err)
	}
	if string(got) != "alice@example.com" {
		t.Fatalf("round-trip: got %q", got)
	}
}

const (
	approleRoleID   = "role-abc"
	approleSecretID = "secret-xyz"
)

// fakeVaultAppRole is an in-memory Vault Transit stand-in that requires AppRole
// login. Tokens issued before acceptFromLogin are treated as already expired,
// so encrypt/decrypt reject them with 403 — this drives the re-auth path. The
// returned func reports how many logins happened.
func fakeVaultAppRole(t *testing.T, acceptFromLogin int) (*httptest.Server, func() int) {
	t.Helper()

	const (
		key    = "kms-proxy"
		prefix = "vault:v1:"
	)
	var mu sync.Mutex
	logins := 0
	valid := map[string]bool{}

	mux := http.NewServeMux()
	mux.HandleFunc("/v1/auth/approle/login", func(w http.ResponseWriter, r *http.Request) {
		var req struct {
			RoleID   string `json:"role_id"`
			SecretID string `json:"secret_id"`
		}
		_ = json.NewDecoder(r.Body).Decode(&req)
		if req.RoleID != approleRoleID || req.SecretID != approleSecretID {
			http.Error(w, `{"errors":["invalid role or secret id"]}`, http.StatusBadRequest)
			return
		}
		mu.Lock()
		logins++
		tok := fmt.Sprintf("approle-tok-%d", logins)
		if logins >= acceptFromLogin {
			valid[tok] = true
		}
		mu.Unlock()
		writeJSON(w, map[string]any{"auth": map[string]any{
			"client_token": tok, "lease_duration": 3600, "renewable": true,
		}})
	})
	authOK := func(w http.ResponseWriter, r *http.Request) bool {
		mu.Lock()
		ok := valid[r.Header.Get("X-Vault-Token")]
		mu.Unlock()
		if !ok {
			http.Error(w, `{"errors":["permission denied"]}`, http.StatusForbidden)
		}
		return ok
	}
	mux.HandleFunc("/v1/transit/encrypt/"+key, func(w http.ResponseWriter, r *http.Request) {
		if !authOK(w, r) {
			return
		}
		var req struct {
			Plaintext string `json:"plaintext"`
		}
		_ = json.NewDecoder(r.Body).Decode(&req)
		writeJSON(w, map[string]any{"data": map[string]string{"ciphertext": prefix + req.Plaintext}})
	})
	mux.HandleFunc("/v1/transit/decrypt/"+key, func(w http.ResponseWriter, r *http.Request) {
		if !authOK(w, r) {
			return
		}
		var req struct {
			Ciphertext string `json:"ciphertext"`
		}
		_ = json.NewDecoder(r.Body).Decode(&req)
		writeJSON(w, map[string]any{"data": map[string]string{"plaintext": strings.TrimPrefix(req.Ciphertext, prefix)}})
	})

	srv := httptest.NewServer(mux)
	t.Cleanup(srv.Close)
	return srv, func() int {
		mu.Lock()
		defer mu.Unlock()
		return logins
	}
}

func newAppRoleVault(t *testing.T, srv *httptest.Server) *VaultKMS {
	t.Helper()

	v, err := NewVaultKMS(VaultConfig{
		Address:    srv.URL,
		KeyName:    "kms-proxy",
		RoleID:     approleRoleID,
		SecretID:   approleSecretID,
		HTTPClient: srv.Client(),
	})
	if err != nil {
		t.Fatalf("NewVaultKMS: %v", err)
	}
	return v
}

func TestVaultKMSAppRoleRoundTrip(t *testing.T) {
	t.Parallel()

	srv, logins := fakeVaultAppRole(t, 1)
	v := newAppRoleVault(t, srv)

	wrapped, err := v.Wrap(context.Background(), []byte("dek"))
	if err != nil {
		t.Fatalf("Wrap: %v", err)
	}
	got, err := v.Unwrap(context.Background(), wrapped)
	if err != nil {
		t.Fatalf("Unwrap: %v", err)
	}
	if string(got) != "dek" {
		t.Fatalf("round-trip mismatch: %q", got)
	}
	if n := logins(); n != 1 {
		t.Fatalf("expected exactly one AppRole login (token cached), got %d", n)
	}
}

func TestVaultKMSAppRoleReauthOn403(t *testing.T) {
	t.Parallel()

	// The first issued token is treated as expired, so the first encrypt gets
	// 403; the KMS must drop it, log in again, and retry successfully.
	srv, logins := fakeVaultAppRole(t, 2)
	v := newAppRoleVault(t, srv)

	if _, err := v.Wrap(context.Background(), []byte("dek")); err != nil {
		t.Fatalf("Wrap should recover via re-auth: %v", err)
	}
	if n := logins(); n != 2 {
		t.Fatalf("expected a re-auth login, got %d logins", n)
	}
}

func TestVaultKMSAppRoleBadCredentials(t *testing.T) {
	t.Parallel()

	srv, _ := fakeVaultAppRole(t, 1)
	v, err := NewVaultKMS(VaultConfig{
		Address:    srv.URL,
		KeyName:    "kms-proxy",
		RoleID:     approleRoleID,
		SecretID:   "wrong-secret",
		HTTPClient: srv.Client(),
	})
	if err != nil {
		t.Fatalf("NewVaultKMS: %v", err)
	}
	if _, err := v.Wrap(context.Background(), []byte("dek")); err == nil {
		t.Fatal("Wrap succeeded with bad AppRole credentials")
	}
}

func TestVaultKMSAuthModeValidation(t *testing.T) {
	t.Parallel()

	cases := map[string]VaultConfig{
		"token and approle":         {Address: "http://v", KeyName: "k", Token: "t", RoleID: "r", SecretID: "s"},
		"approle missing secret":    {Address: "http://v", KeyName: "k", RoleID: "r"},
		"neither token nor approle": {Address: "http://v", KeyName: "k"},
	}
	for name, cfg := range cases {
		if _, err := NewVaultKMS(cfg); err == nil {
			t.Errorf("%s: NewVaultKMS accepted an invalid auth config", name)
		}
	}
}

func TestVaultAuthProactiveRenewFallback(t *testing.T) {
	t.Parallel()

	// A login endpoint that always fails, to simulate a transient Vault error
	// during a proactive re-login.
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		http.Error(w, `{"errors":["service unavailable"]}`, http.StatusServiceUnavailable)
	}))
	t.Cleanup(srv.Close)

	a := &vaultAuth{
		client:   srv.Client(),
		loginURL: srv.URL + "/v1/auth/approle/login",
		roleID:   "r",
		secretID: "s",
		token:    "still-valid",
		expiry:   time.Now().Add(renewSkew / 2), // inside renewSkew, but not expired.
	}
	got, err := a.currentToken(context.Background())
	if err != nil {
		t.Fatalf("currentToken should fall back to the still-valid cached token: %v", err)
	}
	if got != "still-valid" {
		t.Fatalf("got %q, want the cached token", got)
	}
}

func TestVaultAuthReauthNoStaleToken(t *testing.T) {
	t.Parallel()

	// After a hard 403 the token is cleared (reauth); a failing re-login must
	// surface the error rather than returning a stale token.
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		http.Error(w, `{"errors":["permission denied"]}`, http.StatusForbidden)
	}))
	t.Cleanup(srv.Close)

	a := &vaultAuth{
		client:   srv.Client(),
		loginURL: srv.URL + "/v1/auth/approle/login",
		roleID:   "r",
		secretID: "s",
	}
	if _, err := a.currentToken(context.Background()); err == nil {
		t.Fatal("currentToken should fail when login fails and no token is cached")
	}
}

func TestVaultKMSAppRoleConcurrent(t *testing.T) {
	t.Parallel()

	srv, logins := fakeVaultAppRole(t, 1)
	v := newAppRoleVault(t, srv)

	const n = 20
	var wg sync.WaitGroup
	errs := make(chan error, n)
	for range n {
		wg.Add(1)
		go func() {
			defer wg.Done()
			if _, err := v.Wrap(context.Background(), []byte("dek")); err != nil {
				errs <- err
			}
		}()
	}
	wg.Wait()
	close(errs)
	for err := range errs {
		t.Fatalf("concurrent Wrap: %v", err)
	}
	if got := logins(); got != 1 {
		t.Fatalf("concurrent cold-start Wraps must serialize to exactly one login, got %d", got)
	}
}

// VaultKMS must satisfy the KMS interface.
var _ KMS = (*VaultKMS)(nil)
