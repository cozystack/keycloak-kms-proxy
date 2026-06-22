package kms

import (
	"bytes"
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

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

// VaultKMS must satisfy the KMS interface.
var _ KMS = (*VaultKMS)(nil)
