package kms

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"sync"
	"time"
)

const (
	defaultTransitMount = "transit"
	defaultAppRoleMount = "approle"
	defaultVaultTimeout = 10 * time.Second
	// renewSkew re-authenticates this long before the cached token's TTL
	// expires, so an in-flight Wrap/Unwrap never races the expiry.
	renewSkew = 30 * time.Second
	// maxPostAttempts bounds Vault calls to one transparent re-auth: if the
	// first attempt hits 403 (an AppRole token expired since the last call),
	// the token is dropped and the request retried once with a fresh login.
	maxPostAttempts = 2
)

// VaultConfig configures a VaultKMS against a Vault Transit secrets engine.
// The KEK is the Transit key named KeyName. Exactly one authentication mode
// must be supplied: a static Token, or an AppRole (RoleID + SecretID).
type VaultConfig struct {
	Address    string // Vault base address, e.g. "https://vault:8200".
	Token      string // Static Vault token with encrypt/decrypt on the KEK.
	KeyName    string // Transit key name (the KEK).
	Mount      string // Transit mount path; defaults to "transit".
	HTTPClient *http.Client

	// AppRoleMount is the AppRole auth mount path; defaults to "approle".
	AppRoleMount string
	// RoleID/SecretID select AppRole authentication instead of a static
	// Token. When set, the KMS logs in against the AppRole mount and
	// re-authenticates on demand when the issued token expires.
	RoleID   string
	SecretID string
}

// VaultKMS wraps and unwraps the DEK using Vault Transit's encrypt/decrypt
// endpoints. KEK rotation is performed inside Vault; the "vault:vN:" version
// prefix in the ciphertext lets Vault decrypt values wrapped under older KEKs.
type VaultKMS struct {
	encryptURL string
	decryptURL string
	auth       *vaultAuth
	client     *http.Client
}

// NewVaultKMS builds a VaultKMS from cfg.
func NewVaultKMS(cfg VaultConfig) (*VaultKMS, error) {
	if cfg.Address == "" {
		return nil, errors.New("kms: vault address is required")
	}
	if cfg.KeyName == "" {
		return nil, errors.New("kms: vault transit key name is required")
	}

	client := cfg.HTTPClient
	if client == nil {
		client = &http.Client{Timeout: defaultVaultTimeout}
	}

	auth, err := newVaultAuth(cfg, client)
	if err != nil {
		return nil, err
	}

	mount := cfg.Mount
	if mount == "" {
		mount = defaultTransitMount
	}
	return &VaultKMS{
		encryptURL: fmt.Sprintf("%s/v1/%s/encrypt/%s", cfg.Address, mount, cfg.KeyName),
		decryptURL: fmt.Sprintf("%s/v1/%s/decrypt/%s", cfg.Address, mount, cfg.KeyName),
		auth:       auth,
		client:     client,
	}, nil
}

// Wrap encrypts the DEK; the result is Vault's "vault:vN:..." ciphertext token.
func (v *VaultKMS) Wrap(ctx context.Context, plaintextDEK []byte) ([]byte, error) {
	req := map[string]string{"plaintext": base64.StdEncoding.EncodeToString(plaintextDEK)}
	var resp struct {
		Data struct {
			Ciphertext string `json:"ciphertext"`
		} `json:"data"`
	}
	if err := v.post(ctx, v.encryptURL, req, &resp); err != nil {
		return nil, err
	}
	if resp.Data.Ciphertext == "" {
		return nil, errors.New("kms: vault returned an empty ciphertext")
	}
	return []byte(resp.Data.Ciphertext), nil
}

// Unwrap decrypts a Vault ciphertext token back to the plaintext DEK.
func (v *VaultKMS) Unwrap(ctx context.Context, wrappedDEK []byte) ([]byte, error) {
	req := map[string]string{"ciphertext": string(wrappedDEK)}
	var resp struct {
		Data struct {
			Plaintext string `json:"plaintext"`
		} `json:"data"`
	}
	if err := v.post(ctx, v.decryptURL, req, &resp); err != nil {
		return nil, err
	}
	plaintext, err := base64.StdEncoding.DecodeString(resp.Data.Plaintext)
	if err != nil {
		return nil, fmt.Errorf("kms: decode vault plaintext: %w", err)
	}
	return plaintext, nil
}

// post sends a Transit request, authenticating with the current token and
// re-authenticating once if Vault rejects the token with 403.
func (v *VaultKMS) post(ctx context.Context, url string, reqBody, respOut any) error {
	buf, err := json.Marshal(reqBody)
	if err != nil {
		return fmt.Errorf("kms: marshal request: %w", err)
	}
	for attempt := 1; ; attempt++ {
		token, terr := v.auth.currentToken(ctx)
		if terr != nil {
			return terr
		}
		status, body, derr := v.do(ctx, url, buf, token)
		if derr != nil {
			return derr
		}
		if status == http.StatusForbidden && attempt < maxPostAttempts && v.auth.reauth() {
			continue
		}
		if status < http.StatusOK || status >= http.StatusMultipleChoices {
			return fmt.Errorf("kms: vault returned status %d: %s", status, bytes.TrimSpace(body))
		}
		if err := json.Unmarshal(body, respOut); err != nil {
			return fmt.Errorf("kms: decode vault response: %w", err)
		}
		return nil
	}
}

// do performs a single authenticated POST and returns the status and body.
func (v *VaultKMS) do(ctx context.Context, url string, body []byte, token string) (int, []byte, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, url, bytes.NewReader(body))
	if err != nil {
		return 0, nil, fmt.Errorf("kms: build request: %w", err)
	}
	req.Header.Set("X-Vault-Token", token)
	req.Header.Set("Content-Type", "application/json")

	resp, err := v.client.Do(req)
	if err != nil {
		return 0, nil, fmt.Errorf("kms: vault request: %w", err)
	}
	defer func() { _ = resp.Body.Close() }()

	respBody, err := io.ReadAll(resp.Body)
	if err != nil {
		return 0, nil, fmt.Errorf("kms: read vault response: %w", err)
	}
	return resp.StatusCode, respBody, nil
}

// vaultAuth supplies the X-Vault-Token for Transit calls. It is either a fixed
// static token or an AppRole login that mints (and, on demand, re-mints) a
// short-lived token.
type vaultAuth struct {
	client   *http.Client
	static   string // set for static-token auth; empty for AppRole.
	loginURL string // set for AppRole auth.
	roleID   string
	secretID string

	mu     sync.Mutex
	token  string
	expiry time.Time // zero once logged in => the token does not expire.
}

// newVaultAuth builds the auth strategy from cfg, enforcing exactly one mode.
func newVaultAuth(cfg VaultConfig, client *http.Client) (*vaultAuth, error) {
	approle := cfg.RoleID != "" || cfg.SecretID != ""
	switch {
	case approle && cfg.Token != "":
		return nil, errors.New("kms: set either a static token or AppRole credentials, not both")
	case approle && (cfg.RoleID == "" || cfg.SecretID == ""):
		return nil, errors.New("kms: AppRole auth requires both a role id and a secret id")
	case !approle && cfg.Token == "":
		return nil, errors.New("kms: a vault token or AppRole credentials are required")
	}

	if !approle {
		return &vaultAuth{client: client, static: cfg.Token}, nil
	}
	mount := cfg.AppRoleMount
	if mount == "" {
		mount = defaultAppRoleMount
	}
	return &vaultAuth{
		client:   client,
		loginURL: fmt.Sprintf("%s/v1/auth/%s/login", cfg.Address, mount),
		roleID:   cfg.RoleID,
		secretID: cfg.SecretID,
	}, nil
}

// currentToken returns a currently valid Vault token, logging in via AppRole
// when the cached token is absent or within renewSkew of expiry.
func (a *vaultAuth) currentToken(ctx context.Context) (string, error) {
	if a.loginURL == "" {
		return a.static, nil
	}
	a.mu.Lock()
	defer a.mu.Unlock()
	if a.token != "" && (a.expiry.IsZero() || time.Until(a.expiry) > renewSkew) {
		return a.token, nil
	}
	if err := a.login(ctx); err != nil {
		return "", err
	}
	return a.token, nil
}

// reauth drops the cached AppRole token so the next token call logs in again.
// It reports whether re-authentication is possible (false for static tokens).
func (a *vaultAuth) reauth() bool {
	if a.loginURL == "" {
		return false
	}
	a.mu.Lock()
	a.token = ""
	a.mu.Unlock()
	return true
}

// login performs an AppRole login and caches the issued token and its TTL.
// The caller must hold a.mu.
func (a *vaultAuth) login(ctx context.Context) error {
	reqBody, err := json.Marshal(map[string]string{"role_id": a.roleID, "secret_id": a.secretID})
	if err != nil {
		return fmt.Errorf("kms: marshal approle login: %w", err)
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, a.loginURL, bytes.NewReader(reqBody))
	if err != nil {
		return fmt.Errorf("kms: build approle login: %w", err)
	}
	req.Header.Set("Content-Type", "application/json")

	resp, err := a.client.Do(req)
	if err != nil {
		return fmt.Errorf("kms: approle login request: %w", err)
	}
	defer func() { _ = resp.Body.Close() }()

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return fmt.Errorf("kms: read approle login response: %w", err)
	}
	if resp.StatusCode < http.StatusOK || resp.StatusCode >= http.StatusMultipleChoices {
		return fmt.Errorf("kms: approle login returned status %d: %s", resp.StatusCode, bytes.TrimSpace(body))
	}

	var lr struct {
		Auth struct {
			ClientToken   string `json:"client_token"`
			LeaseDuration int    `json:"lease_duration"`
		} `json:"auth"`
	}
	if err := json.Unmarshal(body, &lr); err != nil {
		return fmt.Errorf("kms: decode approle login response: %w", err)
	}
	if lr.Auth.ClientToken == "" {
		return errors.New("kms: approle login returned an empty client token")
	}

	a.token = lr.Auth.ClientToken
	if lr.Auth.LeaseDuration > 0 {
		a.expiry = time.Now().Add(time.Duration(lr.Auth.LeaseDuration) * time.Second)
	} else {
		a.expiry = time.Time{}
	}
	return nil
}
