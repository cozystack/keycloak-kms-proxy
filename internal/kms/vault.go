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
	"time"
)

const (
	defaultTransitMount = "transit"
	defaultVaultTimeout = 10 * time.Second
)

// VaultConfig configures a VaultKMS against a Vault Transit secrets engine.
// The KEK is the Transit key named KeyName.
type VaultConfig struct {
	Address    string // Vault base address, e.g. "https://vault:8200".
	Token      string // Vault token with encrypt/decrypt on the Transit key.
	KeyName    string // Transit key name (the KEK).
	Mount      string // Transit mount path; defaults to "transit".
	HTTPClient *http.Client
}

// VaultKMS wraps and unwraps the DEK using Vault Transit's encrypt/decrypt
// endpoints. KEK rotation is performed inside Vault; the "vault:vN:" version
// prefix in the ciphertext lets Vault decrypt values wrapped under older KEKs.
type VaultKMS struct {
	encryptURL string
	decryptURL string
	token      string
	client     *http.Client
}

// NewVaultKMS builds a VaultKMS from cfg.
func NewVaultKMS(cfg VaultConfig) (*VaultKMS, error) {
	switch {
	case cfg.Address == "":
		return nil, errors.New("kms: vault address is required")
	case cfg.Token == "":
		return nil, errors.New("kms: vault token is required")
	case cfg.KeyName == "":
		return nil, errors.New("kms: vault transit key name is required")
	}

	mount := cfg.Mount
	if mount == "" {
		mount = defaultTransitMount
	}
	client := cfg.HTTPClient
	if client == nil {
		client = &http.Client{Timeout: defaultVaultTimeout}
	}

	return &VaultKMS{
		encryptURL: fmt.Sprintf("%s/v1/%s/encrypt/%s", cfg.Address, mount, cfg.KeyName),
		decryptURL: fmt.Sprintf("%s/v1/%s/decrypt/%s", cfg.Address, mount, cfg.KeyName),
		token:      cfg.Token,
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

func (v *VaultKMS) post(ctx context.Context, url string, reqBody, respOut any) error {
	buf, err := json.Marshal(reqBody)
	if err != nil {
		return fmt.Errorf("kms: marshal request: %w", err)
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, url, bytes.NewReader(buf))
	if err != nil {
		return fmt.Errorf("kms: build request: %w", err)
	}
	req.Header.Set("X-Vault-Token", v.token)
	req.Header.Set("Content-Type", "application/json")

	resp, err := v.client.Do(req)
	if err != nil {
		return fmt.Errorf("kms: vault request: %w", err)
	}
	defer func() { _ = resp.Body.Close() }()

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return fmt.Errorf("kms: read vault response: %w", err)
	}
	if resp.StatusCode < http.StatusOK || resp.StatusCode >= http.StatusMultipleChoices {
		return fmt.Errorf("kms: vault returned status %d: %s", resp.StatusCode, bytes.TrimSpace(body))
	}
	if err := json.Unmarshal(body, respOut); err != nil {
		return fmt.Errorf("kms: decode vault response: %w", err)
	}
	return nil
}
