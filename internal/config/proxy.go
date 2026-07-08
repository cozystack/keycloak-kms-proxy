package config

import (
	"encoding/base64"
	"errors"
	"fmt"
	"os"
	"strconv"
	"time"

	"github.com/cozystack/keycloak-kms-proxy/internal/crypto"
)

// kekBytes is the required KEK length for the static KMS (AES-256).
const kekBytes = 32

// ProxyConfig is the runtime configuration of the proxy server. The encrypted
// field set defaults to the built-in MLukman-compatible set and can be
// replaced.
type ProxyConfig struct {
	// ListenAddr is where the proxy accepts Keycloak connections.
	ListenAddr string
	// BackendAddr is the CNPG read-write address the proxy forwards to.
	BackendAddr string
	// KEK is the 32-byte key-encryption key for the static KMS. Vault
	// Transit configuration will be added alongside this later.
	KEK []byte
	// UpstreamUser/UpstreamPassword is the credential the proxy expects from
	// Keycloak; the proxy verifies it as the SCRAM server.
	UpstreamUser     string
	UpstreamPassword string
	// BackendUser/BackendPassword is the credential the proxy uses to
	// authenticate to CNPG as the SCRAM client.
	BackendUser     string
	BackendPassword string
	// Fields is the encrypted field set.
	Fields *FieldSet
	// Lenient downgrades the rewrite fail-loud rules to passthrough, so
	// historical Liquibase data-migration UPDATEs (CONCAT expressions writing
	// PII columns) can run during the Keycloak bootstrap window. Must be
	// turned off in steady state.
	Lenient bool
	// DEKSetFile is the path to a JSON-encoded kms.DEKSet (wrapped DEKs). When
	// set, the proxy loads it at startup instead of minting an ephemeral one;
	// this is what lets the proxy and the backfill tool share a key.
	DEKSetFile string
	// VaultAddr/VaultToken/VaultKeyName/VaultMount select a Vault Transit KMS
	// instead of the static KEK. KEK is left empty when these
	// are set. KEK rotation happens inside Vault; the version-tagged wrapped
	// DEK keeps the proxy working across rotations transparently.
	VaultAddr    string
	VaultToken   string
	VaultKeyName string
	VaultMount   string
	// VaultRoleID/VaultSecretID select AppRole authentication against the
	// Vault Transit KMS instead of a static VaultToken. When set, the proxy
	// logs in via AppRole and re-authenticates on demand as the token expires.
	// VaultAppRoleMount is the AppRole auth mount path; defaults to "approle".
	VaultAppRoleMount string
	VaultRoleID       string
	VaultSecretID     string
	// VaultKubernetesRole selects Vault Kubernetes authentication (preferred in
	// production): the proxy logs in with its projected ServiceAccount token,
	// which the kubelet rotates, so no long-lived credential is stored.
	// VaultKubernetesMount defaults to "kubernetes"; VaultKubernetesJWTFile
	// defaults to the standard in-pod ServiceAccount token path.
	VaultKubernetesRole    string
	VaultKubernetesMount   string
	VaultKubernetesJWTFile string
	// TLSCertFile/TLSKeyFile, when both set, make the proxy terminate TLS on
	// the Keycloak-facing listener. Both must be set or both
	// must be empty.
	TLSCertFile string
	TLSKeyFile  string
	// MetricsAddr, when set (e.g. ":9090"), starts a Prometheus /metrics
	// endpoint on that address.
	MetricsAddr string
	// HealthAddr, when set (e.g. ":8081"), starts an HTTP server exposing
	// /healthz (liveness) and /readyz (readiness — backend TCP-reachable +
	// not draining).
	HealthAddr string
	// BackendCAFile, when set, makes the proxy negotiate PG-level SSLRequest
	// against the backend and TLS-upgrade the downstream leg with this CA
	// validating the backend's server cert. When empty
	// the downstream leg stays plaintext (the original behaviour).
	BackendCAFile string
	// BackendServerName overrides the SNI / cert name validated on the
	// downstream TLS leg. Defaults to the host portion of BackendAddr.
	BackendServerName string
	// MaxConnections caps the number of concurrent in-flight relays.
	// 0 = unlimited. Recommended in production
	// to bound resource use and force backpressure to the kernel queue.
	MaxConnections int
	// HandshakeTimeout bounds the upstream-side handshake (SSLRequest +
	// SCRAM) per connection (slow-loris protection).
	// 0 = no deadline. The proxy clears the deadline after AuthOK.
	HandshakeTimeout time.Duration
}

// Environment variables consulted by LoadProxyConfig.
const (
	envListenAddr        = "KKP_LISTEN_ADDR"
	envBackendAddr       = "KKP_BACKEND_ADDR"
	envKEK               = "KKP_KEK"
	envUpstreamUser      = "KKP_UPSTREAM_USER"
	envUpstreamPassword  = "KKP_UPSTREAM_PASSWORD" //nolint:gosec // env var name, not a credential
	envBackendUser       = "KKP_BACKEND_USER"
	envBackendPassword   = "KKP_BACKEND_PASSWORD" //nolint:gosec // env var name, not a credential
	envFields            = "KKP_FIELDS"
	envLenient           = "KKP_LENIENT"
	envDEKSetFile        = "KKP_DEKSET_FILE"
	envVaultAddr         = "KKP_VAULT_ADDR"
	envVaultToken        = "KKP_VAULT_TOKEN" //nolint:gosec // env var name, not a credential
	envVaultKeyName      = "KKP_VAULT_KEY_NAME"
	envVaultMount        = "KKP_VAULT_MOUNT"
	envVaultAppRoleMount = "KKP_VAULT_APPROLE_MOUNT"
	envVaultRoleID       = "KKP_VAULT_ROLE_ID"
	envVaultSecretID     = "KKP_VAULT_SECRET_ID" //nolint:gosec // env var name, not a credential
	envVaultK8sRole      = "KKP_VAULT_KUBERNETES_ROLE"
	envVaultK8sMount     = "KKP_VAULT_KUBERNETES_MOUNT"
	envVaultK8sJWTFile   = "KKP_VAULT_KUBERNETES_JWT_FILE" //nolint:gosec // env var name, not a credential
	envTLSCertFile       = "KKP_TLS_CERT_FILE"
	envTLSKeyFile        = "KKP_TLS_KEY_FILE"
	envMetricsAddr       = "KKP_METRICS_ADDR"
	envHealthAddr        = "KKP_HEALTH_ADDR"
	envBackendCAFile     = "KKP_BACKEND_CA_FILE"
	envBackendServerName = "KKP_BACKEND_SERVER_NAME"
	envMaxConnections    = "KKP_MAX_CONNECTIONS"
	envHandshakeTimeout  = "KKP_HANDSHAKE_TIMEOUT"
)

// KKP_FIELDS values.
const (
	// FieldsDisabled selects an empty field set so the proxy operates in pure
	// passthrough mode (no encryption).
	FieldsDisabled = "disabled"
	// FieldsEmailOnly enables deterministic encryption of USER_ENTITY.EMAIL
	// (with lower-case normalization) and nothing else.
	FieldsEmailOnly = "email-only"
	// FieldsEmailOnlyBlindIndex is FieldsEmailOnly plus the EMAIL_HASH shadow
	// column populated with HMAC so admin LIKE searches on email work.
	FieldsEmailOnlyBlindIndex = "email-only-blind-index"
)

// LoadProxyConfig builds a ProxyConfig from environment variables and the
// default field set. KKP_KEK is base64-standard-encoded. The result is
// validated before return.
func LoadProxyConfig() (*ProxyConfig, error) {
	kekB64 := os.Getenv(envKEK)
	var kek []byte
	if kekB64 != "" {
		decoded, err := base64.StdEncoding.DecodeString(kekB64)
		if err != nil {
			return nil, fmt.Errorf("config: %s is not valid base64: %w", envKEK, err)
		}
		kek = decoded
	}

	fields, err := selectFields(os.Getenv(envFields))
	if err != nil {
		return nil, err
	}
	cfg := &ProxyConfig{
		ListenAddr:             os.Getenv(envListenAddr),
		BackendAddr:            os.Getenv(envBackendAddr),
		KEK:                    kek,
		UpstreamUser:           os.Getenv(envUpstreamUser),
		UpstreamPassword:       os.Getenv(envUpstreamPassword),
		BackendUser:            os.Getenv(envBackendUser),
		BackendPassword:        os.Getenv(envBackendPassword),
		Fields:                 fields,
		Lenient:                os.Getenv(envLenient) == "true",
		DEKSetFile:             os.Getenv(envDEKSetFile),
		VaultAddr:              os.Getenv(envVaultAddr),
		VaultToken:             os.Getenv(envVaultToken),
		VaultKeyName:           os.Getenv(envVaultKeyName),
		VaultMount:             os.Getenv(envVaultMount),
		VaultAppRoleMount:      os.Getenv(envVaultAppRoleMount),
		VaultRoleID:            os.Getenv(envVaultRoleID),
		VaultSecretID:          os.Getenv(envVaultSecretID),
		VaultKubernetesRole:    os.Getenv(envVaultK8sRole),
		VaultKubernetesMount:   os.Getenv(envVaultK8sMount),
		VaultKubernetesJWTFile: os.Getenv(envVaultK8sJWTFile),
		TLSCertFile:            os.Getenv(envTLSCertFile),
		TLSKeyFile:             os.Getenv(envTLSKeyFile),
		MetricsAddr:            os.Getenv(envMetricsAddr),
		HealthAddr:             os.Getenv(envHealthAddr),
		BackendCAFile:          os.Getenv(envBackendCAFile),
		BackendServerName:      os.Getenv(envBackendServerName),
	}
	if v := os.Getenv(envMaxConnections); v != "" {
		n, perr := strconv.Atoi(v)
		if perr != nil || n < 0 {
			return nil, fmt.Errorf("config: %s must be a non-negative integer, got %q", envMaxConnections, v)
		}
		cfg.MaxConnections = n
	}
	if v := os.Getenv(envHandshakeTimeout); v != "" {
		d, perr := time.ParseDuration(v)
		if perr != nil || d < 0 {
			return nil, fmt.Errorf("config: %s must be a Go duration (e.g. 10s), got %q", envHandshakeTimeout, v)
		}
		cfg.HandshakeTimeout = d
	}
	if err := cfg.Validate(); err != nil {
		return nil, err
	}
	return cfg, nil
}

// Validate checks that all required fields are present and well-formed.
func (c *ProxyConfig) Validate() error {
	var missing []string
	for _, f := range []struct {
		name, value string
	}{
		{envListenAddr, c.ListenAddr},
		{envBackendAddr, c.BackendAddr},
		{envUpstreamUser, c.UpstreamUser},
		{envUpstreamPassword, c.UpstreamPassword},
		{envBackendUser, c.BackendUser},
		{envBackendPassword, c.BackendPassword},
	} {
		if f.value == "" {
			missing = append(missing, f.name)
		}
	}
	if len(missing) > 0 {
		return fmt.Errorf("config: missing required settings: %v", missing)
	}
	if err := c.validateKMS(); err != nil {
		return err
	}
	if (c.TLSCertFile == "") != (c.TLSKeyFile == "") {
		return fmt.Errorf("config: set both %s and %s, or neither", envTLSCertFile, envTLSKeyFile)
	}
	if c.Fields == nil {
		return errors.New("config: field set is nil")
	}
	return nil
}

// validateKMS enforces that the proxy is configured for exactly one KMS
// backend: either a 32-byte static KEK (KKP_KEK) or a Vault Transit endpoint
// (KKP_VAULT_ADDR + token + key name).
func (c *ProxyConfig) validateKMS() error {
	hasStatic := len(c.KEK) > 0
	hasVault := c.VaultAddr != ""
	switch {
	case hasStatic && hasVault:
		return fmt.Errorf("config: set %s or %s, not both", envKEK, envVaultAddr)
	case !hasStatic && !hasVault:
		return fmt.Errorf("config: one of %s or %s is required", envKEK, envVaultAddr)
	case hasStatic && len(c.KEK) != kekBytes:
		return fmt.Errorf("config: %s must decode to %d bytes (got %d)", envKEK, kekBytes, len(c.KEK))
	case hasVault:
		return c.validateVaultAuth()
	}
	return nil
}

// validateVaultAuth checks the Vault Transit settings: a KEK name plus exactly
// one auth mode — a static token, an AppRole (both role id and secret id), or
// Kubernetes (a role, logging in with the pod ServiceAccount token).
func (c *ProxyConfig) validateVaultAuth() error {
	if c.VaultKeyName == "" {
		return fmt.Errorf("config: %s requires %s", envVaultAddr, envVaultKeyName)
	}
	hasToken := c.VaultToken != ""
	hasAppRole := c.VaultRoleID != "" || c.VaultSecretID != ""
	hasK8s := c.VaultKubernetesRole != ""
	switch {
	case boolCount(hasToken, hasAppRole, hasK8s) > 1:
		return fmt.Errorf("config: configure exactly one Vault auth mode — %s, AppRole (%s), or Kubernetes (%s)",
			envVaultToken, envVaultRoleID, envVaultK8sRole)
	case hasAppRole && (c.VaultRoleID == "" || c.VaultSecretID == ""):
		return fmt.Errorf("config: AppRole auth requires both %s and %s", envVaultRoleID, envVaultSecretID)
	case !hasToken && !hasAppRole && !hasK8s:
		return fmt.Errorf("config: %s requires one of %s, AppRole (%s), or Kubernetes (%s)",
			envVaultAddr, envVaultToken, envVaultRoleID, envVaultK8sRole)
	}
	return nil
}

// boolCount counts how many of the given conditions are true.
func boolCount(bs ...bool) int {
	n := 0
	for _, b := range bs {
		if b {
			n++
		}
	}
	return n
}

// selectFields builds the FieldSet matching the KKP_FIELDS env value.
func selectFields(value string) (*FieldSet, error) {
	switch value {
	case "":
		return Default(), nil
	case FieldsDisabled:
		return New(), nil
	case FieldsEmailOnly:
		fs := New()
		fs.SetColumn(TableUserEntity, "EMAIL", Rule{Scheme: crypto.SchemeDeterministic, LowercaseNormalize: true})
		return fs, nil
	case FieldsEmailOnlyBlindIndex:
		fs := New()
		fs.SetColumn(TableUserEntity, "EMAIL", Rule{
			Scheme: crypto.SchemeDeterministic, LowercaseNormalize: true, BlindIndex: "EMAIL_HASH",
		})
		return fs, nil
	default:
		return nil, fmt.Errorf("config: unknown %s value %q", envFields, value)
	}
}
