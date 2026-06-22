package config

import (
	"encoding/base64"
	"strings"
	"testing"
)

func validProxyConfig() *ProxyConfig {
	return &ProxyConfig{
		ListenAddr:       ":5432",
		BackendAddr:      "cnpg-rw:5432",
		KEK:              make([]byte, kekBytes),
		UpstreamUser:     "keycloak",
		UpstreamPassword: "kc-pw",
		BackendUser:      "proxy",
		BackendPassword:  "db-pw",
		Fields:           Default(),
	}
}

func TestProxyConfigValidateOK(t *testing.T) {
	t.Parallel()

	if err := validProxyConfig().Validate(); err != nil {
		t.Fatalf("Validate: %v", err)
	}
}

func TestProxyConfigValidateMissing(t *testing.T) {
	t.Parallel()

	c := validProxyConfig()
	c.BackendAddr = ""
	c.UpstreamUser = ""
	err := c.Validate()
	if err == nil {
		t.Fatal("Validate accepted a config with missing fields")
	}
	if !strings.Contains(err.Error(), envBackendAddr) || !strings.Contains(err.Error(), envUpstreamUser) {
		t.Fatalf("error should name the missing settings: %v", err)
	}
}

func TestProxyConfigValidateKEKLength(t *testing.T) {
	t.Parallel()

	c := validProxyConfig()
	c.KEK = []byte("too-short")
	if err := c.Validate(); err == nil {
		t.Fatal("Validate accepted an undersized KEK")
	}
}

func TestLoadProxyConfigFromEnv(t *testing.T) {
	kek := base64.StdEncoding.EncodeToString(make([]byte, kekBytes))
	t.Setenv(envListenAddr, ":5432")
	t.Setenv(envBackendAddr, "cnpg-rw:5432")
	t.Setenv(envKEK, kek)
	t.Setenv(envUpstreamUser, "keycloak")
	t.Setenv(envUpstreamPassword, "kc-pw")
	t.Setenv(envBackendUser, "proxy")
	t.Setenv(envBackendPassword, "db-pw")

	cfg, err := LoadProxyConfig()
	if err != nil {
		t.Fatalf("LoadProxyConfig: %v", err)
	}
	if cfg.ListenAddr != ":5432" || cfg.BackendAddr != "cnpg-rw:5432" || len(cfg.KEK) != kekBytes {
		t.Fatalf("config not loaded correctly: %+v", cfg)
	}
	if cfg.Fields == nil {
		t.Fatal("default field set not populated")
	}
}

func TestLoadProxyConfigFieldsDisabled(t *testing.T) {
	kek := base64.StdEncoding.EncodeToString(make([]byte, kekBytes))
	t.Setenv(envListenAddr, ":5432")
	t.Setenv(envBackendAddr, "cnpg-rw:5432")
	t.Setenv(envKEK, kek)
	t.Setenv(envUpstreamUser, "keycloak")
	t.Setenv(envUpstreamPassword, "kc-pw")
	t.Setenv(envBackendUser, "proxy")
	t.Setenv(envBackendPassword, "db-pw")
	t.Setenv(envFields, FieldsDisabled)

	cfg, err := LoadProxyConfig()
	if err != nil {
		t.Fatalf("LoadProxyConfig: %v", err)
	}
	if _, ok := cfg.Fields.ColumnRule(TableUserEntity, "EMAIL"); ok {
		t.Fatal("EMAIL is configured despite KKP_FIELDS=disabled")
	}
}

func TestLoadProxyConfigFieldsEmailOnly(t *testing.T) {
	kek := base64.StdEncoding.EncodeToString(make([]byte, kekBytes))
	t.Setenv(envListenAddr, ":5432")
	t.Setenv(envBackendAddr, "cnpg-rw:5432")
	t.Setenv(envKEK, kek)
	t.Setenv(envUpstreamUser, "keycloak")
	t.Setenv(envUpstreamPassword, "kc-pw")
	t.Setenv(envBackendUser, "proxy")
	t.Setenv(envBackendPassword, "db-pw")
	t.Setenv(envFields, FieldsEmailOnly)

	cfg, err := LoadProxyConfig()
	if err != nil {
		t.Fatalf("LoadProxyConfig: %v", err)
	}
	rule, ok := cfg.Fields.ColumnRule(TableUserEntity, "EMAIL")
	if !ok {
		t.Fatal("EMAIL not configured in email-only mode")
	}
	if !rule.LowercaseNormalize {
		t.Error("EMAIL should be lower-case-normalized")
	}
	if _, ok := cfg.Fields.ColumnRule(TableUserEntity, "USERNAME"); ok {
		t.Error("USERNAME unexpectedly encrypted in email-only mode")
	}
}

func TestLoadProxyConfigFieldsUnknown(t *testing.T) {
	kek := base64.StdEncoding.EncodeToString(make([]byte, kekBytes))
	t.Setenv(envListenAddr, ":5432")
	t.Setenv(envBackendAddr, "cnpg-rw:5432")
	t.Setenv(envKEK, kek)
	t.Setenv(envUpstreamUser, "keycloak")
	t.Setenv(envUpstreamPassword, "kc-pw")
	t.Setenv(envBackendUser, "proxy")
	t.Setenv(envBackendPassword, "db-pw")
	t.Setenv(envFields, "made-up-mode")

	if _, err := LoadProxyConfig(); err == nil {
		t.Fatal("LoadProxyConfig accepted an unknown KKP_FIELDS value")
	}
}

func TestLoadProxyConfigBadKEK(t *testing.T) {
	t.Setenv(envListenAddr, ":5432")
	t.Setenv(envBackendAddr, "cnpg-rw:5432")
	t.Setenv(envKEK, "!!!not base64!!!")
	t.Setenv(envUpstreamUser, "keycloak")
	t.Setenv(envUpstreamPassword, "kc-pw")
	t.Setenv(envBackendUser, "proxy")
	t.Setenv(envBackendPassword, "db-pw")

	if _, err := LoadProxyConfig(); err == nil {
		t.Fatal("LoadProxyConfig accepted invalid base64 KEK")
	}
}
