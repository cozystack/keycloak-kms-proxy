package main

import (
	"encoding/base64"
	"fmt"

	"github.com/cozystack/keycloak-kms-proxy/internal/kms"
)

// selectKMS chooses between the static KMS and Vault Transit. Exactly one set
// of credentials must be supplied: kek (base64) for static, or
// vault-addr/token/key for Vault.
func selectKMS(kekB64, vaultAddr, vaultToken, vaultKey, vaultMount string) (kms.KMS, error) {
	hasStatic := kekB64 != ""
	hasVault := vaultAddr != ""
	switch {
	case hasStatic && hasVault:
		return nil, fmt.Errorf("provide -kek or -vault-addr, not both")
	case hasStatic:
		kek, err := base64.StdEncoding.DecodeString(kekB64)
		if err != nil {
			return nil, fmt.Errorf("decode KEK: %w", err)
		}
		return kms.NewStaticKMS(kek)
	case hasVault:
		if vaultToken == "" || vaultKey == "" {
			return nil, fmt.Errorf("-vault-addr requires -vault-token and -vault-key")
		}
		return kms.NewVaultKMS(kms.VaultConfig{
			Address: vaultAddr,
			Token:   vaultToken,
			KeyName: vaultKey,
			Mount:   vaultMount,
		})
	default:
		return nil, fmt.Errorf("one of -kek or -vault-addr is required")
	}
}
