package main

import (
	"context"
	"encoding/json"
	"flag"
	"fmt"
	"log"
	"math"
	"os"

	"github.com/cozystack/keycloak-kms-proxy/internal/kms"
)

// runGenerate mints a fresh DEK set wrapped by the static KMS and writes it as
// JSON. The proxy and the encrypt-rows step both load this same file so they
// share a key.
func runGenerate() error {
	kekB64 := flag.String("kek", "", "base64-encoded 32-byte KEK (static KMS)")
	vaultAddr := flag.String("vault-addr", "", "Vault address (Transit KMS, alternative to -kek)")
	vaultToken := flag.String("vault-token", "", "Vault token")
	vaultKey := flag.String("vault-key", "", "Vault Transit key name")
	vaultMount := flag.String("vault-mount", "", "Vault Transit mount (default transit)")
	out := flag.String("out", "dekset.json", "output JSON file")
	keyVersion := flag.Uint("key-version", 1, "key version recorded in the DEK set")
	flag.Parse()

	k, err := selectKMS(*kekB64, *vaultAddr, *vaultToken, *vaultKey, *vaultMount)
	if err != nil {
		return err
	}

	if *keyVersion > math.MaxUint32 {
		return fmt.Errorf("-key-version %d exceeds uint32 range", *keyVersion)
	}
	set, err := kms.GenerateDEKSet(context.Background(), k, uint32(*keyVersion))
	if err != nil {
		return err
	}
	data, err := json.MarshalIndent(set, "", "  ")
	if err != nil {
		return err
	}
	if err := os.WriteFile(*out, data, 0o600); err != nil {
		return err
	}
	log.Printf("wrote wrapped DEK set to %s (key_version=%d)", *out, set.KeyVersion)
	return nil
}
