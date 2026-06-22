package main

import (
	"context"
	"encoding/json"
	"flag"
	"fmt"
	"log"
	"os"
	"strings"

	"github.com/jackc/pgx/v5"

	"github.com/cozystack/keycloak-kms-proxy/internal/config"
	"github.com/cozystack/keycloak-kms-proxy/internal/crypto"
	"github.com/cozystack/keycloak-kms-proxy/internal/kms"
)

// runEncrypt walks every configured PII column and rewrites unmarked rows as
// ciphertext, idempotently via the $KKP$ marker. The cipher is
// the same one the proxy uses, so the proxy can decrypt the result on read.
func runEncrypt() error {
	kekB64 := flag.String("kek", "", "base64-encoded KEK (static KMS)")
	vaultAddr := flag.String("vault-addr", "", "Vault address (Transit KMS, alternative to -kek)")
	vaultToken := flag.String("vault-token", "", "Vault token")
	vaultKey := flag.String("vault-key", "", "Vault Transit key name")
	vaultMount := flag.String("vault-mount", "", "Vault Transit mount (default transit)")
	dekset := flag.String("dekset", "dekset.json", "wrapped DEK set JSON (from generate-dekset)")
	dsn := flag.String("dsn", "", "PostgreSQL DSN, e.g. postgres://user:pw@host:5432/keycloak")
	fields := flag.String("fields", "default", "field set: email-only or default")
	flag.Parse()

	if *dsn == "" {
		return fmt.Errorf("-dsn is required")
	}

	k, err := selectKMS(*kekB64, *vaultAddr, *vaultToken, *vaultKey, *vaultMount)
	if err != nil {
		return err
	}
	cipher, err := openCipherFromFile(k, *dekset)
	if err != nil {
		return err
	}
	fs, err := selectFields(*fields)
	if err != nil {
		return err
	}

	ctx := context.Background()
	conn, err := pgx.Connect(ctx, *dsn)
	if err != nil {
		return fmt.Errorf("connect: %w", err)
	}
	defer func() { _ = conn.Close(ctx) }()

	total := 0
	for _, entry := range fs.Columns() {
		n, err := encryptColumn(ctx, conn, cipher, entry)
		if err != nil {
			return fmt.Errorf("%s.%s: %w", entry.Table, entry.Column, err)
		}
		log.Printf("  %s.%s: encrypted %d row(s)", entry.Table, entry.Column, n)
		total += n
	}
	log.Printf("encrypted %d value(s) across %d column(s)", total, len(fs.Columns()))
	return nil
}

func openCipherFromFile(k kms.KMS, path string) (*crypto.Cipher, error) {
	raw, err := os.ReadFile(path) //nolint:gosec // path comes from the -dekset flag.
	if err != nil {
		return nil, fmt.Errorf("read DEK set: %w", err)
	}
	var set kms.DEKSet
	if err := json.Unmarshal(raw, &set); err != nil {
		return nil, fmt.Errorf("decode DEK set: %w", err)
	}
	return kms.OpenCipher(context.Background(), k, set)
}

func selectFields(value string) (*config.FieldSet, error) {
	switch value {
	case "email-only":
		fs := config.New()
		fs.SetColumn(config.TableUserEntity, "EMAIL", config.Rule{Scheme: crypto.SchemeDeterministic, LowercaseNormalize: true})
		return fs, nil
	case "email-only-blind-index":
		fs := config.New()
		fs.SetColumn(config.TableUserEntity, "EMAIL", config.Rule{
			Scheme: crypto.SchemeDeterministic, LowercaseNormalize: true, BlindIndex: "EMAIL_HASH",
		})
		return fs, nil
	case "default":
		return config.Default(), nil
	default:
		return nil, fmt.Errorf("unknown -fields value %q", value)
	}
}

// encryptColumn rewrites any plaintext (markerless) values in the given column
// to ciphertext under the supplied cipher and rule. Idempotent: rows whose
// value already starts with the sentinel are skipped by the SELECT filter.
func encryptColumn(ctx context.Context, conn *pgx.Conn, cipher *crypto.Cipher, e config.ColumnRuleEntry) (int, error) {
	// Keycloak's DDL creates lowercased table/column identifiers in PG.
	table := strings.ToLower(e.Table)
	column := strings.ToLower(e.Column)

	selectSQL := fmt.Sprintf(
		"SELECT id, %s FROM %s WHERE %s IS NOT NULL AND %s NOT LIKE '$KKP$%%'",
		column, table, column, column,
	)
	rows, err := conn.Query(ctx, selectSQL)
	if err != nil {
		return 0, fmt.Errorf("select: %w", err)
	}
	type rec struct {
		id    string
		value string
	}
	var batch []rec
	for rows.Next() {
		var r rec
		if err := rows.Scan(&r.id, &r.value); err != nil {
			rows.Close()
			return 0, fmt.Errorf("scan: %w", err)
		}
		batch = append(batch, r)
	}
	rows.Close()

	aad := []byte(strings.ToUpper(e.Table) + "." + strings.ToUpper(e.Column))
	updateSQL := fmt.Sprintf("UPDATE %s SET %s = $1 WHERE id = $2", table, column)
	for _, r := range batch {
		plaintext := []byte(r.value)
		if e.Rule.LowercaseNormalize {
			plaintext = []byte(crypto.NormalizeLowercase(r.value))
		}
		stored, err := cipher.Encrypt(e.Rule.Scheme, plaintext, aad)
		if err != nil {
			return 0, fmt.Errorf("encrypt id=%s: %w", r.id, err)
		}
		if _, err := conn.Exec(ctx, updateSQL, stored, r.id); err != nil {
			return 0, fmt.Errorf("update id=%s: %w", r.id, err)
		}
	}
	return len(batch), nil
}
