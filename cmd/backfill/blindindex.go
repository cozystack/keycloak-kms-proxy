package main

import (
	"context"
	"flag"
	"fmt"
	"log"
	"strings"

	"github.com/jackc/pgx/v5"

	"github.com/cozystack/keycloak-kms-proxy/internal/crypto"
)

// runMigrate adds the shadow hash columns + indexes for every blind-indexed
// column in the configured field set. DDL only; safe to re-run via
// IF NOT EXISTS. Connects to PostgreSQL directly (bypasses the proxy).
func runMigrate() error {
	dsn := flag.String("dsn", "", "PostgreSQL DSN")
	fields := flag.String("fields", "email-only-blind-index", "field set")
	flag.Parse()
	if *dsn == "" {
		return fmt.Errorf("-dsn is required")
	}
	fs, err := selectFields(*fields)
	if err != nil {
		return err
	}

	ctx := context.Background()
	conn, err := pgx.Connect(ctx, *dsn)
	if err != nil {
		return err
	}
	defer func() { _ = conn.Close(ctx) }()

	for _, e := range fs.Columns() {
		if e.Rule.BlindIndex == "" {
			continue
		}
		table := strings.ToLower(e.Table)
		hashCol := strings.ToLower(e.Rule.BlindIndex)
		ddl := fmt.Sprintf("ALTER TABLE %s ADD COLUMN IF NOT EXISTS %s varchar(64)", table, hashCol)
		if _, err := conn.Exec(ctx, ddl); err != nil {
			return fmt.Errorf("alter %s: %w", table, err)
		}
		idx := fmt.Sprintf("CREATE INDEX IF NOT EXISTS idx_%s_%s ON %s (%s)", table, hashCol, table, hashCol)
		if _, err := conn.Exec(ctx, idx); err != nil {
			return fmt.Errorf("index %s: %w", hashCol, err)
		}
		log.Printf("  %s.%s ready", table, hashCol)
	}
	return nil
}

// runHashRows populates the hash columns for every existing row whose source
// PII column is non-NULL and whose hash is still NULL. Works on rows in either
// state (ciphertext under the marker, or legacy plaintext from a passthrough
// period) — the cipher's Decrypt handles the marker-driven passthrough.
func runHashRows() error {
	kekB64 := flag.String("kek", "", "base64-encoded KEK (static KMS)")
	vaultAddr := flag.String("vault-addr", "", "Vault address")
	vaultToken := flag.String("vault-token", "", "Vault token")
	vaultKey := flag.String("vault-key", "", "Vault Transit key")
	vaultMount := flag.String("vault-mount", "", "Vault Transit mount")
	dekset := flag.String("dekset", "dekset.json", "wrapped DEK set JSON")
	dsn := flag.String("dsn", "", "PostgreSQL DSN")
	fields := flag.String("fields", "email-only-blind-index", "field set")
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
	if cipher.BlindIndex() == nil {
		return fmt.Errorf("DEK set has no blind-index key — regenerate with generate-dekset")
	}
	fs, err := selectFields(*fields)
	if err != nil {
		return err
	}

	ctx := context.Background()
	conn, err := pgx.Connect(ctx, *dsn)
	if err != nil {
		return err
	}
	defer func() { _ = conn.Close(ctx) }()

	total := 0
	for _, e := range fs.Columns() {
		if e.Rule.BlindIndex == "" {
			continue
		}
		n, err := hashColumn(ctx, conn, cipher, e.Table, e.Column, e.Rule.BlindIndex)
		if err != nil {
			return fmt.Errorf("%s.%s: %w", e.Table, e.Column, err)
		}
		total += n
		log.Printf("  %s.%s -> %s: hashed %d row(s)", e.Table, e.Column, e.Rule.BlindIndex, n)
	}
	log.Printf("hashed %d row(s) total", total)
	return nil
}

func hashColumn(ctx context.Context, conn *pgx.Conn, cipher *crypto.Cipher, table, column, hashColumn string) (int, error) {
	tab := strings.ToLower(table)
	src := strings.ToLower(column)
	hash := strings.ToLower(hashColumn)

	sel := fmt.Sprintf("SELECT id, %s FROM %s WHERE %s IS NOT NULL AND %s IS NULL", src, tab, src, hash)
	rows, err := conn.Query(ctx, sel)
	if err != nil {
		return 0, fmt.Errorf("select: %w", err)
	}
	type rec struct{ id, value string }
	var batch []rec
	for rows.Next() {
		var r rec
		if err := rows.Scan(&r.id, &r.value); err != nil {
			rows.Close()
			return 0, err
		}
		batch = append(batch, r)
	}
	rows.Close()

	aad := []byte(strings.ToUpper(table) + "." + strings.ToUpper(column))
	upd := fmt.Sprintf("UPDATE %s SET %s = $1 WHERE id = $2", tab, hash)
	bi := cipher.BlindIndex()
	for _, r := range batch {
		// Cipher.Decrypt returns plaintext whether the source is an envelope
		// or a legacy plaintext (markerless passthrough).
		plaintext, err := cipher.Decrypt(r.value, aad)
		if err != nil {
			return 0, fmt.Errorf("decrypt id=%s: %w", r.id, err)
		}
		normalized := []byte(crypto.NormalizeLowercase(string(plaintext)))
		h, err := bi.Compute(normalized, aad)
		if err != nil {
			return 0, fmt.Errorf("hmac id=%s: %w", r.id, err)
		}
		if _, err := conn.Exec(ctx, upd, h, r.id); err != nil {
			return 0, fmt.Errorf("update id=%s: %w", r.id, err)
		}
	}
	return len(batch), nil
}
