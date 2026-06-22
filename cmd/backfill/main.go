// Command backfill prepares an existing Keycloak database for the encrypting
// proxy: it mints a wrapped DEK set the proxy can load, and converts any
// plaintext rows in PII columns to ciphertext, idempotently via the
// $KKP$ marker. Run with Keycloak stopped.
//
//	backfill generate-dekset -kek <base64> -out dekset.json
//	backfill encrypt-rows   -kek <base64> -dekset dekset.json -dsn postgres://... -fields email-only|default
package main

import (
	"fmt"
	"log"
	"os"
)

func main() {
	if len(os.Args) < 2 {
		usage()
		os.Exit(2)
	}
	cmd := os.Args[1]
	os.Args = append([]string{os.Args[0]}, os.Args[2:]...) // strip subcommand for flag.Parse

	var err error
	switch cmd {
	case "generate-dekset":
		err = runGenerate()
	case "encrypt-rows":
		err = runEncrypt()
	case "migrate-blind-index":
		err = runMigrate()
	case "hash-rows":
		err = runHashRows()
	default:
		usage()
		os.Exit(2)
	}
	if err != nil {
		log.Fatalf("backfill: %v", err)
	}
}

func usage() {
	fmt.Fprintln(os.Stderr, "usage: backfill {generate-dekset|encrypt-rows} [flags]")
}
