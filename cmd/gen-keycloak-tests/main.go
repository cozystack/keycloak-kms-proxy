// Command gen-keycloak-tests reads a pinned Keycloak model/jpa source tree
// and emits a deterministic golden conformance corpus (corpus.json) under
// testdata/keycloak/<version>/. The corpus describes each
// JPA entity (class, table, columns, named queries) and is cross-checked
// against the hand-derived keycloakmodel.Keycloak260() so that schema or
// query drift on a Keycloak upgrade surfaces as a reviewable diff.
package main

import (
	"flag"
	"fmt"
	"os"
	"path/filepath"

	"github.com/cozystack/keycloak-kms-proxy/internal/keycloakmodel"
)

// defaultVersion is the pinned Keycloak release this tool targets.
const defaultVersion = "26.0.0"

func main() {
	src := flag.String("src", "", "path to the Keycloak source tree (git tag checkout)")
	out := flag.String("out", "testdata/keycloak", "output root for the generated corpus")
	version := flag.String("version", defaultVersion, "Keycloak version label for the corpus")
	flag.Parse()

	if err := run(*src, *out, *version); err != nil {
		fmt.Fprintln(os.Stderr, "gen-keycloak-tests:", err)
		os.Exit(1)
	}
}

// run parses the Keycloak sources at src and writes <out>/<version>/corpus.json.
func run(src, out, version string) error {
	if src == "" {
		return fmt.Errorf("-src is required (path to a Keycloak %s source checkout)", version)
	}
	if _, err := os.Stat(src); err != nil {
		return fmt.Errorf("source tree %q: %w", src, err)
	}

	corpus, err := parseSource(src, version)
	if err != nil {
		return err
	}

	dir := filepath.Join(out, version)
	if err := os.MkdirAll(dir, 0o750); err != nil {
		return fmt.Errorf("create output dir %q: %w", dir, err)
	}

	path := filepath.Join(dir, "corpus.json")
	if err := writeCorpus(path, corpus); err != nil {
		return err
	}

	fmt.Printf("wrote %s (%d entities)\n", path, len(corpus.Entities))
	return nil
}

// writeCorpus writes the corpus to path as deterministic JSON.
func writeCorpus(path string, corpus keycloakmodel.Corpus) error {
	f, err := os.Create(path) //nolint:gosec // path is derived from the trusted -out flag.
	if err != nil {
		return fmt.Errorf("create %q: %w", path, err)
	}
	defer func() { _ = f.Close() }()

	if err := corpus.WriteJSON(f); err != nil {
		return err
	}
	if err := f.Close(); err != nil {
		return fmt.Errorf("close %q: %w", path, err)
	}
	return nil
}
