// Command capture-keycloak-sql captures the unique set of SQL statements
// Keycloak emits when driven through the proxy, and writes them as the
// runtime SQL conformance golden corpus.
//
// The capture happens entirely from the kubectl-visible side:
//
//  1. Read the proxy's stdout via `kubectl logs deploy/kkp-proxy -f`. The
//     proxy must run with KKP_DEBUG_RELAY=true so every Parse emits a
//     `kkp: parse "<name>" kind=<K> table="<t>" writeParams=<n> sql="<...>"`
//     line.
//  2. Drive a known client scenario against Keycloak (login by email, admin
//     REST list / get / update / password reset, etc.). The scenario is
//     supplied by the caller — either an HTTP scenario script or a manual
//     run; the tool only reads the log stream.
//  3. Parse the structured log lines, dedupe by (kind, table, sql), and
//     write a sorted golden corpus file as `<KIND>\t<TABLE>\t<SQL>` per
//     line. This is the file `internal/rewrite/runtime_corpus_test.go`
//     gates on.
//
// Typical use:
//
//	# kubectl in a separate window:
//	kubectl -n keycloak-kms-proxy-demo logs deploy/kkp-proxy -f > /tmp/raw.log
//	# drive Keycloak in another window, then:
//	capture-keycloak-sql -in /tmp/raw.log -out testdata/keycloak/26.0.0/runtime-sql.txt
//
// or as a one-shot pipeline:
//
//	kubectl -n keycloak-kms-proxy-demo logs deploy/kkp-proxy --since=1m \
//	  | capture-keycloak-sql -out testdata/keycloak/26.0.0/runtime-sql.txt
package main

import (
	"bufio"
	"flag"
	"fmt"
	"io"
	"os"
	"regexp"
	"sort"
	"strings"
)

// parseLine matches `kkp: parse "<name>" kind=<K> table="<t>" writeParams=<n> sql="<...>"`
// emitted by internal/wire/session.go when KKP_DEBUG_RELAY=true. The greedy
// `(.*)` at the end captures the SQL inside the trailing sql="…" — debug
// lines are guaranteed not to embed an unescaped trailing quote because the
// session.go writer goes through %q which escapes them.
var parseLine = regexp.MustCompile(`kkp: parse "[^"]*" kind=([A-Z]+) table="([^"]*)"[^"]*sql="(.*)"$`)

type stmt struct {
	Kind, Table, SQL string
}

func main() {
	if err := run(); err != nil {
		fmt.Fprintf(os.Stderr, "capture-keycloak-sql: %v\n", err)
		os.Exit(1)
	}
}

func run() error {
	in := flag.String("in", "-", "path to a captured proxy log (- for stdin)")
	out := flag.String("out", "", "path to write the golden corpus (required)")
	merge := flag.Bool("merge", false, "merge with existing -out file (union by Kind+Table+SQL)")
	flag.Parse()

	if *out == "" {
		return fmt.Errorf("-out is required")
	}

	var r io.Reader = os.Stdin
	if *in != "-" {
		f, err := os.Open(*in) //nolint:gosec // caller-supplied path
		if err != nil {
			return fmt.Errorf("open %s: %w", *in, err)
		}
		defer func() { _ = f.Close() }()
		r = f
	}

	seen := make(map[stmt]struct{})
	// Pre-seed from the existing corpus when -merge is set; this lets the
	// scenario be split across multiple captures (e.g. bootstrap + steady
	// state + admin-REST surface) and have the union accumulate over time.
	if *merge {
		if f, err := os.Open(*out); err == nil { //nolint:gosec // caller-supplied
			s := bufio.NewScanner(f)
			s.Buffer(make([]byte, 0, 64*1024), 4*1024*1024)
			for s.Scan() {
				parts := strings.SplitN(s.Text(), "\t", 3)
				if len(parts) == 3 {
					seen[stmt{Kind: parts[0], Table: parts[1], SQL: parts[2]}] = struct{}{}
				}
			}
			_ = f.Close()
		}
	}

	sc := bufio.NewScanner(r)
	sc.Buffer(make([]byte, 0, 64*1024), 4*1024*1024)
	for sc.Scan() {
		m := parseLine.FindStringSubmatch(sc.Text())
		if m == nil {
			continue
		}
		s := stmt{Kind: m[1], Table: m[2], SQL: strings.TrimSpace(m[3])}
		seen[s] = struct{}{}
	}
	if err := sc.Err(); err != nil {
		return fmt.Errorf("scan: %w", err)
	}

	all := make([]stmt, 0, len(seen))
	for s := range seen {
		all = append(all, s)
	}
	sort.Slice(all, func(i, j int) bool {
		if all[i].Kind != all[j].Kind {
			return all[i].Kind < all[j].Kind
		}
		if all[i].Table != all[j].Table {
			return all[i].Table < all[j].Table
		}
		return all[i].SQL < all[j].SQL
	})

	f, err := os.Create(*out) //nolint:gosec // caller-supplied path
	if err != nil {
		return fmt.Errorf("create %s: %w", *out, err)
	}
	defer func() { _ = f.Close() }()
	for _, s := range all {
		if _, err := fmt.Fprintf(f, "%s\t%s\t%s\n", s.Kind, s.Table, s.SQL); err != nil {
			return fmt.Errorf("write: %w", err)
		}
	}
	fmt.Fprintf(os.Stderr, "wrote %d unique statements to %s\n", len(all), *out)
	return nil
}
