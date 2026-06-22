// Runtime SQL conformance test.
//
// Reads a golden corpus of *real* Hibernate-generated SQL captured from a
// live Keycloak 26.0.0 running through the proxy (KKP_DEBUG_RELAY=true) on
// a live integration cluster. For every SQL the test asserts:
//
//   - `Analyze` does not return an error;
//   - the structural Kind matches the captured Kind (so a SELECT that the
//     parser later starts classifying as something else is caught);
//   - the extracted `Table` matches the captured table (so a Hibernate
//     refactor — e.g. wrapping a SELECT in a subquery — that hides the FROM
//     target fails the test instead of silently falling into passthrough);
//   - for PII-touching SQL specifically, the proxy either built a write
//     plan (INSERT/UPDATE) or will build a read plan when the RowDescription
//     arrives (i.e. `Table` is non-empty).
//
// On a Keycloak upgrade: regenerate the golden via
// `examples/encryption-demo/`-style capture, review the diff in the PR.
package rewrite

import (
	"bufio"
	"os"
	"strings"
	"testing"
)

const runtimeCorpusPath = "../../testdata/keycloak/26.0.0/runtime-sql.txt"

// piiTables is the set of tables whose rows hold PII. A
// SQL touching one of these on the read or write path must end up with a
// non-empty `Analysis.Table` so the planner can decide what to do.
var piiTables = map[string]struct{}{
	"user_entity":              {},
	"user_attribute":           {},
	"credential":               {},
	"federated_identity":       {},
	"fed_user_entity":          {},
	"fed_user_attribute":       {},
	"fed_user_credential":      {},
	"fed_user_consent":         {},
	"fed_user_required_action": {},
}

// truncateSQL is a local helper to keep the test self-contained.
func truncateSQL(s string, n int) string {
	s = strings.Join(strings.Fields(s), " ")
	if len(s) > n {
		return s[:n] + "..."
	}
	return s
}

type runtimeCase struct {
	Kind  string
	Table string
	SQL   string
}

func loadRuntimeCorpus(t *testing.T) []runtimeCase {
	t.Helper()
	f, err := os.Open(runtimeCorpusPath)
	if err != nil {
		t.Fatalf("open runtime corpus %s: %v", runtimeCorpusPath, err)
	}
	defer func() { _ = f.Close() }()

	var cases []runtimeCase
	sc := bufio.NewScanner(f)
	sc.Buffer(make([]byte, 0, 1024), 1024*1024)
	for sc.Scan() {
		line := sc.Text()
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		parts := strings.SplitN(line, "\t", 3)
		if len(parts) != 3 {
			t.Fatalf("malformed corpus line: %q", line)
		}
		cases = append(cases, runtimeCase{Kind: parts[0], Table: parts[1], SQL: parts[2]})
	}
	if err := sc.Err(); err != nil {
		t.Fatalf("scan corpus: %v", err)
	}
	return cases
}

// TestRuntimeCorpusParses — every captured SQL must parse and produce the
// same StmtKind the proxy classified live.
func TestRuntimeCorpusParses(t *testing.T) {
	t.Parallel()
	cases := loadRuntimeCorpus(t)
	if len(cases) == 0 {
		t.Fatal("empty runtime corpus")
	}
	for _, c := range cases {
		a, err := Analyze(c.SQL)
		if err != nil {
			t.Errorf("Analyze failed for %s %s: %v\n  sql=%s", c.Kind, c.Table, err, truncateSQL(c.SQL, 200))
			continue
		}
		if a.Kind.String() != c.Kind {
			t.Errorf("kind mismatch for %s %s: got %s, want %s", c.Kind, c.Table, a.Kind, c.Kind)
		}
	}
}

// TestRuntimeCorpusTableExtraction — for non-OTHER statements, `Table` must
// match the captured value. This is what catches silent-ciphertext gaps:
// when Hibernate emits a new shape (e.g. JOIN/subquery) that the analyser
// no longer extracts a target from, the field switches to "" and the test
// fails instead of the data path silently returning ciphertext.
func TestRuntimeCorpusTableExtraction(t *testing.T) {
	t.Parallel()
	cases := loadRuntimeCorpus(t)
	for _, c := range cases {
		if c.Kind == "OTHER" {
			continue // BEGIN/COMMIT/etc carry no table by definition.
		}
		a, err := Analyze(c.SQL)
		if err != nil {
			continue // separate test reports parse failures.
		}
		if strings.EqualFold(a.Table, c.Table) {
			continue
		}
		t.Errorf("table mismatch for %s %s: got %q, want %q\n  sql=%s",
			c.Kind, c.Table, a.Table, c.Table, truncateSQL(c.SQL, 200))
	}
}

// TestRuntimeCorpusPIICoverage — every captured SQL that touches a PII
// table must have a non-empty extracted `Table`. If this fails, the proxy
// would silently pass PII bytes through on that path (read) or refuse the
// write (loud — different failure mode). This is the conformance gate.
func TestRuntimeCorpusPIICoverage(t *testing.T) {
	t.Parallel()
	cases := loadRuntimeCorpus(t)
	pii := 0
	for _, c := range cases {
		tbl := strings.ToLower(c.Table)
		if _, ok := piiTables[tbl]; !ok && !strings.HasPrefix(tbl, "fed_user_") {
			continue
		}
		pii++
		a, err := Analyze(c.SQL)
		if err != nil {
			t.Errorf("Analyze failed for PII %s %s: %v", c.Kind, c.Table, err)
			continue
		}
		if a.Table == "" {
			t.Errorf("PII-touching %s on %s lost its table extraction (silent-passthrough hazard)\n  sql=%s",
				c.Kind, c.Table, truncateSQL(c.SQL, 200))
		}
	}
	if pii == 0 {
		t.Fatal("no PII-touching SQL in the corpus — capture scenario is incomplete")
	}
	t.Logf("runtime corpus covers %d PII-touching statements", pii)
}
