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
//     arrives (i.e. `Table` is non-empty);
//   - every PII relation a SELECT reads (whatever the FROM shape — join,
//     comma join, sub-select, set operation, CTE) appears in `FromTables`
//     (TestRuntimeCorpusFromTableCoverage), so a joined read cannot slip past
//     the single-table gate above and leak ciphertext;
//   - the corpus itself is a reproducible set: no (Kind, Table, SQL) tuple
//     repeats (TestRuntimeCorpusUnique), matching what the generator emits.
//
// On a Keycloak upgrade: regenerate the golden via
// `examples/encryption-demo/`-style capture, review the diff in the PR.
package rewrite

import (
	"bufio"
	"os"
	"strings"
	"testing"

	pg "github.com/pganalyze/pg_query_go/v6"
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

// TestRuntimeCorpusFromTableCoverage — every PII relation a SELECT reads from
// must show up in `FromTables`, whatever shape the FROM clause takes.
//
// TestRuntimeCorpusPIICoverage above keys off the *captured* table column, so a
// statement whose table the proxy already failed to extract is skipped by the
// very gate meant to catch it. That blind spot is how the group-members read
// (USER_GROUP_MEMBERSHIP join USER_ENTITY) shipped: recorded with an empty
// table, skipped by the conformance test, and leaking every USER_ENTITY column
// as a raw envelope in production. This test reads the SQL instead.
func TestRuntimeCorpusFromTableCoverage(t *testing.T) {
	t.Parallel()
	cases := loadRuntimeCorpus(t)
	joined := 0
	for _, c := range cases {
		a, err := Analyze(c.SQL)
		if err != nil || a.Kind != KindSelect {
			continue // parse failures are reported by their own test.
		}
		if len(a.FromTables) > 1 {
			joined++
		}
		for _, rel := range expectedReadRelations(t, c.SQL) {
			if _, ok := piiTables[strings.ToLower(rel)]; !ok {
				continue
			}
			if !containsFold(a.FromTables, rel) {
				t.Errorf("SELECT reads PII relation %s but it is missing from FromTables=%v (silent-passthrough hazard)\n  sql=%s",
					rel, a.FromTables, truncateSQL(c.SQL, 200))
			}
		}
	}
	if joined == 0 {
		t.Fatal("no multi-relation SELECT in the corpus — the joined read path is uncovered")
	}
	t.Logf("runtime corpus covers %d multi-relation SELECTs", joined)
}

// TestRuntimeCorpusUnique — the golden corpus must be reproducible by its
// generator (cmd/capture-keycloak-sql), which dedups statements into a
// map[stmt]struct{} keyed on (Kind, Table, SQL) and writes the sorted set. A
// repeated tuple in the file could therefore never be regenerated, so guard
// against one creeping back in on the next capture/merge.
func TestRuntimeCorpusUnique(t *testing.T) {
	t.Parallel()
	seen := make(map[runtimeCase]int)
	for i, c := range loadRuntimeCorpus(t) {
		if first, dup := seen[c]; dup {
			t.Errorf("duplicate corpus entry (lines %d and %d): %s %s\n  sql=%s",
				first+1, i+1, c.Kind, c.Table, truncateSQL(c.SQL, 200))
			continue
		}
		seen[c] = i
	}
}

// expectedReadRelations parses a SELECT and returns the base relations in its
// result scope, independently of analyze.go: every relation named in a FROM
// clause (walking joins, comma joins, FROM sub-selects and set-operation arms,
// resolving CTE references to their underlying relations), and nothing that
// appears only in a WHERE sub-query — those rows never reach the client, so
// they need no decrypt plan. It is deliberately a second implementation of the
// walk in analyze.go, so this gate cross-checks FromTables rather than trusting
// the code it is testing; a string literal that merely contains the word "from"
// is a constant node, never a relation, so it cannot produce a false positive.
func expectedReadRelations(t *testing.T, sql string) []string {
	t.Helper()
	res, err := pg.Parse(sql)
	if err != nil {
		t.Fatalf("oracle parse %q: %v", sql, err)
	}
	o := &readOracle{seen: map[string]bool{}, active: map[string]bool{}}
	for _, raw := range res.GetStmts() {
		if sel := raw.GetStmt().GetSelectStmt(); sel != nil {
			o.walkSelect(sel, nil)
		}
	}
	return o.rels
}

// readOracle is the conformance test's independent relation collector. seen
// deduplicates; active guards a WITH RECURSIVE cycle.
type readOracle struct {
	rels   []string
	seen   map[string]bool
	active map[string]bool
}

func (o *readOracle) walkSelect(sel *pg.SelectStmt, ctes map[string]*pg.SelectStmt) {
	if sel == nil {
		return
	}
	ctes = oracleCTEScope(ctes, sel.GetWithClause())
	o.walkSelect(sel.GetLarg(), ctes)
	o.walkSelect(sel.GetRarg(), ctes)
	for _, item := range sel.GetFromClause() {
		o.walkFrom(item, ctes)
	}
}

func (o *readOracle) walkFrom(n *pg.Node, ctes map[string]*pg.SelectStmt) {
	if n == nil {
		return
	}
	switch {
	case n.GetRangeVar() != nil:
		o.add(n.GetRangeVar().GetRelname(), ctes)
	case n.GetJoinExpr() != nil:
		o.walkFrom(n.GetJoinExpr().GetLarg(), ctes)
		o.walkFrom(n.GetJoinExpr().GetRarg(), ctes)
	case n.GetRangeSubselect() != nil:
		o.walkSelect(n.GetRangeSubselect().GetSubquery().GetSelectStmt(), ctes)
	}
}

func (o *readOracle) add(name string, ctes map[string]*pg.SelectStmt) {
	if name == "" {
		return
	}
	key := strings.ToUpper(name)
	if q, ok := ctes[key]; ok {
		if o.active[key] {
			return
		}
		o.active[key] = true
		o.walkSelect(q, ctes)
		delete(o.active, key)
		return
	}
	if o.seen[key] {
		return
	}
	o.seen[key] = true
	o.rels = append(o.rels, name)
}

func oracleCTEScope(parent map[string]*pg.SelectStmt, wc *pg.WithClause) map[string]*pg.SelectStmt {
	if wc == nil || len(wc.GetCtes()) == 0 {
		return parent
	}
	scope := make(map[string]*pg.SelectStmt, len(parent)+len(wc.GetCtes()))
	for k, v := range parent {
		scope[k] = v
	}
	for _, node := range wc.GetCtes() {
		if cte := node.GetCommonTableExpr(); cte != nil {
			if q := cte.GetCtequery().GetSelectStmt(); q != nil {
				scope[strings.ToUpper(cte.GetCtename())] = q
			}
		}
	}
	return scope
}

func containsFold(list []string, want string) bool {
	for _, s := range list {
		if strings.EqualFold(s, want) {
			return true
		}
	}
	return false
}
