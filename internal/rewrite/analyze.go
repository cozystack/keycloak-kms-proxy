package rewrite

import (
	"fmt"
	"strings"

	pg "github.com/pganalyze/pg_query_go/v6"
)

// StmtKind classifies a parsed SQL statement.
type StmtKind int

// Statement kinds. KindOther covers everything the proxy passes through
// untouched (DDL/Liquibase, COPY, etc.).
const (
	KindOther StmtKind = iota
	KindSelect
	KindInsert
	KindUpdate
	KindDelete
)

// String renders the statement kind.
func (k StmtKind) String() string {
	switch k {
	case KindSelect:
		return "SELECT"
	case KindInsert:
		return "INSERT"
	case KindUpdate:
		return "UPDATE"
	case KindDelete:
		return "DELETE"
	default:
		return "OTHER"
	}
}

// ColumnParam binds a column to a 1-based statement parameter position ($1 → 1).
// Param is 0 when the column's value is not a bound parameter (a literal,
// DEFAULT, or expression).
type ColumnParam struct {
	Column string
	Param  int
}

// Analysis is the structural result of parsing one SQL statement: enough to map
// PII columns to the parameters that carry their values on the write path and
// to the filtered columns on the read/search path.
type Analysis struct {
	Kind StmtKind
	// SQL is this statement's own text within a multi-statement
	// simple-protocol query string. Set by AnalyzeAll only; empty for
	// Analyze, whose callers already hold the (single) statement text.
	SQL string
	// Table is the target table (INSERT/UPDATE/DELETE) or, for a SELECT, the
	// first FROM item when that item is a plain range variable. It is empty
	// when the first FROM item is an explicit JOIN expression, whose first
	// child is the join rather than a relation. A comma join (FROM a, b) keeps
	// Table non-empty, but it names only the first of several relations —
	// prefer FromTables, which lists them all. Table is retained for the write
	// path and the conformance corpus.
	Table string
	// FromTables lists every base relation the statement reads, with join
	// trees, sub-selects and set-operation arms walked and CTE references
	// resolved to their underlying relations; for INSERT/UPDATE/DELETE it is
	// the target relation. The read planner resolves each result column against
	// this set, so a result set assembled by a join still decrypts: Keycloak's
	// group-members listing (USER_GROUP_MEMBERSHIP join USER_ENTITY) selects
	// every USER_ENTITY column and used to hand Keycloak raw envelopes because
	// Table is empty for a join.
	FromTables []string
	// WriteColumns are the columns whose values are written: INSERT column list
	// and UPDATE SET targets, each with the parameter position of its value.
	WriteColumns []ColumnParam
	// FilterColumns are the columns compared for equality in the WHERE clause,
	// each with the parameter position of the compared value.
	FilterColumns []ColumnParam
	// LikeFilterColumns are the columns compared with LIKE/ILIKE in the WHERE
	// clause. The proxy can rewrite these to equality on deterministic PII
	// columns when the bound value carries no wildcards (% or _).
	LikeFilterColumns []ColumnParam
}

// Analyze parses exactly one SQL statement and extracts its structure. It
// returns an error on a parse failure or when the input is not a single
// statement.
func Analyze(sql string) (*Analysis, error) {
	result, err := pg.Parse(sql)
	if err != nil {
		return nil, fmt.Errorf("rewrite: parse: %w", err)
	}
	stmts := result.GetStmts()
	if len(stmts) != 1 {
		return nil, fmt.Errorf("rewrite: expected exactly one statement, got %d", len(stmts))
	}
	return analyzeNode(stmts[0].GetStmt()), nil
}

// AnalyzeAll parses a simple-protocol query string, which may carry several
// semicolon-separated statements, and returns one Analysis per statement in
// order, each carrying its own statement text. The backend answers each
// statement with its own result cycle, so the wire layer needs one
// result-queue entry per statement to stay in sync.
func AnalyzeAll(sql string) ([]*Analysis, error) {
	result, err := pg.Parse(sql)
	if err != nil {
		return nil, fmt.Errorf("rewrite: parse: %w", err)
	}
	stmts := result.GetStmts()
	analyses := make([]*Analysis, 0, len(stmts))
	for _, st := range stmts {
		a := analyzeNode(st.GetStmt())
		a.SQL = statementText(sql, st)
		analyses = append(analyses, a)
	}
	return analyses, nil
}

// statementText slices one statement's own text out of a multi-statement
// query string using the parser's location/length, so per-statement logging
// and PII heuristics do not see the neighbouring statements.
func statementText(sql string, st *pg.RawStmt) string {
	start := int(st.GetStmtLocation())
	if start < 0 || start > len(sql) {
		return sql
	}
	end := len(sql)
	if l := int(st.GetStmtLen()); l > 0 && start+l <= len(sql) {
		end = start + l
	}
	return strings.TrimLeft(sql[start:end], " \t\r\n;")
}

func analyzeNode(node *pg.Node) *Analysis {
	switch {
	case node.GetInsertStmt() != nil:
		return analyzeInsert(node.GetInsertStmt())
	case node.GetUpdateStmt() != nil:
		return analyzeUpdate(node.GetUpdateStmt())
	case node.GetSelectStmt() != nil:
		return analyzeSelect(node.GetSelectStmt())
	case node.GetDeleteStmt() != nil:
		return analyzeDelete(node.GetDeleteStmt())
	default:
		return &Analysis{Kind: KindOther}
	}
}

func analyzeInsert(ins *pg.InsertStmt) *Analysis {
	a := &Analysis{Kind: KindInsert, Table: ins.GetRelation().GetRelname()}
	a.FromTables = targetTables(a.Table)

	var params []int
	if sel := ins.GetSelectStmt().GetSelectStmt(); sel != nil && len(sel.GetValuesLists()) > 0 {
		for _, item := range sel.GetValuesLists()[0].GetList().GetItems() {
			params = append(params, paramNumber(item))
		}
	}

	for i, col := range ins.GetCols() {
		p := 0
		if i < len(params) {
			p = params[i]
		}
		a.WriteColumns = append(a.WriteColumns, ColumnParam{Column: col.GetResTarget().GetName(), Param: p})
	}
	return a
}

func analyzeUpdate(upd *pg.UpdateStmt) *Analysis {
	a := &Analysis{Kind: KindUpdate, Table: upd.GetRelation().GetRelname()}
	a.FromTables = targetTables(a.Table)
	for _, t := range upd.GetTargetList() {
		rt := t.GetResTarget()
		a.WriteColumns = append(a.WriteColumns, ColumnParam{Column: rt.GetName(), Param: paramNumber(rt.GetVal())})
	}
	a.FilterColumns, a.LikeFilterColumns = whereColumns(upd.GetWhereClause())
	return a
}

func analyzeSelect(sel *pg.SelectStmt) *Analysis {
	a := &Analysis{Kind: KindSelect}
	if from := sel.GetFromClause(); len(from) > 0 {
		if rv := from[0].GetRangeVar(); rv != nil {
			a.Table = rv.GetRelname()
		}
	}
	a.FromTables = selectTables(sel)
	a.FilterColumns, a.LikeFilterColumns = whereColumns(sel.GetWhereClause())
	return a
}

// targetTables returns a write statement's target relation as its lone read
// source, so a plain RETURNING result set decrypts like any other read. It
// does not walk an UPDATE ... FROM / DELETE ... USING auxiliary relation, so a
// RETURNING column drawn from one of those is not resolved — Keycloak issues no
// such statement against a PII table, and the read-path leak detector would
// flag any envelope that slipped through.
func targetTables(table string) []string {
	if table == "" {
		return nil
	}
	return []string{table}
}

// selectTables collects every base relation a SELECT reads from, in the order
// they appear, without duplicates. CTE references are resolved to the relations
// their query reads rather than reported as base tables.
func selectTables(sel *pg.SelectStmt) []string {
	c := &tableCollector{seen: make(map[string]bool), cteActive: make(map[string]bool)}
	c.walkSelect(sel, nil)
	return c.tables
}

// tableCollector accumulates the base relations of a SELECT. seen deduplicates
// the result; cteActive guards against a WITH RECURSIVE cycle while a CTE
// reference is being resolved.
type tableCollector struct {
	tables    []string
	seen      map[string]bool
	cteActive map[string]bool
}

// walkSelect descends a SELECT, its set-operation arms (UNION and friends) and
// its FROM items. ctes is the CTE scope in effect, extended by this select's
// own WITH clause; a nested WITH shadows outer names.
func (c *tableCollector) walkSelect(sel *pg.SelectStmt, ctes map[string]*pg.SelectStmt) {
	if sel == nil {
		return
	}
	ctes = extendCTEScope(ctes, sel.GetWithClause())
	c.walkSelect(sel.GetLarg(), ctes)
	c.walkSelect(sel.GetRarg(), ctes)
	for _, item := range sel.GetFromClause() {
		c.walkFromItem(item, ctes)
	}
}

// walkFromItem walks one FROM item: a range variable is a base relation (or a
// CTE reference to resolve), a join expression has two sides, and a sub-select
// carries its own FROM clause.
func (c *tableCollector) walkFromItem(n *pg.Node, ctes map[string]*pg.SelectStmt) {
	if n == nil {
		return
	}
	switch {
	case n.GetRangeVar() != nil:
		c.addRelation(n.GetRangeVar().GetRelname(), ctes)
	case n.GetJoinExpr() != nil:
		je := n.GetJoinExpr()
		c.walkFromItem(je.GetLarg(), ctes)
		c.walkFromItem(je.GetRarg(), ctes)
	case n.GetRangeSubselect() != nil:
		c.walkSelect(n.GetRangeSubselect().GetSubquery().GetSelectStmt(), ctes)
	}
}

// addRelation records a base relation, or resolves a CTE reference to the
// relations its query reads — a CTE alias is never reported as a base table.
func (c *tableCollector) addRelation(name string, ctes map[string]*pg.SelectStmt) {
	if name == "" {
		return
	}
	key := strings.ToUpper(name)
	if q, ok := ctes[key]; ok {
		if c.cteActive[key] {
			return // WITH RECURSIVE self-reference: already resolving it.
		}
		c.cteActive[key] = true
		c.walkSelect(q, ctes)
		delete(c.cteActive, key)
		return
	}
	if c.seen[key] {
		return
	}
	c.seen[key] = true
	c.tables = append(c.tables, name)
}

// extendCTEScope returns the CTE scope augmented with a WITH clause's CTEs,
// mapping each upper-cased CTE name to its query. The parent scope is left
// untouched so sibling selects do not see this level's names.
func extendCTEScope(parent map[string]*pg.SelectStmt, wc *pg.WithClause) map[string]*pg.SelectStmt {
	if wc == nil || len(wc.GetCtes()) == 0 {
		return parent
	}
	scope := make(map[string]*pg.SelectStmt, len(parent)+len(wc.GetCtes()))
	for k, v := range parent {
		scope[k] = v
	}
	for _, node := range wc.GetCtes() {
		cte := node.GetCommonTableExpr()
		if cte == nil {
			continue
		}
		if q := cte.GetCtequery().GetSelectStmt(); q != nil {
			scope[strings.ToUpper(cte.GetCtename())] = q
		}
	}
	return scope
}

func analyzeDelete(del *pg.DeleteStmt) *Analysis {
	a := &Analysis{Kind: KindDelete, Table: del.GetRelation().GetRelname()}
	a.FromTables = targetTables(a.Table)
	a.FilterColumns, a.LikeFilterColumns = whereColumns(del.GetWhereClause())
	return a
}

func paramNumber(n *pg.Node) int {
	if n == nil {
		return 0
	}
	if pr := n.GetParamRef(); pr != nil {
		return int(pr.GetNumber())
	}
	// Keycloak's pgjdbc renders `LIKE :p ESCAPE ''` as a call to
	// pg_catalog.like_escape($n, ''); descend into the first argument so the
	// proxy still sees the underlying $n.
	if fc := n.GetFuncCall(); fc != nil && isLikeEscape(fc) && len(fc.GetArgs()) >= 1 {
		return paramNumber(fc.GetArgs()[0])
	}
	return 0
}

func isLikeEscape(fc *pg.FuncCall) bool {
	name := fc.GetFuncname()
	if len(name) == 0 {
		return false
	}
	last := name[len(name)-1].GetString_()
	return last != nil && last.GetSval() == "like_escape"
}

// whereColumns walks a WHERE clause and returns the columns compared by
// equality and by LIKE/ILIKE, with their parameter positions.
func whereColumns(where *pg.Node) (eq, like []ColumnParam) {
	collectWhere(where, &eq, &like)
	return eq, like
}

func collectWhere(n *pg.Node, eq, like *[]ColumnParam) {
	if n == nil {
		return
	}
	if be := n.GetBoolExpr(); be != nil {
		for _, arg := range be.GetArgs() {
			collectWhere(arg, eq, like)
		}
		return
	}
	ae := n.GetAExpr()
	if ae == nil {
		return
	}
	switch ae.GetKind() {
	case pg.A_Expr_Kind_AEXPR_OP, pg.A_Expr_Kind_AEXPR_LIKE, pg.A_Expr_Kind_AEXPR_ILIKE:
		// supported.
	default:
		return
	}
	target := bucketFor(ae.GetName(), eq, like)
	if target == nil {
		return
	}

	// Accept either operand order: "col OP $n" or "$n OP col".
	col, param := columnName(ae.GetLexpr()), paramNumber(ae.GetRexpr())
	if col == "" {
		col, param = columnName(ae.GetRexpr()), paramNumber(ae.GetLexpr())
	}
	if col != "" {
		*target = append(*target, ColumnParam{Column: col, Param: param})
	}
}

// bucketFor routes an A_Expr to the eq or like collector based on its operator.
// Returns nil for anything other than =, ~~ (LIKE), or ~~* (ILIKE).
func bucketFor(name []*pg.Node, eq, like *[]ColumnParam) *[]ColumnParam {
	op := operatorName(name)
	switch op {
	case "=":
		return eq
	case "~~", "~~*":
		return like
	default:
		return nil
	}
}

func operatorName(name []*pg.Node) string {
	if len(name) != 1 {
		return ""
	}
	s := name[0].GetString_()
	if s == nil {
		return ""
	}
	return s.GetSval()
}

// columnName extracts the column name from a WHERE operand. It descends through
// a single-argument LOWER()/UPPER() call so that Keycloak's typical
// `LOWER(email) LIKE :p` pattern is recognized as a reference to `email`.
func columnName(n *pg.Node) string {
	if n == nil {
		return ""
	}
	if cr := n.GetColumnRef(); cr != nil {
		fields := cr.GetFields()
		if len(fields) == 0 {
			return ""
		}
		if s := fields[len(fields)-1].GetString_(); s != nil {
			return s.GetSval()
		}
		return ""
	}
	if fc := n.GetFuncCall(); fc != nil {
		fn := funcCallName(fc)
		if (strings.EqualFold(fn, "lower") || strings.EqualFold(fn, "upper")) && len(fc.GetArgs()) == 1 {
			return columnName(fc.GetArgs()[0])
		}
	}
	return ""
}

func funcCallName(fc *pg.FuncCall) string {
	parts := fc.GetFuncname()
	if len(parts) == 0 {
		return ""
	}
	last := parts[len(parts)-1]
	if s := last.GetString_(); s != nil {
		return s.GetSval()
	}
	return ""
}
