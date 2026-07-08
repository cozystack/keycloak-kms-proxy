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
	// Table is the target table (INSERT/UPDATE/DELETE) or the first FROM table
	// (SELECT). Empty if no single table applies.
	Table string
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
// order. The backend answers each statement with its own result cycle, so the
// wire layer needs one result-queue entry per statement to stay in sync.
func AnalyzeAll(sql string) ([]*Analysis, error) {
	result, err := pg.Parse(sql)
	if err != nil {
		return nil, fmt.Errorf("rewrite: parse: %w", err)
	}
	stmts := result.GetStmts()
	analyses := make([]*Analysis, 0, len(stmts))
	for _, st := range stmts {
		analyses = append(analyses, analyzeNode(st.GetStmt()))
	}
	return analyses, nil
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
	a.FilterColumns, a.LikeFilterColumns = whereColumns(sel.GetWhereClause())
	return a
}

func analyzeDelete(del *pg.DeleteStmt) *Analysis {
	a := &Analysis{Kind: KindDelete, Table: del.GetRelation().GetRelname()}
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
