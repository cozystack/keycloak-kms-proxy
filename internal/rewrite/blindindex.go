package rewrite

import (
	"fmt"
	"strings"

	pg "github.com/pganalyze/pg_query_go/v6"
)

// BlindIndexQuery rewrites `<col> LIKE $n` / `LOWER(<col>) LIKE $n` (and
// the ILIKE variants) in the WHERE clause to `<hash_col> = $n` for every
// (column → hash column) pair in mapping. The rewritten SQL replaces the
// statement's Parse.Query so the backend's prepared plan already filters on
// the hash column; the bound value is independently replaced by EncryptBind
// with HMAC(blind-index-key, normalized(plaintext)).
//
// mapping is keyed by the LOWER-cased column identifier as it appears in the
// SQL (PostgreSQL folds unquoted identifiers to lower case at parse time).
func BlindIndexQuery(sql string, mapping map[string]string) (string, error) {
	if len(mapping) == 0 {
		return sql, nil
	}
	tree, err := pg.Parse(sql)
	if err != nil {
		return "", fmt.Errorf("rewrite: parse: %w", err)
	}
	for _, stmt := range tree.GetStmts() {
		mutateWhere(stmt.GetStmt(), mapping)
	}
	out, err := pg.Deparse(tree)
	if err != nil {
		return "", fmt.Errorf("rewrite: deparse: %w", err)
	}
	return out, nil
}

func mutateWhere(node *pg.Node, mapping map[string]string) {
	if node == nil {
		return
	}
	if sel := node.GetSelectStmt(); sel != nil {
		mutateWhereClause(sel.WhereClause, mapping)
	}
	if upd := node.GetUpdateStmt(); upd != nil {
		mutateWhereClause(upd.WhereClause, mapping)
	}
	if del := node.GetDeleteStmt(); del != nil {
		mutateWhereClause(del.WhereClause, mapping)
	}
}

func mutateWhereClause(where *pg.Node, mapping map[string]string) {
	if where == nil {
		return
	}
	if be := where.GetBoolExpr(); be != nil {
		for _, arg := range be.Args {
			mutateWhereClause(arg, mapping)
		}
		return
	}
	ae := where.GetAExpr()
	if ae == nil {
		return
	}
	switch ae.GetKind() {
	case pg.A_Expr_Kind_AEXPR_LIKE, pg.A_Expr_Kind_AEXPR_ILIKE:
		// supported.
	default:
		return
	}
	col := columnRefIdent(ae.Lexpr)
	if col == "" {
		return
	}
	hashCol, ok := mapping[strings.ToLower(col)]
	if !ok {
		return
	}
	setColumnRef(ae.Lexpr, hashCol)
	// Replace LIKE/ILIKE with equality so the backend uses the hash index.
	if len(ae.Name) > 0 {
		if s := ae.Name[0].GetString_(); s != nil {
			s.Sval = "="
		}
	}
	ae.Kind = pg.A_Expr_Kind_AEXPR_OP
	// Unwrap pgjdbc's pg_catalog.like_escape($n, '') on the right operand so
	// the rewritten SQL reads `hash = $n` rather than calling the escape
	// helper.
	if ae.Rexpr != nil {
		if fc := ae.Rexpr.GetFuncCall(); fc != nil && isLikeEscape(fc) && len(fc.GetArgs()) >= 1 {
			ae.Rexpr.Node = fc.GetArgs()[0].Node
		}
	}
}

// columnRefIdent returns the column identifier of a WHERE operand, descending
// through a single-argument LOWER/UPPER. Empty if the operand is not a simple
// column reference the rewriter can transform.
func columnRefIdent(n *pg.Node) string {
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
		name := funcCallName(fc)
		if (strings.EqualFold(name, "lower") || strings.EqualFold(name, "upper")) && len(fc.GetArgs()) == 1 {
			return columnRefIdent(fc.GetArgs()[0])
		}
	}
	return ""
}

// setColumnRef rewrites the operand to a bare ColumnRef on hashCol, collapsing
// any LOWER/UPPER wrapping (the hash column already carries the normalized
// form). It mutates the oneof in place so the protobuf message lock is not
// copied.
func setColumnRef(n *pg.Node, hashCol string) {
	if n == nil {
		return
	}
	col := strings.ToLower(hashCol)
	n.Node = &pg.Node_ColumnRef{ColumnRef: &pg.ColumnRef{
		Fields: []*pg.Node{{Node: &pg.Node_String_{String_: &pg.String{Sval: col}}}},
	}}
}

// BlindIndexWriteSQL rewrites an INSERT or UPDATE so that every source column
// listed in writes is also persisted as a hash-column value. The returned
// map carries each source parameter to the freshly-allocated parameter number
// that the SQL now expects to carry the HMAC. For statement kinds the
// rewriter does not handle the SQL is returned unchanged with an empty map.
func BlindIndexWriteSQL(sql string, writes []BlindIndexWrite) (string, map[int]int, error) {
	if len(writes) == 0 {
		return sql, nil, nil
	}
	tree, err := pg.Parse(sql)
	if err != nil {
		return "", nil, fmt.Errorf("rewrite: parse: %w", err)
	}
	if len(tree.Stmts) != 1 {
		return "", nil, fmt.Errorf("rewrite: expected one statement, got %d", len(tree.Stmts))
	}
	stmt := tree.Stmts[0].Stmt

	maxParam := maxParamRef(stmt)
	allocs := make(map[int]int, len(writes))
	for i := range writes {
		maxParam++
		allocs[writes[i].SourceParam] = maxParam
	}

	switch {
	case stmt.GetInsertStmt() != nil:
		addInsertHashColumns(stmt.GetInsertStmt(), writes, allocs)
	case stmt.GetUpdateStmt() != nil:
		addUpdateHashAssignments(stmt.GetUpdateStmt(), writes, allocs)
	default:
		return sql, nil, nil
	}

	out, err := pg.Deparse(tree)
	if err != nil {
		return "", nil, fmt.Errorf("rewrite: deparse: %w", err)
	}
	return out, allocs, nil
}

func addInsertHashColumns(ins *pg.InsertStmt, writes []BlindIndexWrite, allocs map[int]int) {
	for _, w := range writes {
		ins.Cols = append(ins.Cols, &pg.Node{Node: &pg.Node_ResTarget{ResTarget: &pg.ResTarget{
			Name: strings.ToLower(w.HashColumn),
		}}})
	}
	sel := ins.GetSelectStmt().GetSelectStmt()
	if sel == nil || len(sel.GetValuesLists()) == 0 {
		return
	}
	list := sel.GetValuesLists()[0].GetList()
	for _, w := range writes {
		n := int32(allocs[w.SourceParam]) //nolint:gosec // param numbers are bounded.
		list.Items = append(list.Items, paramRefNode(n))
	}
}

func addUpdateHashAssignments(upd *pg.UpdateStmt, writes []BlindIndexWrite, allocs map[int]int) {
	for _, w := range writes {
		n := int32(allocs[w.SourceParam]) //nolint:gosec // param numbers are bounded.
		upd.TargetList = append(upd.TargetList, &pg.Node{Node: &pg.Node_ResTarget{ResTarget: &pg.ResTarget{
			Name: strings.ToLower(w.HashColumn),
			Val:  paramRefNode(n),
		}}})
	}
}

func paramRefNode(number int32) *pg.Node {
	return &pg.Node{Node: &pg.Node_ParamRef{ParamRef: &pg.ParamRef{Number: number}}}
}

// maxParamRef walks the AST and returns the largest $N seen. Used to allocate
// new parameter numbers without colliding with the original SQL.
func maxParamRef(node *pg.Node) int {
	maxNum := 0
	var walk func(n *pg.Node)
	walk = func(n *pg.Node) {
		if n == nil {
			return
		}
		if pr := n.GetParamRef(); pr != nil {
			if int(pr.GetNumber()) > maxNum {
				maxNum = int(pr.GetNumber())
			}
		}
		if ins := n.GetInsertStmt(); ins != nil {
			walk(ins.GetSelectStmt())
		}
		if upd := n.GetUpdateStmt(); upd != nil {
			for _, t := range upd.GetTargetList() {
				walk(t.GetResTarget().GetVal())
			}
			walk(upd.WhereClause)
		}
		if sel := n.GetSelectStmt(); sel != nil {
			for _, vl := range sel.GetValuesLists() {
				for _, item := range vl.GetList().GetItems() {
					walk(item)
				}
			}
			for _, t := range sel.GetTargetList() {
				walk(t.GetResTarget().GetVal())
			}
			walk(sel.WhereClause)
		}
		if be := n.GetBoolExpr(); be != nil {
			for _, arg := range be.GetArgs() {
				walk(arg)
			}
		}
		if ae := n.GetAExpr(); ae != nil {
			walk(ae.Lexpr)
			walk(ae.Rexpr)
		}
	}
	walk(node)
	return maxNum
}
