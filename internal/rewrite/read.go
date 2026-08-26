package rewrite

import "strings"

// ReadField identifies a result-set field (0-based index, matching the
// RowDescription / DataRow order) that may carry an encrypted value to decrypt
// on the read path. Decryption itself is marker-driven — the
// scheme and key version come from the value's envelope — so a field needs only
// its column context to reconstruct the associated data.
type ReadField struct {
	Index  int
	Table  string
	Column string
}

// ReadPlan is the decrypt-on-DataRow plan for a result set.
type ReadPlan struct {
	Fields []ReadField
}

// IsEmpty reports whether no result field needs decryption.
func (rp *ReadPlan) IsEmpty() bool { return len(rp.Fields) == 0 }

// PlanRead maps a query's result columns (learned from RowDescription, in
// order) to the fields that may need decryption, given the relations the
// statement reads from. A field is included when exactly one of those
// relations configures it as a PII column or an attribute value column;
// non-encrypted rows pass through harmlessly because decryption is
// marker-driven. A statement with no known relation yields an empty plan.
func (p *Planner) PlanRead(tables []string, columns []string) *ReadPlan {
	plan := &ReadPlan{}
	if len(tables) == 0 {
		return plan
	}
	for i, col := range columns {
		c := strings.ToUpper(col)
		if owner, ok := p.columnOwner(tables, c); ok {
			plan.Fields = append(plan.Fields, ReadField{Index: i, Table: owner, Column: c})
		}
	}
	return plan
}

// columnOwner reports which of the statement's relations configures the result
// column as PII. A column claimed by two joined relations is ambiguous: the
// associated data binds a ciphertext to one specific table, so decrypting under
// the wrong one fails the authentication tag and errors the query. Leave those
// alone — the read-path leak detector flags them instead.
func (p *Planner) columnOwner(tables []string, column string) (string, bool) {
	owner := ""
	for _, t := range tables {
		t = strings.ToUpper(t)
		if t == "" || !p.isReadablePIIColumn(t, column) {
			continue
		}
		if owner != "" && owner != t {
			return "", false
		}
		owner = t
	}
	return owner, owner != ""
}

func (p *Planner) isReadablePIIColumn(table, column string) bool {
	if _, ok := p.fields.ColumnRule(table, column); ok {
		return true
	}
	pol, ok := p.fields.AttributePolicyFor(table)
	if !ok {
		return false
	}
	for _, vc := range pol.ValueColumns {
		if strings.ToUpper(vc) == column {
			return true
		}
	}
	return false
}
