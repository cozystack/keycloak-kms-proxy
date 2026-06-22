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
// order) to the fields that may need decryption, given the queried table. A
// field is included when it is a configured PII column or an attribute value
// column; non-encrypted rows pass through harmlessly because decryption is
// marker-driven. An unknown (empty) table yields an empty plan.
func (p *Planner) PlanRead(table string, columns []string) *ReadPlan {
	table = strings.ToUpper(table)
	plan := &ReadPlan{}
	if table == "" {
		return plan
	}
	for i, col := range columns {
		c := strings.ToUpper(col)
		if p.isReadablePIIColumn(table, c) {
			plan.Fields = append(plan.Fields, ReadField{Index: i, Table: table, Column: c})
		}
	}
	return plan
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
