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
	// Fields are the result fields to decrypt, each resolved to exactly one
	// owning relation.
	Fields []ReadField
	// Ambiguous lists result fields whose column is configured as PII by more
	// than one of the statement's relations. The proxy cannot tell which
	// relation's associated data sealed the value, so it will not decrypt them
	// (guessing wrong fails the authentication tag and errors the whole query).
	// They are carried here rather than dropped so DecryptDataRow can count and
	// warn on any raw envelope they still carry: in a join where another column
	// resolves, the plan is non-empty and the whole-row empty-plan leak
	// detector never fires, so an ambiguous skip would otherwise be silent.
	Ambiguous []ReadField
}

// IsEmpty reports whether the plan has nothing to act on — no field to decrypt
// and none left ambiguous to account for.
func (rp *ReadPlan) IsEmpty() bool { return len(rp.Fields) == 0 && len(rp.Ambiguous) == 0 }

// PlanRead maps a query's result columns (learned from RowDescription, in
// order) to the fields that may need decryption, given the relations the
// statement reads from. A field is decrypted when exactly one of those
// relations configures it as a PII column or an attribute value column;
// non-encrypted rows pass through harmlessly because decryption is
// marker-driven. A column claimed by more than one relation is recorded as
// ambiguous instead. A statement with no known relation yields an empty plan.
func (p *Planner) PlanRead(tables []string, columns []string) *ReadPlan {
	plan := &ReadPlan{}
	if len(tables) == 0 {
		return plan
	}
	for i, col := range columns {
		c := strings.ToUpper(col)
		owner, ambiguous := p.columnOwner(tables, c)
		switch {
		case ambiguous:
			plan.Ambiguous = append(plan.Ambiguous, ReadField{Index: i, Column: c})
		case owner != "":
			plan.Fields = append(plan.Fields, ReadField{Index: i, Table: owner, Column: c})
		}
	}
	return plan
}

// columnOwner reports which of the statement's relations configures the result
// column as PII. It returns (owner, false) when exactly one relation claims it,
// ("", true) when more than one does — an ambiguous column the proxy cannot
// safely decrypt (the associated data binds a ciphertext to one specific table,
// so decrypting under the wrong one fails the authentication tag) — and
// ("", false) when none do.
func (p *Planner) columnOwner(tables []string, column string) (owner string, ambiguous bool) {
	for _, t := range tables {
		t = strings.ToUpper(t)
		if t == "" || !p.isReadablePIIColumn(t, column) {
			continue
		}
		if owner != "" && owner != t {
			return "", true
		}
		owner = t
	}
	return owner, false
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
