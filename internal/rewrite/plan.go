package rewrite

import (
	"errors"
	"fmt"
	"strings"

	"github.com/cozystack/keycloak-kms-proxy/internal/config"
	"github.com/cozystack/keycloak-kms-proxy/internal/crypto"
)

// Fail-loud errors: rather than silently storing or searching PII as plaintext,
// the proxy refuses statements it cannot transparently transform.
var (
	// ErrUnencryptablePII means a PII value is not a bound parameter (a literal),
	// so the proxy cannot encrypt it without rewriting the SQL text.
	ErrUnencryptablePII = errors.New("rewrite: PII value is not a bound parameter")
	// ErrUnsearchablePII means a non-deterministically encrypted PII column is
	// used in an equality filter, which can never match stored ciphertext.
	ErrUnsearchablePII = errors.New("rewrite: non-deterministic PII column cannot be equality-searched")
)

// ParamRule directs the wire layer to encrypt the value bound at Param (1-based)
// under Rule, using the column context as associated data.
type ParamRule struct {
	Param  int
	Table  string
	Column string
	Rule   config.Rule
}

// AttributeCondition encrypts an attribute row's value parameters only when the
// attribute name bound at NameParam starts with Prefix. The
// condition is evaluated at Bind time, where the name value is known.
type AttributeCondition struct {
	NameParam   int
	Prefix      string
	ValueParams []ParamRule
}

// WritePlan is the encrypt-on-Bind plan for a statement: the
// parameters to encrypt unconditionally, attribute conditions evaluated against
// bound name values, LIKE filters on deterministic PII columns whose bound
// value is encrypted only when it carries no wildcards, and
// blind-index LIKE filters that rewrite the SQL to query a shadow hash column.
type WritePlan struct {
	Params              []ParamRule
	AttributeConditions []AttributeCondition
	LikeParams          []ParamRule
	BlindIndexFilters   []BlindIndexFilter
	BlindIndexWrites    []BlindIndexWrite
}

// BlindIndexFilter directs the wire layer to rewrite a `<col> LIKE $n` filter
// to `<hash_col> = $n` (Parse SQL mutation) and to replace the bound value at
// Param with HMAC(blind-index-key, normalized(plaintext)) at Bind time. The
// SQL rewrite happens at Parse so the backend's prepared statement plan
// already references the hash column.
type BlindIndexFilter struct {
	Param      int
	Table      string
	Column     string
	HashColumn string
}

// BlindIndexWrite directs the wire layer to also populate a shadow hash column
// alongside its source PII column on INSERT/UPDATE. On Parse the SQL is
// rewritten to append `, <hash_col>` (INSERT) or `, <hash_col> = $K` (UPDATE);
// on Bind the bound value at SourceParam is HMAC-ed *before* it is encrypted,
// and the hash is appended as the new parameter NewParam. NewParam is left
// zero by the planner and filled in by the SQL rewriter.
type BlindIndexWrite struct {
	SourceParam int
	NewParam    int
	Table       string
	Column      string
	HashColumn  string
}

// IsEmpty reports whether the plan transforms nothing (pure passthrough).
func (wp *WritePlan) IsEmpty() bool {
	return len(wp.Params) == 0 &&
		len(wp.AttributeConditions) == 0 &&
		len(wp.LikeParams) == 0 &&
		len(wp.BlindIndexFilters) == 0 &&
		len(wp.BlindIndexWrites) == 0
}

// Planner maps parsed statements to encryption plans against a field set.
// When lenient is true the fail-loud rules become passthroughs: a PII column
// written or filtered with a non-parameter value (a literal or expression) is
// forwarded unencrypted instead of refusing the statement. This is needed to
// let historical Liquibase data-migration UPDATEs run on a fresh database
// (they target rows that do not exist yet) and must be turned off in steady
// state.
type Planner struct {
	fields  *config.FieldSet
	lenient bool
}

// NewPlanner returns a strict Planner for the given field set.
func NewPlanner(fields *config.FieldSet) *Planner {
	return &Planner{fields: fields}
}

// NewLenientPlanner returns a Planner whose fail-loud rules become
// passthroughs, for Keycloak's Liquibase bootstrap window.
func NewLenientPlanner(fields *config.FieldSet) *Planner {
	return &Planner{fields: fields, lenient: true}
}

// AAD returns the associated data binding a ciphertext to its column context.
// Write and read paths must derive it identically for decryption to verify and
// for deterministic search to match.
func AAD(table, column string) []byte {
	return []byte(strings.ToUpper(table) + "." + strings.ToUpper(column))
}

// PlanWrite computes the encrypt-on-Bind plan for a statement: PII columns being
// written (INSERT/UPDATE) and deterministic PII columns being equality-searched
// (WHERE). It fails loudly when a PII value cannot be transparently encrypted.
func (p *Planner) PlanWrite(a *Analysis) (*WritePlan, error) {
	table := strings.ToUpper(a.Table)
	plan := &WritePlan{}

	if err := p.planWrittenColumns(table, a, plan); err != nil {
		return nil, err
	}
	if err := p.planFilteredColumns(table, a, plan); err != nil {
		return nil, err
	}
	p.planLikeFilteredColumns(table, a, plan)
	if err := p.planAttributes(table, a, plan); err != nil {
		return nil, err
	}
	return plan, nil
}

// planLikeFilteredColumns handles LIKE/ILIKE filters on deterministic PII
// columns: the proxy emits a deferred encryption rule that EncryptBind
// applies at Bind time only when the bound value carries no wildcards.
// Non-deterministic columns and literal-valued LIKE filters are not actionable
// here; they pass through unchanged (the search simply will not match
// ciphertext rows — same as today).
func (p *Planner) planLikeFilteredColumns(table string, a *Analysis, plan *WritePlan) {
	for _, fc := range a.LikeFilterColumns {
		col := strings.ToUpper(fc.Column)
		rule, ok := p.fields.ColumnRule(table, col)
		if !ok {
			continue
		}
		if rule.Scheme != crypto.SchemeDeterministic || fc.Param == 0 {
			continue
		}
		if rule.BlindIndex != "" {
			plan.BlindIndexFilters = append(plan.BlindIndexFilters, BlindIndexFilter{
				Param: fc.Param, Table: table, Column: col, HashColumn: rule.BlindIndex,
			})
			continue
		}
		plan.LikeParams = append(plan.LikeParams, ParamRule{Param: fc.Param, Table: table, Column: col, Rule: rule})
	}
}

func (p *Planner) planWrittenColumns(table string, a *Analysis, plan *WritePlan) error {
	for _, wc := range a.WriteColumns {
		col := strings.ToUpper(wc.Column)
		rule, ok := p.fields.ColumnRule(table, col)
		if !ok {
			continue
		}
		if wc.Param == 0 {
			if p.lenient {
				continue
			}
			return fmt.Errorf("%w: %s.%s written as a literal", ErrUnencryptablePII, table, col)
		}
		plan.Params = append(plan.Params, ParamRule{Param: wc.Param, Table: table, Column: col, Rule: rule})
		if rule.BlindIndex != "" {
			plan.BlindIndexWrites = append(plan.BlindIndexWrites, BlindIndexWrite{
				SourceParam: wc.Param, Table: table, Column: col, HashColumn: rule.BlindIndex,
			})
		}
	}
	return nil
}

func (p *Planner) planFilteredColumns(table string, a *Analysis, plan *WritePlan) error {
	for _, fc := range a.FilterColumns {
		col := strings.ToUpper(fc.Column)
		rule, ok := p.fields.ColumnRule(table, col)
		if !ok {
			continue
		}
		if rule.Scheme != crypto.SchemeDeterministic {
			if p.lenient {
				continue
			}
			return fmt.Errorf("%w: %s.%s", ErrUnsearchablePII, table, col)
		}
		if fc.Param == 0 {
			if p.lenient {
				continue
			}
			return fmt.Errorf("%w: %s.%s filtered by a literal", ErrUnencryptablePII, table, col)
		}
		plan.Params = append(plan.Params, ParamRule{Param: fc.Param, Table: table, Column: col, Rule: rule})
	}
	return nil
}

func (p *Planner) planAttributes(table string, a *Analysis, plan *WritePlan) error {
	pol, ok := p.fields.AttributePolicyFor(table)
	if !ok {
		return nil
	}
	valueCols := upperSet(pol.ValueColumns)

	var valueParams []ParamRule
	for _, wc := range a.WriteColumns {
		col := strings.ToUpper(wc.Column)
		if !valueCols[col] {
			continue
		}
		if wc.Param == 0 {
			if p.lenient {
				continue
			}
			return fmt.Errorf("%w: %s.%s written as a literal", ErrUnencryptablePII, table, col)
		}
		valueParams = append(valueParams, ParamRule{Param: wc.Param, Table: table, Column: col, Rule: pol.Rule})
	}
	if len(valueParams) == 0 {
		return nil
	}

	nameParam := paramForColumn(a, strings.ToUpper(pol.NameColumn))
	if nameParam == 0 {
		if p.lenient {
			return nil
		}
		return fmt.Errorf("%w: attribute write to %s without a bound name", ErrUnencryptablePII, table)
	}
	plan.AttributeConditions = append(plan.AttributeConditions, AttributeCondition{
		NameParam:   nameParam,
		Prefix:      pol.Prefix,
		ValueParams: valueParams,
	})
	return nil
}

func paramForColumn(a *Analysis, column string) int {
	for _, wc := range a.WriteColumns {
		if strings.ToUpper(wc.Column) == column {
			return wc.Param
		}
	}
	for _, fc := range a.FilterColumns {
		if strings.ToUpper(fc.Column) == column {
			return fc.Param
		}
	}
	return 0
}

func upperSet(cols []string) map[string]bool {
	set := make(map[string]bool, len(cols))
	for _, c := range cols {
		set[strings.ToUpper(c)] = true
	}
	return set
}
