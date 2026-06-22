package config

import (
	"sort"
	"strings"

	"github.com/cozystack/keycloak-kms-proxy/internal/crypto"
)

// Keycloak table names that hold PII.
const (
	TableUserEntity    = "USER_ENTITY"
	TableUserAttribute = "USER_ATTRIBUTE"
	TableCredential    = "CREDENTIAL"
)

// DefaultAttributePrefix marks custom user attributes as PII: any
// attribute whose name starts with this prefix has its value columns encrypted.
const DefaultAttributePrefix = "pii-"

// Rule is the encryption policy applied to a value: which scheme, whether to
// lower-case the plaintext before deterministic encryption, and
// the optional shadow blind-index column populated with
// HMAC(blind-index-key, normalized(plaintext)) so admin LIKE searches can be
// rewritten to an equality match on the hash column.
type Rule struct {
	Scheme             crypto.Scheme
	LowercaseNormalize bool
	BlindIndex         string
}

// ColumnKey identifies a database column.
type ColumnKey struct {
	Table  string
	Column string
}

// attrPolicy encrypts the value columns of attribute rows whose name column
// starts with prefix. The blind-index hash column is never listed:
// Keycloak computes it over plaintext, so the proxy must leave it alone.
type attrPolicy struct {
	nameColumn   string
	valueColumns []string
	prefix       string
	rule         Rule
}

// FieldSet is the configured set of encrypted fields. It is
// configurable; Default returns the built-in MLukman-compatible set. Use New
// for an empty set and the Set* methods to build a custom one.
type FieldSet struct {
	columns map[ColumnKey]Rule
	attrs   map[string]attrPolicy
}

// New returns an empty FieldSet.
func New() *FieldSet {
	return &FieldSet{
		columns: make(map[ColumnKey]Rule),
		attrs:   make(map[string]attrPolicy),
	}
}

// SetColumn registers an encryption rule for a fixed table column.
func (fs *FieldSet) SetColumn(table, column string, rule Rule) {
	fs.columns[ColumnKey{Table: table, Column: column}] = rule
}

// SetAttributePolicy registers a name-prefix rule for an attribute table: rows
// whose nameColumn value starts with prefix have their valueColumns encrypted.
func (fs *FieldSet) SetAttributePolicy(table, nameColumn string, valueColumns []string, prefix string, rule Rule) {
	fs.attrs[table] = attrPolicy{
		nameColumn:   nameColumn,
		valueColumns: valueColumns,
		prefix:       prefix,
		rule:         rule,
	}
}

// ColumnRuleEntry pairs a fixed column with its rule, for iteration (e.g. the
// backfill tool walks all configured PII columns).
type ColumnRuleEntry struct {
	Table  string
	Column string
	Rule   Rule
}

// Columns returns every fixed column rule, in deterministic order (table then
// column ascending).
func (fs *FieldSet) Columns() []ColumnRuleEntry {
	out := make([]ColumnRuleEntry, 0, len(fs.columns))
	for k, v := range fs.columns {
		out = append(out, ColumnRuleEntry{Table: k.Table, Column: k.Column, Rule: v})
	}
	sort.Slice(out, func(i, j int) bool {
		if out[i].Table != out[j].Table {
			return out[i].Table < out[j].Table
		}
		return out[i].Column < out[j].Column
	})
	return out
}

// ColumnRule returns the encryption rule for a fixed column, if any.
func (fs *FieldSet) ColumnRule(table, column string) (Rule, bool) {
	r, ok := fs.columns[ColumnKey{Table: table, Column: column}]
	return r, ok
}

// AttributeRule returns the rule and value columns to encrypt for an attribute
// row in table whose name matches the table's configured prefix.
func (fs *FieldSet) AttributeRule(table, attrName string) (Rule, []string, bool) {
	p, ok := fs.attrs[table]
	if !ok || !strings.HasPrefix(attrName, p.prefix) {
		return Rule{}, nil, false
	}
	return p.rule, p.valueColumns, true
}

// AttributeNameColumn returns the name column for an attribute table, so the
// rewrite layer knows which bound parameter carries the attribute name.
func (fs *FieldSet) AttributeNameColumn(table string) (string, bool) {
	p, ok := fs.attrs[table]
	if !ok {
		return "", false
	}
	return p.nameColumn, true
}

// AttributePolicy is a read-only view of a table's attribute encryption policy.
type AttributePolicy struct {
	NameColumn   string
	ValueColumns []string
	Prefix       string
	Rule         Rule
}

// AttributePolicyFor returns the attribute policy configured for a table.
func (fs *FieldSet) AttributePolicyFor(table string) (AttributePolicy, bool) {
	p, ok := fs.attrs[table]
	if !ok {
		return AttributePolicy{}, false
	}
	return AttributePolicy{
		NameColumn:   p.nameColumn,
		ValueColumns: append([]string(nil), p.valueColumns...),
		Prefix:       p.prefix,
		Rule:         p.rule,
	}, true
}

// Default returns the built-in MLukman-compatible field set:
// username/email (deterministic, lower-cased), first/last name
// (non-deterministic), pii- user attributes (non-deterministic), and the
// CREDENTIAL secret columns (non-deterministic, defense-in-depth).
func Default() *FieldSet {
	det := Rule{Scheme: crypto.SchemeDeterministic, LowercaseNormalize: true}
	nondet := Rule{Scheme: crypto.SchemeNonDeterministic}

	fs := New()
	fs.SetColumn(TableUserEntity, "USERNAME", det)
	fs.SetColumn(TableUserEntity, "EMAIL", det)
	fs.SetColumn(TableUserEntity, "FIRST_NAME", nondet)
	fs.SetColumn(TableUserEntity, "LAST_NAME", nondet)
	// CREDENTIAL.{SECRET_DATA,CREDENTIAL_DATA} (re-enabled
	// after the runtime SQL conformance corpus captured all read/write paths
	// Keycloak takes — see testdata/keycloak/26.0.0/runtime-sql.txt). Values
	// are non-deterministic (no equality search by value) — defense-in-depth
	// on top of BCrypt.
	fs.SetColumn(TableCredential, "SECRET_DATA", nondet)
	fs.SetColumn(TableCredential, "CREDENTIAL_DATA", nondet)
	fs.SetAttributePolicy(TableUserAttribute, "NAME", []string{"VALUE", "LONG_VALUE"}, DefaultAttributePrefix, nondet)
	return fs
}
