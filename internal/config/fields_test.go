package config

import (
	"testing"

	"github.com/cozystack/keycloak-kms-proxy/internal/crypto"
)

func TestDefaultColumns(t *testing.T) {
	t.Parallel()

	fs := Default()

	cases := []struct {
		table, column string
		wantScheme    crypto.Scheme
		wantLower     bool
	}{
		{TableUserEntity, "USERNAME", crypto.SchemeDeterministic, true},
		{TableUserEntity, "EMAIL", crypto.SchemeDeterministic, true},
		{TableUserEntity, "FIRST_NAME", crypto.SchemeNonDeterministic, false},
		{TableUserEntity, "LAST_NAME", crypto.SchemeNonDeterministic, false},
		{TableCredential, "SECRET_DATA", crypto.SchemeNonDeterministic, false},
		{TableCredential, "CREDENTIAL_DATA", crypto.SchemeNonDeterministic, false},
	}
	for _, tc := range cases {
		rule, ok := fs.ColumnRule(tc.table, tc.column)
		if !ok {
			t.Errorf("%s.%s: not in default field set", tc.table, tc.column)
			continue
		}
		if rule.Scheme != tc.wantScheme {
			t.Errorf("%s.%s scheme: got %v, want %v", tc.table, tc.column, rule.Scheme, tc.wantScheme)
		}
		if rule.LowercaseNormalize != tc.wantLower {
			t.Errorf("%s.%s lowercase: got %v, want %v", tc.table, tc.column, rule.LowercaseNormalize, tc.wantLower)
		}
	}
}

func TestDefaultNonPIIColumns(t *testing.T) {
	t.Parallel()

	fs := Default()
	for _, col := range []struct{ table, column string }{
		{TableUserEntity, "ID"},
		{TableUserEntity, "REALM_ID"},
		{"REALM", "NAME"},
	} {
		if _, ok := fs.ColumnRule(col.table, col.column); ok {
			t.Errorf("%s.%s unexpectedly encrypted", col.table, col.column)
		}
	}
}

func TestDefaultAttributeRule(t *testing.T) {
	t.Parallel()

	fs := Default()

	// A pii- attribute encrypts its value columns non-deterministically; the
	// LONG_VALUE_HASH blind index is intentionally left out.
	rule, valueCols, ok := fs.AttributeRule(TableUserAttribute, "pii-ssn")
	if !ok {
		t.Fatal("pii- attribute not encrypted")
	}
	if rule.Scheme != crypto.SchemeNonDeterministic {
		t.Errorf("attribute scheme: got %v, want non-deterministic", rule.Scheme)
	}
	wantCols := map[string]bool{"VALUE": true, "LONG_VALUE": true}
	if len(valueCols) != len(wantCols) {
		t.Fatalf("value columns: got %v, want VALUE+LONG_VALUE", valueCols)
	}
	for _, c := range valueCols {
		if !wantCols[c] {
			t.Errorf("unexpected value column %q", c)
		}
		if c == "LONG_VALUE_HASH" {
			t.Error("LONG_VALUE_HASH must not be encrypted")
		}
	}

	// A non-pii attribute is left untouched.
	if _, _, ok := fs.AttributeRule(TableUserAttribute, "phone"); ok {
		t.Error("non-pii attribute unexpectedly encrypted")
	}
	// Attribute rules do not apply to arbitrary tables.
	if _, _, ok := fs.AttributeRule("REALM_ATTRIBUTE", "pii-x"); ok {
		t.Error("attribute rule leaked to an unrelated table")
	}
}

func TestExtensibility(t *testing.T) {
	t.Parallel()

	fs := New()
	if _, ok := fs.ColumnRule(TableUserEntity, "EMAIL"); ok {
		t.Fatal("New() should start empty")
	}
	fs.SetColumn("FEDERATED_IDENTITY", "TOKEN", Rule{Scheme: crypto.SchemeNonDeterministic})
	rule, ok := fs.ColumnRule("FEDERATED_IDENTITY", "TOKEN")
	if !ok || rule.Scheme != crypto.SchemeNonDeterministic {
		t.Fatalf("SetColumn did not register the rule: ok=%v rule=%+v", ok, rule)
	}
}
