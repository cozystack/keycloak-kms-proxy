package keycloakmodel

import (
	"sort"
	"testing"
)

func TestKeycloak260Version(t *testing.T) {
	t.Parallel()

	if v := Keycloak260().Version; v != "26.0.0" {
		t.Fatalf("Version=%q, want 26.0.0", v)
	}
}

func TestEntitiesAndPIIColumns(t *testing.T) {
	t.Parallel()

	m := Keycloak260()
	cases := []struct {
		class string
		table string
		cols  []string
	}{
		{"UserEntity", "USER_ENTITY", []string{"EMAIL", "FIRST_NAME", "LAST_NAME", "USERNAME"}},
		{"UserAttributeEntity", "USER_ATTRIBUTE", []string{"LONG_VALUE", "VALUE"}},
		{"CredentialEntity", "CREDENTIAL", []string{"CREDENTIAL_DATA", "SECRET_DATA"}},
		{"FederatedIdentityEntity", "FEDERATED_IDENTITY", []string{"FEDERATED_USERNAME", "TOKEN"}},
		{"FederatedUserAttributeEntity", "FED_USER_ATTRIBUTE", []string{"LONG_VALUE", "VALUE"}},
		{"FederatedUserCredentialEntity", "FED_USER_CREDENTIAL", []string{"CREDENTIAL_DATA", "SECRET_DATA"}},
	}
	for _, tc := range cases {
		e, ok := m.Entity(tc.class)
		if !ok {
			t.Errorf("entity %s missing", tc.class)
			continue
		}
		if e.Table != tc.table {
			t.Errorf("%s table: got %q, want %q", tc.class, e.Table, tc.table)
		}
		got := append([]string(nil), e.PIIColumns...)
		sort.Strings(got)
		if len(got) != len(tc.cols) {
			t.Errorf("%s PII columns: got %v, want %v", tc.class, e.PIIColumns, tc.cols)
			continue
		}
		for i := range got {
			if got[i] != tc.cols[i] {
				t.Errorf("%s PII columns: got %v, want %v", tc.class, e.PIIColumns, tc.cols)
				break
			}
		}
	}
}

func TestLongValueHashIsNotPII(t *testing.T) {
	t.Parallel()

	// The blind index must never be in a PII column set.
	e, _ := Keycloak260().Entity("UserAttributeEntity")
	if e.IsPIIColumn("LONG_VALUE_HASH") {
		t.Fatal("LONG_VALUE_HASH must not be a PII column")
	}
	if !e.IsPIIColumn("VALUE") {
		t.Fatal("VALUE must be a PII column")
	}
}

func TestEntityByTable(t *testing.T) {
	t.Parallel()

	m := Keycloak260()
	if e, ok := m.EntityByTable("USER_ENTITY"); !ok || e.Class != "UserEntity" {
		t.Fatalf("EntityByTable(USER_ENTITY)=(%+v,%v)", e, ok)
	}
	if _, ok := m.EntityByTable("REALM"); ok {
		t.Fatal("EntityByTable found an unmodeled table")
	}
}

func TestNamedQueryPIIParams(t *testing.T) {
	t.Parallel()

	m := Keycloak260()
	cases := []struct {
		query     string
		piiParams map[string]string // param -> column
	}{
		{"getRealmUserByUsername", map[string]string{"username": "USERNAME"}},
		{"getRealmUserByEmail", map[string]string{"email": "EMAIL"}},
		{"getRealmUsersByAttributeNameAndValue", map[string]string{"value": "VALUE"}},
		// Long-value search goes through the untouched hash → no PII param.
		{"getRealmUsersByAttributeNameAndLongValue", map[string]string{}},
	}
	for _, tc := range cases {
		q, ok := m.Query(tc.query)
		if !ok {
			t.Errorf("query %s missing", tc.query)
			continue
		}
		pii := m.PIIParams(q)
		if len(pii) != len(tc.piiParams) {
			t.Errorf("%s PII params: got %v, want %v", tc.query, pii, tc.piiParams)
			continue
		}
		for _, p := range pii {
			if tc.piiParams[p.Param] != p.Column {
				t.Errorf("%s: param %q mapped to %q, want %q", tc.query, p.Param, p.Column, tc.piiParams[p.Param])
			}
		}
	}
}
