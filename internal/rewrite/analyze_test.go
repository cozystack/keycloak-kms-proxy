package rewrite

import "testing"

func eqColumnParams(got []ColumnParam, want map[string]int) bool {
	if len(got) != len(want) {
		return false
	}
	for _, cp := range got {
		if w, ok := want[cp.Column]; !ok || w != cp.Param {
			return false
		}
	}
	return true
}

func TestAnalyzeInsert(t *testing.T) {
	t.Parallel()

	a, err := Analyze(`INSERT INTO user_entity (id, username, email, realm_id) VALUES ($1, $2, $3, $4)`)
	if err != nil {
		t.Fatalf("Analyze: %v", err)
	}
	if a.Kind != KindInsert {
		t.Errorf("kind: got %v, want INSERT", a.Kind)
	}
	if a.Table != "user_entity" {
		t.Errorf("table: got %q", a.Table)
	}
	want := map[string]int{"id": 1, "username": 2, "email": 3, "realm_id": 4}
	if !eqColumnParams(a.WriteColumns, want) {
		t.Errorf("write columns: got %+v, want %v", a.WriteColumns, want)
	}
	if len(a.FilterColumns) != 0 {
		t.Errorf("filter columns: got %+v, want none", a.FilterColumns)
	}
}

func TestAnalyzeInsertLiteralValue(t *testing.T) {
	t.Parallel()

	a, err := Analyze(`INSERT INTO user_entity (username) VALUES ('alice')`)
	if err != nil {
		t.Fatalf("Analyze: %v", err)
	}
	// A literal (non-parameter) value maps to param position 0.
	if !eqColumnParams(a.WriteColumns, map[string]int{"username": 0}) {
		t.Errorf("write columns: got %+v", a.WriteColumns)
	}
}

func TestAnalyzeUpdate(t *testing.T) {
	t.Parallel()

	a, err := Analyze(`UPDATE user_entity SET email = $1, first_name = $2 WHERE id = $3`)
	if err != nil {
		t.Fatalf("Analyze: %v", err)
	}
	if a.Kind != KindUpdate || a.Table != "user_entity" {
		t.Errorf("kind/table: got %v/%q", a.Kind, a.Table)
	}
	if !eqColumnParams(a.WriteColumns, map[string]int{"email": 1, "first_name": 2}) {
		t.Errorf("write columns: got %+v", a.WriteColumns)
	}
	if !eqColumnParams(a.FilterColumns, map[string]int{"id": 3}) {
		t.Errorf("filter columns: got %+v", a.FilterColumns)
	}
}

func TestAnalyzeSelect(t *testing.T) {
	t.Parallel()

	a, err := Analyze(`SELECT id, username, email FROM user_entity WHERE username = $1 AND realm_id = $2`)
	if err != nil {
		t.Fatalf("Analyze: %v", err)
	}
	if a.Kind != KindSelect || a.Table != "user_entity" {
		t.Errorf("kind/table: got %v/%q", a.Kind, a.Table)
	}
	if !eqColumnParams(a.FilterColumns, map[string]int{"username": 1, "realm_id": 2}) {
		t.Errorf("filter columns: got %+v", a.FilterColumns)
	}
}

func TestAnalyzeSelectQualifiedAndReversed(t *testing.T) {
	t.Parallel()

	// Qualified column (u.email) and reversed operand order ($1 = u.email).
	a, err := Analyze(`SELECT u.id FROM user_entity u WHERE $1 = u.email`)
	if err != nil {
		t.Fatalf("Analyze: %v", err)
	}
	if !eqColumnParams(a.FilterColumns, map[string]int{"email": 1}) {
		t.Errorf("filter columns: got %+v", a.FilterColumns)
	}
}

func TestAnalyzeDelete(t *testing.T) {
	t.Parallel()

	a, err := Analyze(`DELETE FROM user_entity WHERE id = $1`)
	if err != nil {
		t.Fatalf("Analyze: %v", err)
	}
	if a.Kind != KindDelete || a.Table != "user_entity" {
		t.Errorf("kind/table: got %v/%q", a.Kind, a.Table)
	}
	if !eqColumnParams(a.FilterColumns, map[string]int{"id": 1}) {
		t.Errorf("filter columns: got %+v", a.FilterColumns)
	}
}

func TestAnalyzeLikeFilters(t *testing.T) {
	t.Parallel()

	// LIKE on a bare column and an ILIKE through LOWER() must both surface
	// in LikeFilterColumns, mapped to the underlying column name.
	a, err := Analyze(`SELECT id FROM user_entity WHERE email LIKE $1 AND LOWER(username) ILIKE $2`)
	if err != nil {
		t.Fatalf("Analyze: %v", err)
	}
	if len(a.FilterColumns) != 0 {
		t.Errorf("LIKE/ILIKE must not appear in equality FilterColumns: %+v", a.FilterColumns)
	}
	if !eqColumnParams(a.LikeFilterColumns, map[string]int{"email": 1, "username": 2}) {
		t.Errorf("like filters: got %+v", a.LikeFilterColumns)
	}
}

func TestAnalyzeLowerEqualityFilter(t *testing.T) {
	t.Parallel()

	// LOWER(col) = $1 must be recognized as equality on the underlying column.
	a, err := Analyze(`SELECT id FROM user_entity WHERE LOWER(email) = $1`)
	if err != nil {
		t.Fatalf("Analyze: %v", err)
	}
	if !eqColumnParams(a.FilterColumns, map[string]int{"email": 1}) {
		t.Errorf("filter columns: got %+v", a.FilterColumns)
	}
}

func TestAnalyzeDDLIsOther(t *testing.T) {
	t.Parallel()

	// DDL/Liquibase statements are passed through untouched.
	a, err := Analyze(`CREATE TABLE user_entity (id varchar(36) PRIMARY KEY)`)
	if err != nil {
		t.Fatalf("Analyze: %v", err)
	}
	if a.Kind != KindOther {
		t.Errorf("kind: got %v, want OTHER", a.Kind)
	}
}

func TestAnalyzeErrors(t *testing.T) {
	t.Parallel()

	if _, err := Analyze(`this is not sql`); err == nil {
		t.Error("Analyze accepted invalid SQL")
	}
	if _, err := Analyze(`SELECT 1; SELECT 2`); err == nil {
		t.Error("Analyze accepted multiple statements")
	}
}
