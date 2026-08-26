package rewrite

import "testing"

// FromTables is what lets the read planner decrypt a result set the backend
// assembled from more than one relation. A join's first FROM item is the join
// expression, not a range variable, so `Table` is empty for it — the
// group-members listing leaked every USER_ENTITY column on stage for exactly
// that reason.

func eqTables(got, want []string) bool {
	if len(got) != len(want) {
		return false
	}
	for i := range got {
		if got[i] != want[i] {
			return false
		}
	}
	return true
}

func TestAnalyzeFromTablesJoin(t *testing.T) {
	t.Parallel()

	a, err := Analyze(`select u.EMAIL from USER_GROUP_MEMBERSHIP m join USER_ENTITY u on u.ID=m.USER_ID where m.GROUP_ID=$1`)
	if err != nil {
		t.Fatalf("Analyze: %v", err)
	}
	if a.Table != "" {
		t.Errorf("table: got %q, want empty for a join", a.Table)
	}
	if want := []string{"user_group_membership", "user_entity"}; !eqTables(a.FromTables, want) {
		t.Errorf("from tables: got %v, want %v", a.FromTables, want)
	}
}

func TestAnalyzeFromTablesNestedJoin(t *testing.T) {
	t.Parallel()

	a, err := Analyze(`select u.EMAIL from FEDERATED_IDENTITY f join USER_ENTITY u on u.ID=f.USER_ID ` +
		`left join USER_ATTRIBUTE at on at.USER_ID=u.ID where f.FEDERATED_USER_ID=$1`)
	if err != nil {
		t.Fatalf("Analyze: %v", err)
	}
	want := []string{"federated_identity", "user_entity", "user_attribute"}
	if !eqTables(a.FromTables, want) {
		t.Errorf("from tables: got %v, want %v", a.FromTables, want)
	}
}

func TestAnalyzeFromTablesCommaJoin(t *testing.T) {
	t.Parallel()

	a, err := Analyze(`select u.EMAIL from USER_ENTITY u, USER_ATTRIBUTE at where at.USER_ID=u.ID`)
	if err != nil {
		t.Fatalf("Analyze: %v", err)
	}
	if want := []string{"user_entity", "user_attribute"}; !eqTables(a.FromTables, want) {
		t.Errorf("from tables: got %v, want %v", a.FromTables, want)
	}
}

func TestAnalyzeFromTablesSubselect(t *testing.T) {
	t.Parallel()

	a, err := Analyze(`select x.EMAIL from (select ue.EMAIL from USER_ENTITY ue) x`)
	if err != nil {
		t.Fatalf("Analyze: %v", err)
	}
	if want := []string{"user_entity"}; !eqTables(a.FromTables, want) {
		t.Errorf("from tables: got %v, want %v", a.FromTables, want)
	}
}

func TestAnalyzeFromTablesSetOperation(t *testing.T) {
	t.Parallel()

	a, err := Analyze(`select EMAIL from USER_ENTITY union all select FEDERATED_USERNAME from FEDERATED_IDENTITY`)
	if err != nil {
		t.Fatalf("Analyze: %v", err)
	}
	if want := []string{"user_entity", "federated_identity"}; !eqTables(a.FromTables, want) {
		t.Errorf("from tables: got %v, want %v", a.FromTables, want)
	}
}

func TestAnalyzeFromTablesDeduplicatesSelfJoin(t *testing.T) {
	t.Parallel()

	a, err := Analyze(`select a.EMAIL from USER_ENTITY a join USER_ENTITY b on b.ID=a.FEDERATION_LINK`)
	if err != nil {
		t.Fatalf("Analyze: %v", err)
	}
	if want := []string{"user_entity"}; !eqTables(a.FromTables, want) {
		t.Errorf("from tables: got %v, want %v", a.FromTables, want)
	}
}

func TestAnalyzeFromTablesOnWrites(t *testing.T) {
	t.Parallel()

	for _, sql := range []string{
		`UPDATE user_entity SET email = $1 WHERE id = $2`,
		`INSERT INTO user_entity (id, email) VALUES ($1, $2)`,
		`DELETE FROM user_entity WHERE id = $1`,
	} {
		a, err := Analyze(sql)
		if err != nil {
			t.Fatalf("Analyze(%s): %v", sql, err)
		}
		if want := []string{"user_entity"}; !eqTables(a.FromTables, want) {
			t.Errorf("%s: from tables got %v, want %v", sql, a.FromTables, want)
		}
	}
}
