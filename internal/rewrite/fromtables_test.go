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

// TestAnalyzeFromTablesCTE: a CTE alias is not a base relation. `FROM m` must
// resolve to the relations the CTE's query reads (USER_ENTITY), never report
// the alias `m` — which would leave the read planner unable to decrypt and
// (worse) misrepresent what the statement actually touches.
func TestAnalyzeFromTablesCTE(t *testing.T) {
	t.Parallel()

	a, err := Analyze(`with m as (select ue.EMAIL from USER_ENTITY ue) select x.EMAIL from m x`)
	if err != nil {
		t.Fatalf("Analyze: %v", err)
	}
	if want := []string{"user_entity"}; !eqTables(a.FromTables, want) {
		t.Errorf("from tables: got %v, want %v (CTE alias must resolve to its base relation)", a.FromTables, want)
	}
}

// TestAnalyzeFromTablesCTEJoinedWithBase: a CTE reference joined with a real
// relation resolves the CTE to its underlying table and keeps the base table,
// in order, without the alias.
func TestAnalyzeFromTablesCTEJoinedWithBase(t *testing.T) {
	t.Parallel()

	a, err := Analyze(`with m as (select fue.USER_ID from FED_USER_ENTITY fue) ` +
		`select u.EMAIL from USER_ENTITY u join m on m.USER_ID=u.ID`)
	if err != nil {
		t.Fatalf("Analyze: %v", err)
	}
	if want := []string{"user_entity", "fed_user_entity"}; !eqTables(a.FromTables, want) {
		t.Errorf("from tables: got %v, want %v", a.FromTables, want)
	}
}

// TestAnalyzeFromTablesRecursiveCTETerminates: a WITH RECURSIVE self-reference
// must not send the walker into an infinite loop.
func TestAnalyzeFromTablesRecursiveCTETerminates(t *testing.T) {
	t.Parallel()

	a, err := Analyze(`with recursive m as (select ue.ID from USER_ENTITY ue union all select ue2.ID from USER_ENTITY ue2 join m on m.ID=ue2.ID) select ID from m`)
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
