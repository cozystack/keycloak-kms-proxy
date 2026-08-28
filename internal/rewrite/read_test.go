package rewrite

import (
	"testing"

	"github.com/cozystack/keycloak-kms-proxy/internal/config"
	"github.com/cozystack/keycloak-kms-proxy/internal/crypto"
)

func readFieldIndices(plan *ReadPlan) map[string]int {
	m := make(map[string]int, len(plan.Fields))
	for _, f := range plan.Fields {
		m[f.Column] = f.Index
	}
	return m
}

func TestPlanReadUserEntity(t *testing.T) {
	t.Parallel()

	p := NewPlanner(config.Default())
	plan := p.PlanRead([]string{"user_entity"}, []string{"id", "username", "email", "first_name"})

	got := readFieldIndices(plan)
	want := map[string]int{"USERNAME": 1, "EMAIL": 2, "FIRST_NAME": 3}
	if len(got) != len(want) {
		t.Fatalf("fields: got %+v, want %v", plan.Fields, want)
	}
	for col, idx := range want {
		if got[col] != idx {
			t.Errorf("%s index: got %d, want %d", col, got[col], idx)
		}
	}
	if _, ok := got["ID"]; ok {
		t.Error("id must not be a decrypt field")
	}
}

func TestPlanReadUppercaseColumns(t *testing.T) {
	t.Parallel()

	p := NewPlanner(config.Default())
	plan := p.PlanRead([]string{"USER_ENTITY"}, []string{"EMAIL"})
	if len(plan.Fields) != 1 || plan.Fields[0].Column != "EMAIL" || plan.Fields[0].Index != 0 {
		t.Fatalf("uppercase columns not matched: %+v", plan.Fields)
	}
}

func TestPlanReadAttributeValues(t *testing.T) {
	t.Parallel()

	p := NewPlanner(config.Default())
	plan := p.PlanRead([]string{"user_attribute"}, []string{"name", "value", "long_value", "long_value_hash"})

	got := readFieldIndices(plan)
	// value and long_value may be encrypted; name and the hash never are.
	if got["VALUE"] != 1 || got["LONG_VALUE"] != 2 || len(got) != 2 {
		t.Fatalf("attribute read fields wrong: %+v", plan.Fields)
	}
	if _, ok := got["LONG_VALUE_HASH"]; ok {
		t.Error("LONG_VALUE_HASH must not be decrypted")
	}
}

func TestPlanReadNonPIITableEmpty(t *testing.T) {
	t.Parallel()

	p := NewPlanner(config.Default())
	if plan := p.PlanRead([]string{"realm"}, []string{"id", "name"}); !plan.IsEmpty() {
		t.Fatalf("non-PII table produced read fields: %+v", plan.Fields)
	}
}

func TestPlanReadUnknownTableEmpty(t *testing.T) {
	t.Parallel()

	p := NewPlanner(config.Default())
	if plan := p.PlanRead(nil, []string{"email"}); !plan.IsEmpty() {
		t.Fatalf("unknown table produced read fields: %+v", plan.Fields)
	}
}

// TestPlanReadJoinedTables is the group-members read: the join brings in a
// relation with no PII of its own, and every PII column must still resolve to
// USER_ENTITY so the AAD matches what the write path used.
func TestPlanReadJoinedTables(t *testing.T) {
	t.Parallel()

	p := NewPlanner(config.Default())
	plan := p.PlanRead(
		[]string{"user_group_membership", "user_entity"},
		[]string{"id", "email", "first_name", "last_name", "username"},
	)

	got := readFieldIndices(plan)
	want := map[string]int{"EMAIL": 1, "FIRST_NAME": 2, "LAST_NAME": 3, "USERNAME": 4}
	if len(got) != len(want) {
		t.Fatalf("fields: got %+v, want %v", plan.Fields, want)
	}
	for col, idx := range want {
		if got[col] != idx {
			t.Errorf("%s index: got %d, want %d", col, got[col], idx)
		}
	}
	for _, f := range plan.Fields {
		if f.Table != "USER_ENTITY" {
			t.Errorf("%s resolved to table %q, want USER_ENTITY", f.Column, f.Table)
		}
	}
}

// TestPlanReadAmbiguousColumnSkipped: when two joined relations both configure
// the same column, the proxy cannot tell which AAD the value was sealed with.
// Guessing would fail the authentication tag and error the whole query, so the
// field is not decrypted — but it is carried in plan.Ambiguous (not silently
// dropped) so DecryptDataRow can count and warn on any envelope it still holds.
func TestPlanReadAmbiguousColumnSkipped(t *testing.T) {
	t.Parallel()

	fs := config.New()
	rule := config.Rule{Scheme: crypto.SchemeNonDeterministic}
	fs.SetColumn("USER_ENTITY", "EMAIL", rule)
	fs.SetColumn("FED_USER_ENTITY", "EMAIL", rule)

	p := NewPlanner(fs)
	plan := p.PlanRead([]string{"user_entity", "fed_user_entity"}, []string{"email"})
	if len(plan.Fields) != 0 {
		t.Fatalf("ambiguous column decrypted anyway: %+v", plan.Fields)
	}
	if len(plan.Ambiguous) != 1 || plan.Ambiguous[0].Column != "EMAIL" || plan.Ambiguous[0].Index != 0 {
		t.Fatalf("ambiguous column not carried through the plan: %+v", plan.Ambiguous)
	}
	if plan.IsEmpty() {
		t.Fatal("plan with an ambiguous field reports empty; the leak detector would never see it")
	}
	// Unambiguous on its own.
	if plan := p.PlanRead([]string{"user_entity"}, []string{"email"}); len(plan.Fields) != 1 || len(plan.Ambiguous) != 0 {
		t.Fatalf("single-table read lost its field or misclassified it: %+v", plan)
	}
}
