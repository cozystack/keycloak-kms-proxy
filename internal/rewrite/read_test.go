package rewrite

import (
	"testing"

	"github.com/cozystack/keycloak-kms-proxy/internal/config"
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
	plan := p.PlanRead("user_entity", []string{"id", "username", "email", "first_name"})

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
	plan := p.PlanRead("USER_ENTITY", []string{"EMAIL"})
	if len(plan.Fields) != 1 || plan.Fields[0].Column != "EMAIL" || plan.Fields[0].Index != 0 {
		t.Fatalf("uppercase columns not matched: %+v", plan.Fields)
	}
}

func TestPlanReadAttributeValues(t *testing.T) {
	t.Parallel()

	p := NewPlanner(config.Default())
	plan := p.PlanRead("user_attribute", []string{"name", "value", "long_value", "long_value_hash"})

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
	if plan := p.PlanRead("realm", []string{"id", "name"}); !plan.IsEmpty() {
		t.Fatalf("non-PII table produced read fields: %+v", plan.Fields)
	}
}

func TestPlanReadUnknownTableEmpty(t *testing.T) {
	t.Parallel()

	p := NewPlanner(config.Default())
	if plan := p.PlanRead("", []string{"email"}); !plan.IsEmpty() {
		t.Fatalf("unknown table produced read fields: %+v", plan.Fields)
	}
}
