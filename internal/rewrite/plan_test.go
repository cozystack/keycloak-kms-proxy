package rewrite

import (
	"errors"
	"testing"

	"github.com/cozystack/keycloak-kms-proxy/internal/config"
	"github.com/cozystack/keycloak-kms-proxy/internal/crypto"
)

func planFor(t *testing.T, sql string) *WritePlan {
	t.Helper()

	a, err := Analyze(sql)
	if err != nil {
		t.Fatalf("Analyze(%q): %v", sql, err)
	}
	plan, err := NewPlanner(config.Default()).PlanWrite(a)
	if err != nil {
		t.Fatalf("PlanWrite(%q): %v", sql, err)
	}
	return plan
}

func findParam(plan *WritePlan, param int) (ParamRule, bool) {
	for _, pr := range plan.Params {
		if pr.Param == param {
			return pr, true
		}
	}
	return ParamRule{}, false
}

func TestPlanInsertEncryptsPIIColumns(t *testing.T) {
	t.Parallel()

	plan := planFor(t, `INSERT INTO user_entity (id, username, email, first_name, realm_id) VALUES ($1, $2, $3, $4, $5)`)

	// username ($2) deterministic+lowercase, email ($3) deterministic+lowercase,
	// first_name ($4) non-deterministic; id and realm_id untouched.
	if len(plan.Params) != 3 {
		t.Fatalf("got %d param rules, want 3: %+v", len(plan.Params), plan.Params)
	}
	email, ok := findParam(plan, 3)
	if !ok || email.Column != "EMAIL" || email.Rule.Scheme != crypto.SchemeDeterministic || !email.Rule.LowercaseNormalize {
		t.Errorf("email rule wrong: %+v ok=%v", email, ok)
	}
	first, ok := findParam(plan, 4)
	if !ok || first.Column != "FIRST_NAME" || first.Rule.Scheme != crypto.SchemeNonDeterministic {
		t.Errorf("first_name rule wrong: %+v ok=%v", first, ok)
	}
	if _, ok := findParam(plan, 1); ok {
		t.Error("id ($1) must not be encrypted")
	}
}

func TestPlanUppercaseTable(t *testing.T) {
	t.Parallel()

	// Identifier case must not matter when matching the field set.
	plan := planFor(t, `INSERT INTO "USER_ENTITY" (EMAIL) VALUES ($1)`)
	if pr, ok := findParam(plan, 1); !ok || pr.Column != "EMAIL" {
		t.Fatalf("uppercase table not matched: %+v ok=%v", pr, ok)
	}
}

func TestPlanSelectEncryptsDeterministicSearch(t *testing.T) {
	t.Parallel()

	plan := planFor(t, `SELECT id FROM user_entity WHERE email = $1 AND realm_id = $2`)
	if len(plan.Params) != 1 {
		t.Fatalf("got %d param rules, want 1: %+v", len(plan.Params), plan.Params)
	}
	if pr, _ := findParam(plan, 1); pr.Column != "EMAIL" || pr.Rule.Scheme != crypto.SchemeDeterministic {
		t.Errorf("email search rule wrong: %+v", pr)
	}
}

func TestLenientPlannerPassesThroughLiteralPII(t *testing.T) {
	t.Parallel()

	// A Liquibase historical UPDATE writes CREDENTIAL.CREDENTIAL_DATA with a
	// CONCAT() expression (no bound parameter). The strict planner refuses;
	// the lenient planner passes it through (no encryption applied), as
	// needed during the Keycloak bootstrap window.
	sql := `UPDATE credential SET credential_data = 'literal-json', secret_data = 'literal-secret' WHERE type = 'password'`
	a, err := Analyze(sql)
	if err != nil {
		t.Fatalf("Analyze: %v", err)
	}
	_, strictErr := NewPlanner(config.Default()).PlanWrite(a)
	if !errors.Is(strictErr, ErrUnencryptablePII) {
		t.Fatalf("strict planner: err=%v, want ErrUnencryptablePII", strictErr)
	}
	plan, err := NewLenientPlanner(config.Default()).PlanWrite(a)
	if err != nil {
		t.Fatalf("lenient planner: %v", err)
	}
	if !plan.IsEmpty() {
		t.Errorf("lenient planner produced a plan for literal writes: %+v", plan)
	}
}

func TestPlanFailsLoudOnLiteralPII(t *testing.T) {
	t.Parallel()

	a, _ := Analyze(`INSERT INTO user_entity (email) VALUES ('alice@example.com')`)
	_, err := NewPlanner(config.Default()).PlanWrite(a)
	if !errors.Is(err, ErrUnencryptablePII) {
		t.Fatalf("err=%v, want ErrUnencryptablePII", err)
	}
}

func TestPlanLikeOnDeterministicEmitsLikeParam(t *testing.T) {
	t.Parallel()

	// A LIKE filter on the deterministic EMAIL column produces a deferred
	// LikeParam entry (encrypt iff the bound value has no wildcards).
	a, err := Analyze(`SELECT id FROM user_entity WHERE email LIKE $1`)
	if err != nil {
		t.Fatalf("Analyze: %v", err)
	}
	plan, err := NewPlanner(config.Default()).PlanWrite(a)
	if err != nil {
		t.Fatalf("PlanWrite: %v", err)
	}
	if len(plan.Params) != 0 {
		t.Errorf("LikeParam misfiled into Params: %+v", plan.Params)
	}
	if len(plan.LikeParams) != 1 || plan.LikeParams[0].Column != "EMAIL" || plan.LikeParams[0].Param != 1 {
		t.Fatalf("LikeParams wrong: %+v", plan.LikeParams)
	}
	if !plan.LikeParams[0].Rule.LowercaseNormalize {
		t.Error("EMAIL rule should keep its lower-case normalization")
	}
}

func TestPlanLikeOnNonDeterministicIsIgnored(t *testing.T) {
	t.Parallel()

	// LIKE on a non-deterministic PII column cannot match ciphertext rows
	// either way, so the proxy leaves it unchanged (no fail-loud here).
	a, err := Analyze(`SELECT id FROM user_entity WHERE first_name LIKE $1`)
	if err != nil {
		t.Fatalf("Analyze: %v", err)
	}
	plan, err := NewPlanner(config.Default()).PlanWrite(a)
	if err != nil {
		t.Fatalf("PlanWrite: %v", err)
	}
	if !plan.IsEmpty() {
		t.Errorf("non-deterministic LIKE filter produced a plan: %+v", plan)
	}
}

func TestPlanFailsLoudOnNonDeterministicSearch(t *testing.T) {
	t.Parallel()

	// first_name is non-deterministic → equality search can never match.
	a, _ := Analyze(`SELECT id FROM user_entity WHERE first_name = $1`)
	_, err := NewPlanner(config.Default()).PlanWrite(a)
	if !errors.Is(err, ErrUnsearchablePII) {
		t.Fatalf("err=%v, want ErrUnsearchablePII", err)
	}
}

func TestPlanNonPIITableIsEmpty(t *testing.T) {
	t.Parallel()

	plan := planFor(t, `INSERT INTO realm (id, name) VALUES ($1, $2)`)
	if !plan.IsEmpty() {
		t.Fatalf("non-PII table produced a plan: %+v", plan)
	}
}

func TestPlanAttributeConditional(t *testing.T) {
	t.Parallel()

	plan := planFor(t, `INSERT INTO user_attribute (id, name, value, long_value, long_value_hash) VALUES ($1, $2, $3, $4, $5)`)

	if len(plan.Params) != 0 {
		t.Errorf("attribute write should produce no unconditional params, got %+v", plan.Params)
	}
	if len(plan.AttributeConditions) != 1 {
		t.Fatalf("got %d attribute conditions, want 1", len(plan.AttributeConditions))
	}
	cond := plan.AttributeConditions[0]
	if cond.NameParam != 2 {
		t.Errorf("name param: got %d, want 2", cond.NameParam)
	}
	if cond.Prefix != "pii-" {
		t.Errorf("prefix: got %q, want pii-", cond.Prefix)
	}
	// VALUE ($3) and LONG_VALUE ($4) are encrypted; LONG_VALUE_HASH ($5) is not.
	gotCols := map[string]int{}
	for _, vp := range cond.ValueParams {
		gotCols[vp.Column] = vp.Param
	}
	if gotCols["VALUE"] != 3 || gotCols["LONG_VALUE"] != 4 || len(gotCols) != 2 {
		t.Errorf("value params wrong: %+v", cond.ValueParams)
	}
}

func TestPlanAttributeLiteralValueFailsLoud(t *testing.T) {
	t.Parallel()

	a, _ := Analyze(`INSERT INTO user_attribute (name, value) VALUES ($1, 'plain')`)
	_, err := NewPlanner(config.Default()).PlanWrite(a)
	if !errors.Is(err, ErrUnencryptablePII) {
		t.Fatalf("err=%v, want ErrUnencryptablePII", err)
	}
}
