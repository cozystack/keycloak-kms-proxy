package rewrite

import (
	"testing"

	"github.com/cozystack/keycloak-kms-proxy/internal/config"
	"github.com/cozystack/keycloak-kms-proxy/internal/crypto"
)

func TestBlindIndexQueryRewrites(t *testing.T) {
	t.Parallel()

	mapping := map[string]string{"email": "email_hash", "username": "username_hash"}
	cases := []struct {
		name, in, want string
	}{
		{
			name: "LIKE on bare column",
			in:   "SELECT id FROM user_entity WHERE email LIKE $1",
			want: "SELECT id FROM user_entity WHERE email_hash = $1",
		},
		{
			name: "LIKE under LOWER",
			in:   "SELECT id FROM user_entity WHERE LOWER(email) LIKE $1",
			want: "SELECT id FROM user_entity WHERE email_hash = $1",
		},
		{
			name: "ILIKE",
			in:   "SELECT id FROM user_entity WHERE email ILIKE $1",
			want: "SELECT id FROM user_entity WHERE email_hash = $1",
		},
		{
			name: "AND of two blind-indexed filters",
			in:   "SELECT id FROM user_entity WHERE email LIKE $1 AND LOWER(username) LIKE $2",
			want: "SELECT id FROM user_entity WHERE email_hash = $1 AND username_hash = $2",
		},
		{
			name: "untouched columns remain LIKE",
			in:   "SELECT id FROM user_entity WHERE first_name LIKE $1",
			want: "SELECT id FROM user_entity WHERE first_name LIKE $1",
		},
		{
			name: "equality on the same column is left alone",
			in:   "SELECT id FROM user_entity WHERE email = $1",
			want: "SELECT id FROM user_entity WHERE email = $1",
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			got, err := BlindIndexQuery(tc.in, mapping)
			if err != nil {
				t.Fatalf("BlindIndexQuery: %v", err)
			}
			if got != tc.want {
				t.Fatalf("rewrite:\n got %q\nwant %q", got, tc.want)
			}
		})
	}
}

func TestPlanBlindIndexFilterRoutesAroundLikeParams(t *testing.T) {
	t.Parallel()

	// A field set with EMAIL configured to maintain a shadow hash column must
	// route LIKE filters into BlindIndexFilters, not the wildcard-free
	// LikeParams branch (which still applies for det+lower columns that have
	// no blind index).
	fs := config.New()
	fs.SetColumn(config.TableUserEntity, "EMAIL", config.Rule{
		Scheme: crypto.SchemeDeterministic, LowercaseNormalize: true, BlindIndex: "EMAIL_HASH",
	})

	a, err := Analyze(`SELECT id FROM user_entity WHERE email LIKE $1`)
	if err != nil {
		t.Fatalf("Analyze: %v", err)
	}
	plan, err := NewPlanner(fs).PlanWrite(a)
	if err != nil {
		t.Fatalf("PlanWrite: %v", err)
	}
	if len(plan.LikeParams) != 0 {
		t.Errorf("LikeParams should be empty when blind-index is configured: %+v", plan.LikeParams)
	}
	if len(plan.BlindIndexFilters) != 1 {
		t.Fatalf("BlindIndexFilters: got %+v", plan.BlindIndexFilters)
	}
	f := plan.BlindIndexFilters[0]
	if f.Column != "EMAIL" || f.HashColumn != "EMAIL_HASH" || f.Param != 1 {
		t.Errorf("BlindIndexFilter wrong: %+v", f)
	}
}
