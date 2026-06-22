package keycloakmodel_test

import (
	"path/filepath"
	"testing"

	"github.com/cozystack/keycloak-kms-proxy/internal/keycloakmodel"
)

const corpusVersion = "26.0.0"

// loadCorpus loads the committed golden corpus (no Keycloak clone required).
func loadCorpus(t *testing.T) keycloakmodel.Corpus {
	t.Helper()

	path := filepath.Join("..", "..", "testdata", "keycloak", corpusVersion, "corpus.json")
	corpus, err := keycloakmodel.LoadCorpus(path)
	if err != nil {
		t.Fatalf("load corpus: %v", err)
	}
	if corpus.Version != corpusVersion {
		t.Fatalf("corpus version = %q, want %q", corpus.Version, corpusVersion)
	}
	return corpus
}

// TestModelEntitiesPresentInCorpus asserts every entity/table the hand-derived
// model names exists in the generated corpus, so the model cannot reference an
// entity that drifted out of the Keycloak sources.
func TestModelEntitiesPresentInCorpus(t *testing.T) {
	t.Parallel()

	corpus := loadCorpus(t)
	for _, ent := range keycloakmodel.Keycloak260().Entities {
		got, ok := corpus.LookupEntity(ent.Class)
		if !ok {
			t.Errorf("entity %s missing from corpus", ent.Class)
			continue
		}
		if got.Table != ent.Table {
			t.Errorf("entity %s table = %q, model expects %q", ent.Class, got.Table, ent.Table)
		}
	}
}

// TestModelPIIColumnsPresentInCorpus asserts every PII column the model
// encrypts exists in the corpus, catching renamed/removed columns on upgrade.
func TestModelPIIColumnsPresentInCorpus(t *testing.T) {
	t.Parallel()

	corpus := loadCorpus(t)
	for _, ent := range keycloakmodel.Keycloak260().Entities {
		got, ok := corpus.LookupEntity(ent.Class)
		if !ok {
			t.Errorf("entity %s missing from corpus", ent.Class)
			continue
		}
		for _, col := range ent.PIIColumns {
			if !got.HasColumn(col) {
				t.Errorf("PII column %s.%s missing from corpus", ent.Table, col)
			}
		}
	}
}

// TestModelNamedQueriesPresentInCorpus asserts every named query the model
// intercepts exists in the corpus. Presence is checked corpus-wide because the
// attribute-search queries are declared on UserEntity (they join u.attributes)
// while the model attributes them to the entity whose columns they filter.
func TestModelNamedQueriesPresentInCorpus(t *testing.T) {
	t.Parallel()

	corpus := loadCorpus(t)
	for _, q := range keycloakmodel.Keycloak260().Queries {
		if !corpus.HasQuery(q.Name) {
			t.Errorf("named query %q missing from corpus", q.Name)
		}
	}
}

// TestModelQueryParamColumnsExist asserts every parameter binding references a
// column the corpus actually declares somewhere, keeping param→column bindings
// anchored to real columns.
func TestModelQueryParamColumnsExist(t *testing.T) {
	t.Parallel()

	corpus := loadCorpus(t)
	for _, q := range keycloakmodel.Keycloak260().Queries {
		for _, p := range q.Params {
			if !corpus.HasColumn(p.Column) {
				t.Errorf("query %q binds :%s to column %q, absent from the corpus", q.Name, p.Param, p.Column)
			}
		}
	}
}

// TestCorpusIsSorted verifies the committed corpus keeps its deterministic
// ordering so regeneration yields reviewable diffs.
func TestCorpusIsSorted(t *testing.T) {
	t.Parallel()

	corpus := loadCorpus(t)
	if len(corpus.Entities) == 0 {
		t.Fatal("corpus has no entities")
	}
	for i := 1; i < len(corpus.Entities); i++ {
		if corpus.Entities[i-1].Class > corpus.Entities[i].Class {
			t.Errorf("entities not sorted: %q before %q", corpus.Entities[i-1].Class, corpus.Entities[i].Class)
		}
	}
	for _, e := range corpus.Entities {
		for i := 1; i < len(e.Columns); i++ {
			if e.Columns[i-1].Name > e.Columns[i].Name {
				t.Errorf("%s columns not sorted", e.Class)
			}
		}
	}
}
