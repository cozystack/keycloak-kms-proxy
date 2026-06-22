package keycloakmodel

import (
	"encoding/json"
	"fmt"
	"io"
	"os"
)

// Corpus is the golden conformance corpus generated from a pinned Keycloak
// source tree by cmd/gen-keycloak-tests. It is committed under
// testdata/keycloak/<version>/corpus.json and cross-checked against the
// hand-derived model (Keycloak260) so schema/query drift fails loudly.
//
// The JSON layout is deliberately simple and deterministically ordered so
// that regeneration produces reviewable diffs.
type Corpus struct {
	// Version is the Keycloak release tag the corpus was generated from.
	Version string `json:"version"`
	// Entities are the parsed JPA entities, sorted by class name.
	Entities []CorpusEntity `json:"entities"`
}

// CorpusEntity is a single JPA entity as parsed from the Keycloak sources.
type CorpusEntity struct {
	// Class is the simple Java class name.
	Class string `json:"class"`
	// Package is the Java package of the entity.
	Package string `json:"package"`
	// Table is the physical table name from @Table.
	Table string `json:"table"`
	// Columns are the @Column mappings, sorted by database column name.
	Columns []CorpusColumn `json:"columns"`
	// Queries are the @NamedQuery declarations, sorted by name.
	Queries []CorpusQuery `json:"queries"`
}

// CorpusColumn is a single @Column mapping (Java field to DB column name).
type CorpusColumn struct {
	// Field is the Java field name.
	Field string `json:"field"`
	// Name is the physical database column name.
	Name string `json:"name"`
}

// CorpusQuery is a single @NamedQuery (name plus joined JPQL text).
type CorpusQuery struct {
	// Name is the @NamedQuery name.
	Name string `json:"name"`
	// JPQL is the query text with Java string concatenation joined.
	JPQL string `json:"jpql"`
}

// LookupEntity returns the corpus entity with the given class name, or false
// if it is absent.
func (c Corpus) LookupEntity(class string) (CorpusEntity, bool) {
	for _, e := range c.Entities {
		if e.Class == class {
			return e, true
		}
	}
	return CorpusEntity{}, false
}

// HasColumn reports whether any entity in the corpus declares the given
// database column name. Keycloak's attribute-search queries are declared on
// UserEntity but filter columns owned by UserAttributeEntity, so column
// presence is checked corpus-wide.
func (c Corpus) HasColumn(name string) bool {
	for _, e := range c.Entities {
		if e.HasColumn(name) {
			return true
		}
	}
	return false
}

// HasQuery reports whether any entity in the corpus declares a named query
// with the given name.
func (c Corpus) HasQuery(name string) bool {
	for _, e := range c.Entities {
		if e.HasQuery(name) {
			return true
		}
	}
	return false
}

// HasColumn reports whether the entity declares a column with the given
// database column name.
func (e CorpusEntity) HasColumn(name string) bool {
	for _, col := range e.Columns {
		if col.Name == name {
			return true
		}
	}
	return false
}

// HasQuery reports whether the entity declares a named query with the given
// name.
func (e CorpusEntity) HasQuery(name string) bool {
	for _, q := range e.Queries {
		if q.Name == name {
			return true
		}
	}
	return false
}

// WriteJSON marshals the corpus as indented, deterministic JSON.
func (c Corpus) WriteJSON(w io.Writer) error {
	enc := json.NewEncoder(w)
	enc.SetIndent("", "  ")
	enc.SetEscapeHTML(false)
	if err := enc.Encode(c); err != nil {
		return fmt.Errorf("encode corpus: %w", err)
	}
	return nil
}

// LoadCorpus reads and decodes a corpus JSON file from disk.
func LoadCorpus(path string) (Corpus, error) {
	data, err := os.ReadFile(path) //nolint:gosec // path comes from trusted test/codegen input.
	if err != nil {
		return Corpus{}, fmt.Errorf("read corpus %q: %w", path, err)
	}
	var c Corpus
	if err := json.Unmarshal(data, &c); err != nil {
		return Corpus{}, fmt.Errorf("decode corpus %q: %w", path, err)
	}
	return c, nil
}
