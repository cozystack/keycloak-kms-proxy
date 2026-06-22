package main

import (
	"fmt"
	"os"
	"regexp"
	"sort"
	"strings"

	"github.com/cozystack/keycloak-kms-proxy/internal/keycloakmodel"
)

// entitySources lists the JPA entity files (relative to the Keycloak source
// root) that the proxy cares about. All live under
// model/jpa in Keycloak 26.0.0 (the federated entities share that tree).
var entitySources = []string{
	"model/jpa/src/main/java/org/keycloak/models/jpa/entities/UserEntity.java",
	"model/jpa/src/main/java/org/keycloak/models/jpa/entities/UserAttributeEntity.java",
	"model/jpa/src/main/java/org/keycloak/models/jpa/entities/CredentialEntity.java",
	"model/jpa/src/main/java/org/keycloak/models/jpa/entities/FederatedIdentityEntity.java",
	"model/jpa/src/main/java/org/keycloak/storage/jpa/entity/FederatedUserAttributeEntity.java",
	"model/jpa/src/main/java/org/keycloak/storage/jpa/entity/FederatedUserCredentialEntity.java",
}

var (
	reClass   = regexp.MustCompile(`(?m)^\s*public\s+class\s+(\w+)`)
	rePackage = regexp.MustCompile(`(?m)^\s*package\s+([\w.]+)\s*;`)
	reTable   = regexp.MustCompile(`@Table\s*\(\s*name\s*=\s*"([^"]+)"`)
	// reColumn matches an @Column(name="X" ...) annotation followed (after
	// any further annotations) by the Java field declaration it maps. The
	// field name is the last identifier before the terminating semicolon.
	reColumn = regexp.MustCompile(
		`@Column\s*\(\s*name\s*=\s*"([^"]+)"[^)]*\)` + // @Column(name="NAME" ...)
			`(?:\s*@\w+(?:\([^)]*\))?)*` + // optional trailing annotations
			`\s+(?:private|protected|public)\s+[\w.\[\]<>]+\s+(\w+)\s*[;=]`)
	// reNamedQuery matches @NamedQuery(name="X", query="..." [+ "..."]). The
	// query value may be split across Java string-concatenation segments.
	reNamedQuery = regexp.MustCompile(
		`@NamedQuery\s*\(\s*name\s*=\s*"([^"]+)"\s*,\s*query\s*=\s*((?:"(?:[^"\\]|\\.)*"\s*\+?\s*)+)\)`)
	reStringSegment = regexp.MustCompile(`"((?:[^"\\]|\\.)*)"`)
	// reLineComment matches a Java // line comment that is not inside a
	// string literal (the entity files have no // inside string literals).
	reLineComment = regexp.MustCompile(`(?m)//[^\n]*`)
)

// parseSource reads the Keycloak source root and parses the target entity
// files into a deterministic corpus for the given version.
func parseSource(root, version string) (keycloakmodel.Corpus, error) {
	corpus := keycloakmodel.Corpus{Version: version}
	for _, rel := range entitySources {
		path := root + string(os.PathSeparator) + rel
		ent, err := parseEntityFile(path)
		if err != nil {
			return keycloakmodel.Corpus{}, fmt.Errorf("parse %s: %w", rel, err)
		}
		corpus.Entities = append(corpus.Entities, ent)
	}
	sortCorpus(&corpus)
	return corpus, nil
}

// parseEntityFile parses a single JPA entity Java file.
func parseEntityFile(path string) (keycloakmodel.CorpusEntity, error) {
	data, err := os.ReadFile(path) //nolint:gosec // path is built from the trusted -src flag.
	if err != nil {
		return keycloakmodel.CorpusEntity{}, fmt.Errorf("read: %w", err)
	}
	// Strip // line comments so a trailing comment between an annotation and
	// its field (e.g. the @Access comment on @Id columns) does not break the
	// column regex. The target entities have no // inside JPQL literals.
	src := reLineComment.ReplaceAllString(string(data), "")

	ent := keycloakmodel.CorpusEntity{
		Class:   firstSubmatch(reClass, src),
		Package: firstSubmatch(rePackage, src),
		Table:   firstSubmatch(reTable, src),
	}
	if ent.Class == "" || ent.Table == "" {
		return keycloakmodel.CorpusEntity{}, fmt.Errorf("missing class or @Table in %s", path)
	}
	ent.Columns = parseColumns(src)
	ent.Queries = parseQueries(src)
	return ent, nil
}

// parseColumns extracts @Column mappings (field name to DB column name).
func parseColumns(src string) []keycloakmodel.CorpusColumn {
	var cols []keycloakmodel.CorpusColumn
	for _, m := range reColumn.FindAllStringSubmatch(src, -1) {
		cols = append(cols, keycloakmodel.CorpusColumn{Field: m[2], Name: m[1]})
	}
	return cols
}

// parseQueries extracts @NamedQuery declarations, joining Java string
// concatenation and normalizing whitespace in the JPQL.
func parseQueries(src string) []keycloakmodel.CorpusQuery {
	var queries []keycloakmodel.CorpusQuery
	for _, m := range reNamedQuery.FindAllStringSubmatch(src, -1) {
		queries = append(queries, keycloakmodel.CorpusQuery{
			Name: m[1],
			JPQL: joinJavaString(m[2]),
		})
	}
	return queries
}

// joinJavaString joins the segments of a Java string-concatenation
// expression ("a" + "b") into a single string and collapses runs of
// whitespace so that line-wrapped JPQL normalizes consistently.
func joinJavaString(expr string) string {
	var b strings.Builder
	for _, seg := range reStringSegment.FindAllStringSubmatch(expr, -1) {
		b.WriteString(unescapeJava(seg[1]))
	}
	return strings.Join(strings.Fields(b.String()), " ")
}

// unescapeJava resolves the Java string escapes that occur in JPQL literals.
func unescapeJava(s string) string {
	r := strings.NewReplacer(`\"`, `"`, `\\`, `\`, `\n`, "\n", `\t`, "\t")
	return r.Replace(s)
}

func firstSubmatch(re *regexp.Regexp, src string) string {
	if m := re.FindStringSubmatch(src); m != nil {
		return m[1]
	}
	return ""
}

// sortCorpus orders entities, columns and queries deterministically so that
// regeneration yields stable, reviewable diffs.
func sortCorpus(c *keycloakmodel.Corpus) {
	sort.Slice(c.Entities, func(i, j int) bool { return c.Entities[i].Class < c.Entities[j].Class })
	for i := range c.Entities {
		cols := c.Entities[i].Columns
		sort.Slice(cols, func(a, b int) bool { return cols[a].Name < cols[b].Name })
		qs := c.Entities[i].Queries
		sort.Slice(qs, func(a, b int) bool { return qs[a].Name < qs[b].Name })
	}
}
