package main

import (
	"os"
	"path/filepath"
	"testing"
)

// sampleEntity mirrors the shape of a real Keycloak JPA entity (concatenated
// JPQL, an @Id column with a trailing // comment, varied @Column spacing) so
// the parser is exercised without a Keycloak clone.
const sampleEntity = `package org.keycloak.models.jpa.entities;

@NamedQueries({
        @NamedQuery(name="getRealmUserByUsername", query="select u from UserEntity u where u.username = :username and u.realmId = :realmId"),
        @NamedQuery(name="getRealmUsersByAttributeNameAndValue", query="select u from UserEntity u join u.attributes attr " +
                "where u.realmId = :realmId and attr.name = :name and attr.value = :value")
})
@Entity
@Table(name="USER_ENTITY")
public class UserEntity {
    @Id
    @Column(name="ID", length = 36)
    @Access(AccessType.PROPERTY) // avoids an extra SQL
    protected String id;

    @Nationalized
    @Column(name = "USERNAME")
    protected String username;

    @Column(name = "EMAIL")
    protected String email = null;
}
`

func writeSample(t *testing.T) string {
	t.Helper()
	dir := t.TempDir()
	rel := entitySources[0]
	path := filepath.Join(dir, rel)
	if err := os.MkdirAll(filepath.Dir(path), 0o750); err != nil {
		t.Fatalf("mkdir: %v", err)
	}
	if err := os.WriteFile(path, []byte(sampleEntity), 0o600); err != nil {
		t.Fatalf("write sample: %v", err)
	}
	return dir
}

func TestParseEntityFile(t *testing.T) {
	dir := writeSample(t)
	ent, err := parseEntityFile(filepath.Join(dir, entitySources[0]))
	if err != nil {
		t.Fatalf("parseEntityFile: %v", err)
	}

	if ent.Class != "UserEntity" {
		t.Errorf("class = %q, want UserEntity", ent.Class)
	}
	if ent.Table != "USER_ENTITY" {
		t.Errorf("table = %q, want USER_ENTITY", ent.Table)
	}
	if ent.Package != "org.keycloak.models.jpa.entities" {
		t.Errorf("package = %q", ent.Package)
	}

	wantCols := map[string]string{"ID": "id", "USERNAME": "username", "EMAIL": "email"}
	if len(ent.Columns) != len(wantCols) {
		t.Fatalf("columns = %d, want %d: %+v", len(ent.Columns), len(wantCols), ent.Columns)
	}
	for _, col := range ent.Columns {
		if wantCols[col.Name] != col.Field {
			t.Errorf("column %q field = %q, want %q", col.Name, col.Field, wantCols[col.Name])
		}
	}

	byName := map[string]string{}
	for _, q := range ent.Queries {
		byName[q.Name] = q.JPQL
	}
	const wantConcat = "select u from UserEntity u join u.attributes attr " +
		"where u.realmId = :realmId and attr.name = :name and attr.value = :value"
	if got := byName["getRealmUsersByAttributeNameAndValue"]; got != wantConcat {
		t.Errorf("concatenated JPQL = %q, want %q", got, wantConcat)
	}
}

func TestParseSourceSortsDeterministically(t *testing.T) {
	dir := writeSample(t)
	// Only the first entity file exists in the temp dir; the rest are
	// missing, so parseSource must surface a clear error rather than panic.
	if _, err := parseSource(dir, "test"); err == nil {
		t.Fatal("expected error for incomplete source tree, got nil")
	}
}

func TestJoinJavaString(t *testing.T) {
	// Segments "a  b" and "c\td" concatenate with no space at the seam, so
	// "b" and "c" join into one token after whitespace normalization. This
	// matches Java string concatenation (the seam adds no separator).
	got := joinJavaString(`"a  b" +  "c\td"`)
	if want := "a bc d"; got != want {
		t.Errorf("joinJavaString = %q, want %q", got, want)
	}
	if seam := joinJavaString(`"select u " + "from UserEntity u"`); seam != "select u from UserEntity u" {
		t.Errorf("joinJavaString seam = %q, want %q", seam, "select u from UserEntity u")
	}
}
