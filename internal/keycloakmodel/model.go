package keycloakmodel

// Entity maps a Keycloak JPA entity to its table and the columns that hold PII.
// The blind-index hash column (LONG_VALUE_HASH) is deliberately
// excluded: Keycloak computes it over plaintext, so the proxy never touches it.
type Entity struct {
	Class      string
	Table      string
	PIIColumns []string
}

// IsPIIColumn reports whether column is a PII column of the entity.
func (e Entity) IsPIIColumn(column string) bool {
	for _, c := range e.PIIColumns {
		if c == column {
			return true
		}
	}
	return false
}

// QueryParam binds a JPQL named parameter to the database column it constrains.
type QueryParam struct {
	Param  string
	Column string
}

// NamedQuery is a Keycloak @NamedQuery (JPQL) that filters on entity columns.
// Entity is the class whose PII columns the query's parameters
// filter — used to resolve PIIParams. Note this is not always the class the
// query is declared on: Keycloak declares the attribute-search queries on
// UserEntity (they join u.attributes) yet they filter UserAttributeEntity
// columns, which is why the generated corpus checks query presence corpus-wide.
type NamedQuery struct {
	Name   string
	Entity string
	Params []QueryParam
}

// Model is the schema and query model for a pinned Keycloak version: the input
// from which the conformance test corpus is generated.
type Model struct {
	Version  string
	Entities []Entity
	Queries  []NamedQuery
}

// Entity returns the entity with the given class.
func (m Model) Entity(class string) (Entity, bool) {
	for _, e := range m.Entities {
		if e.Class == class {
			return e, true
		}
	}
	return Entity{}, false
}

// EntityByTable returns the entity backing the given table.
func (m Model) EntityByTable(table string) (Entity, bool) {
	for _, e := range m.Entities {
		if e.Table == table {
			return e, true
		}
	}
	return Entity{}, false
}

// Query returns the named query with the given name.
func (m Model) Query(name string) (NamedQuery, bool) {
	for _, q := range m.Queries {
		if q.Name == name {
			return q, true
		}
	}
	return NamedQuery{}, false
}

// PIIParams returns the query parameters that bind to PII columns of the
// query's entity — i.e. the parameters the proxy must encrypt before
// forwarding. Parameters on non-PII columns (realm id, attribute name, the
// blind-index hash) are excluded.
func (m Model) PIIParams(q NamedQuery) []QueryParam {
	entity, ok := m.Entity(q.Entity)
	if !ok {
		return nil
	}
	var out []QueryParam
	for _, p := range q.Params {
		if entity.IsPIIColumn(p.Column) {
			out = append(out, p)
		}
	}
	return out
}

// Keycloak260 returns the model for Keycloak 26.0.0.
func Keycloak260() Model {
	return Model{
		Version: "26.0.0",
		Entities: []Entity{
			{Class: "UserEntity", Table: "USER_ENTITY", PIIColumns: []string{"USERNAME", "EMAIL", "FIRST_NAME", "LAST_NAME"}},
			{Class: "UserAttributeEntity", Table: "USER_ATTRIBUTE", PIIColumns: []string{"VALUE", "LONG_VALUE"}},
			{Class: "CredentialEntity", Table: "CREDENTIAL", PIIColumns: []string{"SECRET_DATA", "CREDENTIAL_DATA"}},
			{Class: "FederatedIdentityEntity", Table: "FEDERATED_IDENTITY", PIIColumns: []string{"FEDERATED_USERNAME", "TOKEN"}},
			{Class: "FederatedUserAttributeEntity", Table: "FED_USER_ATTRIBUTE", PIIColumns: []string{"VALUE", "LONG_VALUE"}},
			{Class: "FederatedUserCredentialEntity", Table: "FED_USER_CREDENTIAL", PIIColumns: []string{"SECRET_DATA", "CREDENTIAL_DATA"}},
		},
		Queries: []NamedQuery{
			{
				Name:   "getRealmUserByUsername",
				Entity: "UserEntity",
				Params: []QueryParam{{Param: "username", Column: "USERNAME"}, {Param: "realmId", Column: "REALM_ID"}},
			},
			{
				Name:   "getRealmUserByEmail",
				Entity: "UserEntity",
				Params: []QueryParam{{Param: "email", Column: "EMAIL"}, {Param: "realmId", Column: "REALM_ID"}},
			},
			{
				Name:   "getRealmUsersByAttributeNameAndValue",
				Entity: "UserAttributeEntity",
				Params: []QueryParam{{Param: "name", Column: "NAME"}, {Param: "value", Column: "VALUE"}},
			},
			{
				Name:   "getRealmUsersByAttributeNameAndLongValue",
				Entity: "UserAttributeEntity",
				Params: []QueryParam{{Param: "name", Column: "NAME"}, {Param: "longValueHash", Column: "LONG_VALUE_HASH"}},
			},
		},
	}
}
