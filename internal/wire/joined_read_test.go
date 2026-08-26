package wire

import (
	"testing"

	"github.com/jackc/pgproto3/v2"
	"github.com/prometheus/client_golang/prometheus/testutil"

	"github.com/cozystack/keycloak-kms-proxy/internal/crypto"
	"github.com/cozystack/keycloak-kms-proxy/internal/observe"
	"github.com/cozystack/keycloak-kms-proxy/internal/rewrite"
)

// Regression tests for the joined read path. A SELECT whose FROM clause is a
// join has no single range variable, so the analyser left `Table` empty, the
// read planner returned an empty plan, and every USER_ENTITY column in the
// result — email, names, username — reached Keycloak as a raw $KKP$ envelope.
// Observed live on stage: kkp_ciphertext_passthrough_total{reason="empty-plan"}
// climbing in lockstep with the "unrecognised PII-touching SELECT" warning for
// the group-members listing below.

// groupMembersSelect is the Hibernate SQL Keycloak issues for
// getGroupMembersStream (admin REST GET /groups/{id}/members), captured
// verbatim from the stage proxy's warning log.
const groupMembersSelect = "select u1_0.ID,u1_0.CREATED_TIMESTAMP,u1_0.EMAIL,u1_0.EMAIL_CONSTRAINT," +
	"u1_0.EMAIL_VERIFIED,u1_0.ENABLED,u1_0.FEDERATION_LINK,u1_0.FIRST_NAME,u1_0.LAST_MODIFIED_TIMESTAMP," +
	"u1_0.LAST_NAME,u1_0.NOT_BEFORE,u1_0.REALM_ID,u1_0.SERVICE_ACCOUNT_CLIENT_LINK,u1_0.USERNAME " +
	"from USER_GROUP_MEMBERSHIP ugme1_0 join USER_ENTITY u1_0 on u1_0.ID=ugme1_0.USER_ID " +
	"where ugme1_0.GROUP_ID=$1 order by u1_0.USERNAME offset $2 rows fetch first $3 rows only"

// groupMembersColumns is the RowDescription the backend answers with, in the
// select list's order.
var groupMembersColumns = []string{
	"id", "created_timestamp", "email", "email_constraint", "email_verified", "enabled",
	"federation_link", "first_name", "last_modified_timestamp", "last_name", "not_before",
	"realm_id", "service_account_client_link", "username",
}

func rowDescriptionFor(columns []string) *pgproto3.RowDescription {
	fields := make([]pgproto3.FieldDescription, len(columns))
	for i, c := range columns {
		fields[i] = pgproto3.FieldDescription{Name: []byte(c)}
	}
	return &pgproto3.RowDescription{Fields: fields}
}

// storedValue produces the backend-stored ciphertext for a column value.
func storedValue(t *testing.T, s *Session, scheme crypto.Scheme, table, column, plaintext string) []byte {
	t.Helper()
	stored, err := s.cipher.Encrypt(scheme, []byte(plaintext), rewrite.AAD(table, column))
	if err != nil {
		t.Fatalf("Encrypt(%s.%s): %v", table, column, err)
	}
	return []byte(stored)
}

// groupMembersRow builds one DataRow of the group-members result with the
// PII columns stored as the backend holds them.
func groupMembersRow(t *testing.T, s *Session) *pgproto3.DataRow {
	t.Helper()
	const (
		deterministic    = crypto.SchemeDeterministic
		nonDeterministic = crypto.SchemeNonDeterministic
	)
	return &pgproto3.DataRow{Values: [][]byte{
		[]byte("00000000-0000-0000-0000-000000000001"),                               // id
		[]byte("1700000000000"),                                                      // created_timestamp
		storedValue(t, s, deterministic, "USER_ENTITY", "EMAIL", "ivy@example.test"), // email
		[]byte("ivy@example.test"),                                                   // email_constraint
		[]byte("t"),                                                                  // email_verified
		[]byte("t"),                                                                  // enabled
		nil,                                                                          // federation_link
		storedValue(t, s, nonDeterministic, "USER_ENTITY", "FIRST_NAME", "Ivy"), // first_name
		[]byte("1700000000000"), // last_modified_timestamp
		storedValue(t, s, nonDeterministic, "USER_ENTITY", "LAST_NAME", "Nolan"), // last_name
		[]byte("0"), // not_before
		[]byte("00000000-0000-0000-0000-0000000000aa"), // realm_id
		nil, // service_account_client_link
		storedValue(t, s, deterministic, "USER_ENTITY", "USERNAME", "ivy"), // username
	}}
}

func assertGroupMemberDecrypted(t *testing.T, dr *pgproto3.DataRow) {
	t.Helper()
	for _, want := range []struct {
		index int
		name  string
		value string
	}{
		{2, "email", "ivy@example.test"},
		{7, "first_name", "Ivy"},
		{9, "last_name", "Nolan"},
		{13, "username", "ivy"},
	} {
		if got := string(dr.Values[want.index]); got != want.value {
			t.Errorf("%s not decrypted on joined read: got %q, want %q", want.name, got, want.value)
		}
	}
}

// TestJoinedSelectDecrypts is the group-members regression: the result set is
// assembled by a join, but every column in it belongs to USER_ENTITY and must
// decrypt.
func TestJoinedSelectDecrypts(t *testing.T) {
	t.Parallel()

	s := newEncryptingSession(t)
	if err := s.OnParse(&pgproto3.Parse{Name: "S_223", Query: groupMembersSelect}); err != nil {
		t.Fatalf("OnParse: %v", err)
	}
	s.OnDescribe(&pgproto3.Describe{ObjectType: 'S', Name: "S_223"})
	s.OnBind(&pgproto3.Bind{DestinationPortal: "C_1", PreparedStatement: "S_223"})
	s.OnExecute(&pgproto3.Execute{Portal: "C_1"})
	s.OnSync()

	s.OnRowDescription(rowDescriptionFor(groupMembersColumns))
	dr := groupMembersRow(t, s)
	if err := s.DecryptDataRow(dr); err != nil {
		t.Fatalf("DecryptDataRow: %v", err)
	}
	assertGroupMemberDecrypted(t, dr)
	s.OnCommandComplete()
	s.OnReadyForQuery()
}

// TestJoinedSelectReuseDecrypts covers the warm pgjdbc path for the same
// statement: once described, later executions carry no Describe at all and
// the plan must still be derivable from the cached columns.
func TestJoinedSelectReuseDecrypts(t *testing.T) {
	t.Parallel()

	s := newEncryptingSession(t)
	if err := s.OnParse(&pgproto3.Parse{Name: "S_223", Query: groupMembersSelect}); err != nil {
		t.Fatalf("OnParse: %v", err)
	}
	s.OnDescribe(&pgproto3.Describe{ObjectType: 'S', Name: "S_223"})
	s.OnBind(&pgproto3.Bind{DestinationPortal: "C_1", PreparedStatement: "S_223"})
	s.OnExecute(&pgproto3.Execute{Portal: "C_1"})
	s.OnSync()
	s.OnRowDescription(rowDescriptionFor(groupMembersColumns))
	s.OnCommandComplete()
	s.OnReadyForQuery()

	s.OnBind(&pgproto3.Bind{DestinationPortal: "C_2", PreparedStatement: "S_223"})
	s.OnExecute(&pgproto3.Execute{Portal: "C_2"})
	s.OnSync()
	dr := groupMembersRow(t, s)
	if err := s.DecryptDataRow(dr); err != nil {
		t.Fatalf("DecryptDataRow: %v", err)
	}
	assertGroupMemberDecrypted(t, dr)
}

// TestJoinedSelectLeavesNoCiphertextPassthrough asserts the incident counter
// stays flat: it is the signal production alerts on, and it was the only
// evidence the group-members read was leaking.
func TestJoinedSelectLeavesNoCiphertextPassthrough(t *testing.T) {
	observe.CiphertextPassthrough.Reset()
	observe.UnrecognizedPIISQL.Add(0)
	before := testutil.ToFloat64(observe.UnrecognizedPIISQL)

	s := newEncryptingSession(t)
	if err := s.OnParse(&pgproto3.Parse{Name: "S_223", Query: groupMembersSelect}); err != nil {
		t.Fatalf("OnParse: %v", err)
	}
	s.OnDescribe(&pgproto3.Describe{ObjectType: 'S', Name: "S_223"})
	s.OnBind(&pgproto3.Bind{DestinationPortal: "C_1", PreparedStatement: "S_223"})
	s.OnExecute(&pgproto3.Execute{Portal: "C_1"})
	s.OnSync()
	s.OnRowDescription(rowDescriptionFor(groupMembersColumns))
	if err := s.DecryptDataRow(groupMembersRow(t, s)); err != nil {
		t.Fatalf("DecryptDataRow: %v", err)
	}

	if leaked := testutil.ToFloat64(observe.CiphertextPassthrough.WithLabelValues("empty-plan")); leaked != 0 {
		t.Errorf("ciphertext passthrough counted %v times on the joined read", leaked)
	}
	if got := testutil.ToFloat64(observe.UnrecognizedPIISQL) - before; got != 0 {
		t.Errorf("joined PII SELECT still counted as unrecognised %v times", got)
	}
}
