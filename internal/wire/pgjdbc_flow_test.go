package wire

import (
	"strings"
	"testing"

	"github.com/jackc/pgproto3/v2"
	"github.com/prometheus/client_golang/prometheus/testutil"

	"github.com/cozystack/keycloak-kms-proxy/internal/observe"
	"github.com/cozystack/keycloak-kms-proxy/internal/rewrite"
)

// Regression tests for the read-path flows behind the stage verify-email
// incident: pgjdbc describes a server-prepared statement once (Describe 'S')
// and afterwards executes it with bare Bind/Execute cycles that carry no
// Describe at all, so no RowDescription flows during those Executes; and
// simple-protocol queries share the connection with extended traffic, where
// an untracked CommandComplete desyncs the result queue. Both paths used to
// pass raw $KKP$ ciphertext through to Keycloak.

// keycloakUserSelect mirrors the Hibernate SQL captured live on the stage
// incident (statement S_22).
const keycloakUserSelect = "select ue1_0.ID,ue1_0.EMAIL,ue1_0.USERNAME from USER_ENTITY ue1_0 where ue1_0.USERNAME=$1 and ue1_0.REALM_ID=$2"

func userSelectRowDescription() *pgproto3.RowDescription {
	return &pgproto3.RowDescription{Fields: []pgproto3.FieldDescription{
		{Name: []byte("id")}, {Name: []byte("email")}, {Name: []byte("username")},
	}}
}

// storedEmail produces the backend-stored ciphertext for an email value.
func storedEmail(t *testing.T, s *Session, plaintext string) []byte {
	t.Helper()
	stored, err := s.cipher.Encrypt(0 /*deterministic*/, []byte(plaintext), rewrite.AAD("USER_ENTITY", "EMAIL"))
	if err != nil {
		t.Fatalf("Encrypt: %v", err)
	}
	return []byte(stored)
}

// TestDescribeStatementFlowDecrypts covers pgjdbc's first execution of a
// server-prepared statement: Parse + Describe('S') + Bind + Execute in one
// batch. The RowDescription answers the statement Describe — not a portal
// Describe — and the DataRow must still decrypt.
func TestDescribeStatementFlowDecrypts(t *testing.T) {
	t.Parallel()

	s := newEncryptingSession(t)
	if err := s.OnParse(&pgproto3.Parse{Name: "S_1", Query: keycloakUserSelect}); err != nil {
		t.Fatalf("OnParse: %v", err)
	}
	s.OnDescribe(&pgproto3.Describe{ObjectType: 'S', Name: "S_1"})
	s.OnBind(&pgproto3.Bind{DestinationPortal: "C_1", PreparedStatement: "S_1"})
	s.OnExecute(&pgproto3.Execute{Portal: "C_1"})
	s.OnSync()

	// Backend answers: ParseComplete, ParameterDescription, RowDescription
	// (for the Describe), then the Execute's rows.
	s.OnRowDescription(userSelectRowDescription())
	dr := &pgproto3.DataRow{Values: [][]byte{[]byte("u1"), storedEmail(t, s, "dora@example.com"), []byte("dora")}}
	if err := s.DecryptDataRow(dr); err != nil {
		t.Fatalf("DecryptDataRow: %v", err)
	}
	if string(dr.Values[1]) != "dora@example.com" {
		t.Fatalf("email not decrypted on describe-statement flow: %q", dr.Values[1])
	}
	s.OnCommandComplete()
	s.OnReadyForQuery()
}

// TestServerPreparedReuseDecrypts is the verify-email regression: once pgjdbc
// has the statement's metadata it re-executes with Bind + Execute only — no
// Describe, no RowDescription. The decrypt plan must come from the columns
// cached at the initial Describe.
func TestServerPreparedReuseDecrypts(t *testing.T) {
	t.Parallel()

	s := newEncryptingSession(t)
	if err := s.OnParse(&pgproto3.Parse{Name: "S_1", Query: keycloakUserSelect}); err != nil {
		t.Fatalf("OnParse: %v", err)
	}
	// First batch: describe-statement flow, complete cycle.
	s.OnDescribe(&pgproto3.Describe{ObjectType: 'S', Name: "S_1"})
	s.OnBind(&pgproto3.Bind{DestinationPortal: "C_1", PreparedStatement: "S_1"})
	s.OnExecute(&pgproto3.Execute{Portal: "C_1"})
	s.OnSync()
	s.OnRowDescription(userSelectRowDescription())
	s.OnCommandComplete()
	s.OnReadyForQuery()

	// Warm reuse: bare Bind + Execute. The backend sends BindComplete,
	// DataRow, CommandComplete — no RowDescription at all.
	s.OnBind(&pgproto3.Bind{DestinationPortal: "C_2", PreparedStatement: "S_1"})
	s.OnExecute(&pgproto3.Execute{Portal: "C_2"})
	s.OnSync()
	dr := &pgproto3.DataRow{Values: [][]byte{[]byte("u1"), storedEmail(t, s, "erin@example.com"), []byte("erin")}}
	if err := s.DecryptDataRow(dr); err != nil {
		t.Fatalf("DecryptDataRow: %v", err)
	}
	if string(dr.Values[1]) != "erin@example.com" {
		t.Fatalf("email not decrypted on server-prepared reuse: %q", dr.Values[1])
	}
}

// TestSimpleQuerySelectDecrypts covers the simple protocol ('Q'): its
// RowDescription arrives with no Describe outstanding and its rows must
// decrypt through the same read-plan path.
func TestSimpleQuerySelectDecrypts(t *testing.T) {
	t.Parallel()

	s := newEncryptingSession(t)
	if err := s.OnQuery(&pgproto3.Query{String: "select id, email from user_entity where id = 'u1'"}); err != nil {
		t.Fatalf("OnQuery: %v", err)
	}
	s.OnRowDescription(&pgproto3.RowDescription{Fields: []pgproto3.FieldDescription{
		{Name: []byte("id")}, {Name: []byte("email")},
	}})
	dr := &pgproto3.DataRow{Values: [][]byte{[]byte("u1"), storedEmail(t, s, "faye@example.com")}}
	if err := s.DecryptDataRow(dr); err != nil {
		t.Fatalf("DecryptDataRow: %v", err)
	}
	if string(dr.Values[1]) != "faye@example.com" {
		t.Fatalf("email not decrypted on simple-query flow: %q", dr.Values[1])
	}
	s.OnCommandComplete()
	s.OnReadyForQuery()
}

// TestSimpleQueryKeepsResultQueueInSync: an untracked simple query's
// CommandComplete used to pop a pending extended-protocol portal, shifting
// every later result onto the wrong portal (the "NO executing portal"
// desyncs observed on stage).
func TestSimpleQueryKeepsResultQueueInSync(t *testing.T) {
	t.Parallel()

	s := newEncryptingSession(t)
	if err := s.OnQuery(&pgproto3.Query{String: "COMMIT"}); err != nil {
		t.Fatalf("OnQuery: %v", err)
	}
	if err := s.OnParse(&pgproto3.Parse{Name: "S_1", Query: keycloakUserSelect}); err != nil {
		t.Fatalf("OnParse: %v", err)
	}
	s.OnDescribe(&pgproto3.Describe{ObjectType: 'S', Name: "S_1"})
	s.OnBind(&pgproto3.Bind{DestinationPortal: "C_1", PreparedStatement: "S_1"})
	s.OnExecute(&pgproto3.Execute{Portal: "C_1"})
	s.OnSync()

	// Backend: COMMIT's CommandComplete must pop the synthetic simple-query
	// entry (and its ReadyForQuery the implicit boundary), leaving the select
	// portal to receive its own results.
	s.OnCommandComplete()
	s.OnReadyForQuery()
	s.OnRowDescription(userSelectRowDescription())
	dr := &pgproto3.DataRow{Values: [][]byte{[]byte("u1"), storedEmail(t, s, "gino@example.com"), []byte("gino")}}
	if err := s.DecryptDataRow(dr); err != nil {
		t.Fatalf("DecryptDataRow: %v", err)
	}
	if string(dr.Values[1]) != "gino@example.com" {
		t.Fatalf("email not decrypted after interleaved simple query: %q", dr.Values[1])
	}
}

// TestSimpleQueryMultiStatement: each statement in a multi-statement simple
// query gets its own result cycle, so each needs its own queue entry.
func TestSimpleQueryMultiStatement(t *testing.T) {
	t.Parallel()

	s := newEncryptingSession(t)
	err := s.OnQuery(&pgproto3.Query{String: "select id from realm; select id, email from user_entity where id = 'u1'"})
	if err != nil {
		t.Fatalf("OnQuery: %v", err)
	}
	// First statement's cycle: realm rows pass through.
	s.OnRowDescription(&pgproto3.RowDescription{Fields: []pgproto3.FieldDescription{{Name: []byte("id")}}})
	if err := s.DecryptDataRow(&pgproto3.DataRow{Values: [][]byte{[]byte("r1")}}); err != nil {
		t.Fatalf("DecryptDataRow(realm): %v", err)
	}
	s.OnCommandComplete()
	// Second statement's cycle: user rows decrypt.
	s.OnRowDescription(&pgproto3.RowDescription{Fields: []pgproto3.FieldDescription{
		{Name: []byte("id")}, {Name: []byte("email")},
	}})
	dr := &pgproto3.DataRow{Values: [][]byte{[]byte("u1"), storedEmail(t, s, "hana@example.com")}}
	if err := s.DecryptDataRow(dr); err != nil {
		t.Fatalf("DecryptDataRow(user): %v", err)
	}
	if string(dr.Values[1]) != "hana@example.com" {
		t.Fatalf("email not decrypted on second simple statement: %q", dr.Values[1])
	}
}

// TestSimpleQueryLiteralPIIWriteFailsLoud: a simple-protocol write of a PII
// column carries the value as a literal the proxy cannot encrypt; it must be
// refused, mirroring OnParse.
func TestSimpleQueryLiteralPIIWriteFailsLoud(t *testing.T) {
	t.Parallel()

	s := newEncryptingSession(t)
	err := s.OnQuery(&pgproto3.Query{String: "insert into user_entity (id, email) values ('u1', 'raw@example.com')"})
	if err == nil || !strings.Contains(err.Error(), "not a bound parameter") {
		t.Fatalf("OnQuery err=%v, want unencryptable-PII failure", err)
	}
}

// TestNoDataConsumesPendingDescribe: a Describe of a row-less statement is
// answered with NoData; it must consume its queue slot so the next
// RowDescription lands on the right statement.
func TestNoDataConsumesPendingDescribe(t *testing.T) {
	t.Parallel()

	s := newEncryptingSession(t)
	if err := s.OnParse(&pgproto3.Parse{Name: "S_up", Query: "update user_entity set email = $1 where id = $2"}); err != nil {
		t.Fatalf("OnParse(update): %v", err)
	}
	if err := s.OnParse(&pgproto3.Parse{Name: "S_sel", Query: keycloakUserSelect}); err != nil {
		t.Fatalf("OnParse(select): %v", err)
	}
	s.OnDescribe(&pgproto3.Describe{ObjectType: 'S', Name: "S_up"})
	s.OnDescribe(&pgproto3.Describe{ObjectType: 'S', Name: "S_sel"})

	s.OnNoData()                                   // answers S_up
	s.OnRowDescription(userSelectRowDescription()) // answers S_sel

	up, _ := s.Statement("S_up")
	sel, _ := s.Statement("S_sel")
	if len(up.Columns) != 0 {
		t.Fatalf("update statement got columns: %v", up.Columns)
	}
	if len(sel.Columns) != 3 {
		t.Fatalf("select statement columns = %v, want 3", sel.Columns)
	}
}

// TestPortalSuspendedAdvancesQueue: a row-limited Execute ends in
// PortalSuspended; the resumed Execute re-enqueues the portal and its rows
// keep decrypting.
func TestPortalSuspendedAdvancesQueue(t *testing.T) {
	t.Parallel()

	s := newEncryptingSession(t)
	if err := s.OnParse(&pgproto3.Parse{Name: "S_1", Query: keycloakUserSelect}); err != nil {
		t.Fatalf("OnParse: %v", err)
	}
	s.OnDescribe(&pgproto3.Describe{ObjectType: 'S', Name: "S_1"})
	s.OnBind(&pgproto3.Bind{DestinationPortal: "C_1", PreparedStatement: "S_1"})
	s.OnExecute(&pgproto3.Execute{Portal: "C_1", MaxRows: 1})
	s.OnRowDescription(userSelectRowDescription())

	dr := &pgproto3.DataRow{Values: [][]byte{[]byte("u1"), storedEmail(t, s, "ivy@example.com"), []byte("ivy")}}
	if err := s.DecryptDataRow(dr); err != nil {
		t.Fatalf("DecryptDataRow(first): %v", err)
	}
	s.OnPortalSuspended()

	s.OnExecute(&pgproto3.Execute{Portal: "C_1", MaxRows: 1})
	dr2 := &pgproto3.DataRow{Values: [][]byte{[]byte("u2"), storedEmail(t, s, "june@example.com"), []byte("june")}}
	if err := s.DecryptDataRow(dr2); err != nil {
		t.Fatalf("DecryptDataRow(resumed): %v", err)
	}
	if string(dr2.Values[1]) != "june@example.com" {
		t.Fatalf("email not decrypted after portal resume: %q", dr2.Values[1])
	}
}

// TestErrorResponseClearsPipeline: after an error the backend skips to Sync,
// so nothing still queued will produce results; keeping entries would shift
// the next batch's rows onto the wrong portals.
func TestErrorResponseClearsPipeline(t *testing.T) {
	t.Parallel()

	s := newEncryptingSession(t)
	if err := s.OnParse(&pgproto3.Parse{Name: "S_1", Query: keycloakUserSelect}); err != nil {
		t.Fatalf("OnParse: %v", err)
	}
	s.OnDescribe(&pgproto3.Describe{ObjectType: 'S', Name: "S_1"})
	s.OnBind(&pgproto3.Bind{DestinationPortal: "C_1", PreparedStatement: "S_1"})
	s.OnExecute(&pgproto3.Execute{Portal: "C_1"})
	s.OnBind(&pgproto3.Bind{DestinationPortal: "C_2", PreparedStatement: "S_1"})
	s.OnExecute(&pgproto3.Execute{Portal: "C_2"})

	s.OnErrorResponse()
	if s.CurrentExecuting() != nil {
		t.Fatal("exec queue not cleared by ErrorResponse")
	}
	s.OnReadyForQuery()

	// A fresh cycle decrypts normally.
	s.OnBind(&pgproto3.Bind{DestinationPortal: "C_3", PreparedStatement: "S_1"})
	s.OnExecute(&pgproto3.Execute{Portal: "C_3"})
	s.OnRowDescription(userSelectRowDescription())
	dr := &pgproto3.DataRow{Values: [][]byte{[]byte("u1"), storedEmail(t, s, "kate@example.com"), []byte("kate")}}
	if err := s.DecryptDataRow(dr); err != nil {
		t.Fatalf("DecryptDataRow: %v", err)
	}
	if string(dr.Values[1]) != "kate@example.com" {
		t.Fatalf("email not decrypted after pipeline reset: %q", dr.Values[1])
	}
}

// TestPIIWarnIdentifierBoundary: RESET_CREDENTIALS_FLOW must not count as a
// mention of the CREDENTIAL table (the stage false-positive WARN), while a
// real USER_ENTITY select with a PII column must.
func TestPIIWarnIdentifierBoundary(t *testing.T) {
	t.Parallel()

	realmSQL := "select re1_0.ID, re1_0.RESET_CREDENTIALS_FLOW, a1_0.VALUE from REALM re1_0 left join REALM_ATTRIBUTE a1_0 on re1_0.ID=a1_0.REALM_ID"
	if piiTouchedButNotPlanned(realmSQL, []string{"id", "reset_credentials_flow", "value"}) {
		t.Fatal("REALM select flagged as PII-touching via RESET_CREDENTIALS_FLOW substring")
	}
	if !piiTouchedButNotPlanned(keycloakUserSelect, []string{"id", "email", "username"}) {
		t.Fatal("USER_ENTITY select not flagged as PII-touching")
	}
}

// TestPipelinedBatchAcrossReadyForQuery: clients pipeline the next batch
// before consuming the previous batch's ReadyForQuery. The boundary handling
// must only close the finished batch — clearing the queues wholesale here
// dropped the live entries and leaked ciphertext (observed on stage as
// "ready-for-query with entries still pending").
func TestPipelinedBatchAcrossReadyForQuery(t *testing.T) {
	t.Parallel()

	s := newEncryptingSession(t)
	if err := s.OnParse(&pgproto3.Parse{Name: "S_1", Query: keycloakUserSelect}); err != nil {
		t.Fatalf("OnParse: %v", err)
	}
	// Batch 1 and batch 2 both sent before any backend answer arrives.
	s.OnDescribe(&pgproto3.Describe{ObjectType: 'S', Name: "S_1"})
	s.OnBind(&pgproto3.Bind{DestinationPortal: "C_1", PreparedStatement: "S_1"})
	s.OnExecute(&pgproto3.Execute{Portal: "C_1"})
	s.OnSync()
	s.OnBind(&pgproto3.Bind{DestinationPortal: "C_2", PreparedStatement: "S_1"})
	s.OnExecute(&pgproto3.Execute{Portal: "C_2"})
	s.OnSync()

	// Backend answers batch 1.
	s.OnRowDescription(userSelectRowDescription())
	dr1 := &pgproto3.DataRow{Values: [][]byte{[]byte("u1"), storedEmail(t, s, "lena@example.com"), []byte("lena")}}
	if err := s.DecryptDataRow(dr1); err != nil {
		t.Fatalf("DecryptDataRow(batch1): %v", err)
	}
	s.OnCommandComplete()
	s.OnReadyForQuery()

	// Backend answers batch 2 — bare rows, no RowDescription.
	dr2 := &pgproto3.DataRow{Values: [][]byte{[]byte("u2"), storedEmail(t, s, "mira@example.com"), []byte("mira")}}
	if err := s.DecryptDataRow(dr2); err != nil {
		t.Fatalf("DecryptDataRow(batch2): %v", err)
	}
	if string(dr2.Values[1]) != "mira@example.com" {
		t.Fatalf("email not decrypted in pipelined batch: %q", dr2.Values[1])
	}
	s.OnCommandComplete()
	s.OnReadyForQuery()
}

// TestErrorInBatchKeepsPipelinedBatch: an error aborts only the failing
// batch (the backend skips to Sync); a batch pipelined behind it must keep
// its entries and still decrypt.
func TestErrorInBatchKeepsPipelinedBatch(t *testing.T) {
	t.Parallel()

	s := newEncryptingSession(t)
	// Batch 1: a passthrough statement that will fail on the backend.
	if err := s.OnParse(&pgproto3.Parse{Name: "S_bad", Query: "SELECT broken FROM nowhere"}); err != nil {
		t.Fatalf("OnParse(bad): %v", err)
	}
	s.OnDescribe(&pgproto3.Describe{ObjectType: 'S', Name: "S_bad"})
	s.OnBind(&pgproto3.Bind{DestinationPortal: "C_1", PreparedStatement: "S_bad"})
	s.OnExecute(&pgproto3.Execute{Portal: "C_1"})
	s.OnSync()
	// Batch 2 pipelined behind it: the user select.
	if err := s.OnParse(&pgproto3.Parse{Name: "S_1", Query: keycloakUserSelect}); err != nil {
		t.Fatalf("OnParse: %v", err)
	}
	s.OnDescribe(&pgproto3.Describe{ObjectType: 'S', Name: "S_1"})
	s.OnBind(&pgproto3.Bind{DestinationPortal: "C_2", PreparedStatement: "S_1"})
	s.OnExecute(&pgproto3.Execute{Portal: "C_2"})
	s.OnSync()

	// Backend: batch 1 errors, its ReadyForQuery closes the batch.
	s.OnErrorResponse()
	s.OnReadyForQuery()

	// Batch 2 proceeds normally and must decrypt.
	s.OnRowDescription(userSelectRowDescription())
	dr := &pgproto3.DataRow{Values: [][]byte{[]byte("u1"), storedEmail(t, s, "nora@example.com"), []byte("nora")}}
	if err := s.DecryptDataRow(dr); err != nil {
		t.Fatalf("DecryptDataRow: %v", err)
	}
	if string(dr.Values[1]) != "nora@example.com" {
		t.Fatalf("email not decrypted in batch after error: %q", dr.Values[1])
	}
	s.OnCommandComplete()
	s.OnReadyForQuery()
}

// TestDecryptDataRowFlagsDoubleEncrypted: a stored value that decrypts into
// another envelope is a corrupted row — ciphertext leaked during a
// passthrough window and written back as the value. The proxy decrypts one
// layer, returns the inner envelope, and inventories the row via the
// kkp_double_encrypted_total counter.
func TestDecryptDataRowFlagsDoubleEncrypted(t *testing.T) {
	t.Parallel()

	s := newEncryptingSession(t)
	if err := s.OnParse(&pgproto3.Parse{Name: "S_1", Query: keycloakUserSelect}); err != nil {
		t.Fatalf("OnParse: %v", err)
	}
	s.OnDescribe(&pgproto3.Describe{ObjectType: 'S', Name: "S_1"})
	s.OnBind(&pgproto3.Bind{DestinationPortal: "C_1", PreparedStatement: "S_1"})
	s.OnExecute(&pgproto3.Execute{Portal: "C_1"})
	s.OnSync()
	s.OnRowDescription(userSelectRowDescription())

	inner := string(storedEmail(t, s, "olga@example.com"))
	outer, err := s.cipher.Encrypt(0 /*deterministic*/, []byte(inner), rewrite.AAD("USER_ENTITY", "EMAIL"))
	if err != nil {
		t.Fatalf("Encrypt(outer): %v", err)
	}

	before := testutil.ToFloat64(observe.DoubleEncrypted.WithLabelValues("USER_ENTITY", "EMAIL"))
	dr := &pgproto3.DataRow{Values: [][]byte{[]byte("u1"), []byte(outer), []byte("olga")}}
	if err := s.DecryptDataRow(dr); err != nil {
		t.Fatalf("DecryptDataRow: %v", err)
	}
	if string(dr.Values[1]) != inner {
		t.Fatalf("double-encrypted value = %q, want one decryption layer removed (%q)", dr.Values[1], inner)
	}
	after := testutil.ToFloat64(observe.DoubleEncrypted.WithLabelValues("USER_ENTITY", "EMAIL"))
	if after != before+1 {
		t.Fatalf("kkp_double_encrypted_total = %v, want %v", after, before+1)
	}
}
