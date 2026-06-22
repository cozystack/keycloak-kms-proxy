package wire

import (
	"errors"
	"testing"

	"github.com/jackc/pgproto3/v2"

	"github.com/cozystack/keycloak-kms-proxy/internal/config"
	"github.com/cozystack/keycloak-kms-proxy/internal/crypto"
	"github.com/cozystack/keycloak-kms-proxy/internal/rewrite"
)

// newTestCipher builds an in-memory Cipher with fresh DEKs for both schemes.
func newTestCipher(t *testing.T) *crypto.Cipher {
	t.Helper()

	dh, err := crypto.GenerateDEK(crypto.SchemeDeterministic)
	if err != nil {
		t.Fatalf("GenerateDEK(det): %v", err)
	}
	det, err := crypto.NewDeterministicAEAD(dh)
	if err != nil {
		t.Fatalf("NewDeterministicAEAD: %v", err)
	}
	nh, err := crypto.GenerateDEK(crypto.SchemeNonDeterministic)
	if err != nil {
		t.Fatalf("GenerateDEK(nondet): %v", err)
	}
	nondet, err := crypto.NewNonDeterministicAEAD(nh)
	if err != nil {
		t.Fatalf("NewNonDeterministicAEAD: %v", err)
	}
	c, err := crypto.NewCipher(1, nil, det, nondet)
	if err != nil {
		t.Fatalf("NewCipher: %v", err)
	}
	return c
}

func newTestSession() *Session {
	return NewSession(rewrite.NewPlanner(config.Default()), nil)
}

func TestSessionParseBuildsWritePlan(t *testing.T) {
	t.Parallel()

	s := newTestSession()
	if err := s.OnParse(&pgproto3.Parse{Name: "s1", Query: "SELECT id FROM user_entity WHERE email = $1"}); err != nil {
		t.Fatalf("OnParse: %v", err)
	}
	ps, ok := s.Statement("s1")
	if !ok {
		t.Fatal("statement s1 not tracked")
	}
	if ps.WritePlan == nil || len(ps.WritePlan.Params) != 1 || ps.WritePlan.Params[0].Column != "EMAIL" {
		t.Fatalf("write plan wrong: %+v", ps.WritePlan)
	}
}

func TestSessionParseFailsLoud(t *testing.T) {
	t.Parallel()

	s := newTestSession()
	// Writing a PII column as a literal cannot be encrypted transparently.
	err := s.OnParse(&pgproto3.Parse{Name: "bad", Query: "INSERT INTO user_entity (email) VALUES ('a@b.c')"})
	if !errors.Is(err, rewrite.ErrUnencryptablePII) {
		t.Fatalf("OnParse err=%v, want ErrUnencryptablePII", err)
	}
}

func TestSessionParseUnparsablePassthrough(t *testing.T) {
	t.Parallel()

	s := newTestSession()
	if err := s.OnParse(&pgproto3.Parse{Name: "set", Query: "SET search_path = public"}); err != nil {
		t.Fatalf("OnParse: %v", err)
	}
	ps, _ := s.Statement("set")
	// SET parses as OTHER; no PII plan, treated as passthrough.
	if ps.WritePlan == nil || !ps.WritePlan.IsEmpty() {
		t.Fatalf("expected empty passthrough plan, got %+v", ps.WritePlan)
	}
}

func TestSessionBindLinksStatement(t *testing.T) {
	t.Parallel()

	s := newTestSession()
	_ = s.OnParse(&pgproto3.Parse{Name: "s1", Query: "SELECT id FROM user_entity WHERE email = $1"})
	s.OnBind(&pgproto3.Bind{DestinationPortal: "p1", PreparedStatement: "s1", ResultFormatCodes: []int16{0}})

	p, ok := s.Portal("p1")
	if !ok || p.Stmt == nil || p.Stmt.Name != "s1" {
		t.Fatalf("portal not linked to statement: %+v ok=%v", p, ok)
	}
}

func TestSessionExecuteAndResultMatching(t *testing.T) {
	t.Parallel()

	s := newTestSession()
	_ = s.OnParse(&pgproto3.Parse{Name: "s1", Query: "SELECT id, email FROM user_entity WHERE id = $1"})
	s.OnBind(&pgproto3.Bind{DestinationPortal: "p1", PreparedStatement: "s1"})
	s.OnExecute(&pgproto3.Execute{Portal: "p1"})

	if s.CurrentExecuting() == nil || s.CurrentExecuting().Name != "p1" {
		t.Fatal("execute did not enqueue the portal")
	}

	s.OnRowDescription(&pgproto3.RowDescription{Fields: []pgproto3.FieldDescription{
		{Name: []byte("id")},
		{Name: []byte("email")},
	}})
	p, _ := s.Portal("p1")
	if p.ReadPlan == nil || len(p.ReadPlan.Fields) != 1 || p.ReadPlan.Fields[0].Column != "EMAIL" || p.ReadPlan.Fields[0].Index != 1 {
		t.Fatalf("read plan wrong: %+v", p.ReadPlan)
	}

	s.OnCommandComplete()
	if s.CurrentExecuting() != nil {
		t.Fatal("command complete did not advance the execute queue")
	}
}

func TestSessionExecuteQueueFIFO(t *testing.T) {
	t.Parallel()

	s := newTestSession()
	_ = s.OnParse(&pgproto3.Parse{Name: "s1", Query: "SELECT id FROM user_entity WHERE id = $1"})
	s.OnBind(&pgproto3.Bind{DestinationPortal: "p1", PreparedStatement: "s1"})
	s.OnBind(&pgproto3.Bind{DestinationPortal: "p2", PreparedStatement: "s1"})
	s.OnExecute(&pgproto3.Execute{Portal: "p1"})
	s.OnExecute(&pgproto3.Execute{Portal: "p2"})

	if s.CurrentExecuting().Name != "p1" {
		t.Fatal("FIFO order broken at head")
	}
	s.OnCommandComplete()
	if s.CurrentExecuting().Name != "p2" {
		t.Fatal("FIFO order broken after advance")
	}
}

func TestSessionClose(t *testing.T) {
	t.Parallel()

	s := newTestSession()
	_ = s.OnParse(&pgproto3.Parse{Name: "s1", Query: "SELECT 1"})
	s.OnBind(&pgproto3.Bind{DestinationPortal: "p1", PreparedStatement: "s1"})

	s.OnClose(&pgproto3.Close{ObjectType: 'P', Name: "p1"})
	if _, ok := s.Portal("p1"); ok {
		t.Error("portal not closed")
	}
	s.OnClose(&pgproto3.Close{ObjectType: 'S', Name: "s1"})
	if _, ok := s.Statement("s1"); ok {
		t.Error("statement not closed")
	}
}
