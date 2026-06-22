package wire

import (
	"fmt"
	"log"
	"os"
	"strings"
	"sync"

	"github.com/jackc/pgproto3/v2"

	"github.com/cozystack/keycloak-kms-proxy/internal/crypto"
	"github.com/cozystack/keycloak-kms-proxy/internal/observe"
	"github.com/cozystack/keycloak-kms-proxy/internal/rewrite"
)

// debugRelay is set by KKP_DEBUG_RELAY=true. Logs every Parse and
// RowDescription so we can see which queries the proxy is and is not
// recognising. Performance penalty is real; only enable for diagnostics.
var debugRelay = os.Getenv("KKP_DEBUG_RELAY") == "true"

func debugf(format string, args ...any) {
	if debugRelay {
		log.Printf(format, args...)
	}
}

func truncate(s string, n int) string {
	s = strings.Join(strings.Fields(s), " ")
	if len(s) > n {
		return s[:n] + "..."
	}
	return s
}

// PreparedStatement is a parsed extended-protocol statement and the encryption
// plans derived from it. Hibernate prepares a statement once (Parse) and binds
// it many times, so the analysis is cached here keyed by statement name.
type PreparedStatement struct {
	Name      string
	SQL       string
	Analysis  *rewrite.Analysis
	WritePlan *rewrite.WritePlan
}

// Portal is a bound instance of a prepared statement (a Bind destination). It
// carries the parameter/result format codes and, once the backend describes the
// result, the decrypt-on-DataRow plan.
type Portal struct {
	Name             string
	Stmt             *PreparedStatement
	ParameterFormats []int16
	ResultFormats    []int16
	ReadPlan         *rewrite.ReadPlan
}

// Session is the per-connection extended-protocol state machine. It maps
// statement names to parsed SQL and PII parameter positions, tracks portals,
// and matches backend result messages to the executing portal so the read plan
// can be applied. It does not perform I/O; the relay drives it by
// calling the On* observers as messages flow in each direction.
type Session struct {
	planner    *rewrite.Planner
	cipher     *crypto.Cipher
	statements map[string]*PreparedStatement
	portals    map[string]*Portal
	execQueue  []*Portal

	// mu serializes state access between the two relay pump goroutines (the
	// frontend and backend directions). The pump takes it via observeFrontend /
	// observeBackend; the individual On* methods are lock-free for direct
	// single-goroutine use in tests.
	mu sync.Mutex
}

// NewSession creates a Session that plans against the given planner and applies
// the cipher on Bind/DataRow. The cipher may be nil for state-only use (no
// transformation); transforming a non-passthrough statement then errors.
func NewSession(planner *rewrite.Planner, cipher *crypto.Cipher) *Session {
	return &Session{
		planner:    planner,
		cipher:     cipher,
		statements: make(map[string]*PreparedStatement),
		portals:    make(map[string]*Portal),
	}
}

// OnParse records a prepared statement and its encryption plans. A statement
// whose SQL cannot be parsed is recorded as passthrough (no analysis). A
// statement that touches PII in a way the proxy cannot transform returns a
// fail-loud error so the caller can reject it. When the plan
// includes blind-index filters the SQL is rewritten in place so the backend's
// prepared plan filters on the hash column.
func (s *Session) OnParse(p *pgproto3.Parse) error {
	ps := &PreparedStatement{Name: p.Name, SQL: p.Query}

	if a, err := rewrite.Analyze(p.Query); err == nil {
		plan, perr := s.planner.PlanWrite(a)
		if perr != nil {
			debugf("kkp: parse %q FAIL plan: kind=%v table=%q err=%v sql=%q", p.Name, a.Kind, a.Table, perr, truncate(p.Query, 4000))
			return fmt.Errorf("wire: prepare %q: %w", p.Name, perr)
		}
		debugf("kkp: parse %q kind=%v table=%q writeParams=%d sql=%q", p.Name, a.Kind, a.Table, len(plan.Params), truncate(p.Query, 4000))
		ps.Analysis = a
		ps.WritePlan = plan

		if len(plan.BlindIndexFilters) > 0 {
			mapping := make(map[string]string, len(plan.BlindIndexFilters))
			for _, f := range plan.BlindIndexFilters {
				mapping[strings.ToLower(f.Column)] = f.HashColumn
			}
			rewritten, rerr := rewrite.BlindIndexQuery(p.Query, mapping)
			if rerr != nil {
				return fmt.Errorf("wire: prepare %q: blind-index rewrite: %w", p.Name, rerr)
			}
			p.Query = rewritten
			ps.SQL = rewritten
		}
		if len(plan.BlindIndexWrites) > 0 {
			rewritten, allocs, rerr := rewrite.BlindIndexWriteSQL(p.Query, plan.BlindIndexWrites)
			if rerr != nil {
				return fmt.Errorf("wire: prepare %q: blind-index write rewrite: %w", p.Name, rerr)
			}
			for i := range plan.BlindIndexWrites {
				plan.BlindIndexWrites[i].NewParam = allocs[plan.BlindIndexWrites[i].SourceParam]
			}
			p.Query = rewritten
			ps.SQL = rewritten
		}
	}

	s.statements[p.Name] = ps
	return nil
}

// OnBind binds a prepared statement to a portal. An unknown statement is bound
// as passthrough; the backend reports the protocol error.
func (s *Session) OnBind(b *pgproto3.Bind) {
	s.portals[b.DestinationPortal] = &Portal{
		Name:             b.DestinationPortal,
		Stmt:             s.statements[b.PreparedStatement],
		ParameterFormats: b.ParameterFormatCodes,
		ResultFormats:    b.ResultFormatCodes,
	}
}

// OnExecute enqueues a portal as the next result producer, so the backend's
// result messages can be matched to it in order.
func (s *Session) OnExecute(e *pgproto3.Execute) {
	if p, ok := s.portals[e.Portal]; ok {
		s.execQueue = append(s.execQueue, p)
	}
}

// OnClose drops a closed prepared statement or portal.
func (s *Session) OnClose(c *pgproto3.Close) {
	switch c.ObjectType {
	case 'S':
		delete(s.statements, c.Name)
	case 'P':
		delete(s.portals, c.Name)
	}
}

// OnRowDescription learns the result columns for the executing portal and
// builds its decrypt-on-DataRow plan.
func (s *Session) OnRowDescription(rd *pgproto3.RowDescription) {
	p := s.CurrentExecuting()
	if p == nil || p.Stmt == nil || p.Stmt.Analysis == nil {
		debugf("kkp: rowdesc — no executing portal/analysis, skipping decrypt-plan build")
		return
	}
	columns := make([]string, len(rd.Fields))
	for i, f := range rd.Fields {
		columns[i] = string(f.Name)
	}
	p.ReadPlan = s.planner.PlanRead(p.Stmt.Analysis.Table, columns)
	debugf("kkp: rowdesc portal=%q stmt=%q table=%q cols=%v readPlanFields=%d",
		p.Name, p.Stmt.Name, p.Stmt.Analysis.Table, columns, len(p.ReadPlan.Fields))

	// Observability fail-loud: log when a SELECT mentions a PII
	// table and returns a PII column, but the analyser produced no read
	// plan. This is exactly the silent-ciphertext failure mode the runtime-
	// SQL conformance contract is meant to catch. The check is a
	// hint, not an error — production turns this into an alerted metric.
	if p.ReadPlan.IsEmpty() && piiTouchedButNotPlanned(p.Stmt.SQL, columns) {
		observe.UnrecognizedPIISQL.Inc()
		log.Printf("kkp: WARN unrecognised PII-touching SELECT — passthrough — stmt=%q cols=%v sql=%q",
			p.Stmt.Name, columns, truncate(p.Stmt.SQL, 4000))
	}
}

// piiTouchedButNotPlanned reports whether the SQL textually mentions one of
// the PII tables and the result set contains at least one PII column name.
// Used purely to log a warning when a read sneaks past the analyser; it does
// not gate the data path.
func piiTouchedButNotPlanned(sql string, cols []string) bool {
	su := strings.ToUpper(sql)
	mentioned := false
	for _, t := range []string{"USER_ENTITY", "USER_ATTRIBUTE", "CREDENTIAL", "FED_USER_", "FEDERATED_IDENTITY"} {
		if strings.Contains(su, t) {
			mentioned = true
			break
		}
	}
	if !mentioned {
		return false
	}
	for _, c := range cols {
		switch strings.ToUpper(c) {
		case "USERNAME", "EMAIL", "FIRST_NAME", "LAST_NAME",
			"SECRET_DATA", "CREDENTIAL_DATA", "VALUE", "LONG_VALUE",
			"FEDERATED_USERNAME", "FEDERATED_USER_ID", "TOKEN":
			return true
		}
	}
	return false
}

// OnCommandComplete advances past the executing portal once its result ends.
func (s *Session) OnCommandComplete() { s.popExecuting() }

// OnEmptyQueryResponse advances past an empty-query result.
func (s *Session) OnEmptyQueryResponse() { s.popExecuting() }

// OnErrorResponse advances past a failed command's result.
func (s *Session) OnErrorResponse() { s.popExecuting() }

func (s *Session) popExecuting() {
	if len(s.execQueue) > 0 {
		s.execQueue = s.execQueue[1:]
	}
}

// CurrentExecuting returns the portal at the head of the execute queue, or nil.
func (s *Session) CurrentExecuting() *Portal {
	if len(s.execQueue) == 0 {
		return nil
	}
	return s.execQueue[0]
}

// Statement returns a tracked prepared statement by name.
func (s *Session) Statement(name string) (*PreparedStatement, bool) {
	ps, ok := s.statements[name]
	return ps, ok
}

// Portal returns a tracked portal by name.
func (s *Session) Portal(name string) (*Portal, bool) {
	p, ok := s.portals[name]
	return p, ok
}
