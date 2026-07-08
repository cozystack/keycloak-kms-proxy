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

const truncateLimit = 4000

func truncate(s string) string {
	s = strings.Join(strings.Fields(s), " ")
	if len(s) > truncateLimit {
		return s[:truncateLimit] + "..."
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
	// Columns caches the result-set column names learned from the backend's
	// RowDescription (statement or portal Describe). pgjdbc describes a
	// statement once and afterwards binds/executes it with no further
	// Describe, so no RowDescription flows on those executions; the read plan
	// must be derivable from this cache or ciphertext leaks to the client.
	Columns []string
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
	describes  []pendingDescribe

	// mu serializes state access between the two relay pump goroutines (the
	// frontend and backend directions). The pump takes it via observeFrontend /
	// observeBackend; the individual On* methods are lock-free for direct
	// single-goroutine use in tests.
	mu sync.Mutex
}

// pendingDescribe is a frontend Describe awaiting its backend answer
// (RowDescription or NoData). The backend answers Describes strictly in
// request order, so a FIFO attributes each answer to the described object.
// A boundary entry marks a Sync boundary instead of a Describe.
type pendingDescribe struct {
	stmt     *PreparedStatement
	portal   *Portal
	boundary bool
}

// syncBoundary marks a Sync boundary in the execute queue. Clients may
// pipeline the next batch before consuming the previous batch's
// ReadyForQuery, so error/RFQ handling must only affect entries of the
// batch the backend is actually answering — everything up to the boundary.
var syncBoundary = &Portal{Name: "(sync)"}

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
			debugf("kkp: parse %q FAIL plan: kind=%v table=%q err=%v sql=%q", p.Name, a.Kind, a.Table, perr, truncate(p.Query))
			return fmt.Errorf("wire: prepare %q: %w", p.Name, perr)
		}
		debugf("kkp: parse %q kind=%v table=%q writeParams=%d sql=%q", p.Name, a.Kind, a.Table, len(plan.Params), truncate(p.Query))
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

// OnDescribe records a frontend Describe so its backend answer (RowDescription
// or NoData) can be attributed to the described statement or portal. An
// unknown name still occupies a queue slot to keep the FIFO aligned with the
// backend's answers.
func (s *Session) OnDescribe(d *pgproto3.Describe) {
	pd := pendingDescribe{}
	switch d.ObjectType {
	case 'S':
		pd.stmt = s.statements[d.Name]
	case 'P':
		if p, ok := s.portals[d.Name]; ok {
			pd.portal = p
			pd.stmt = p.Stmt
		}
	}
	s.describes = append(s.describes, pd)
}

// simplePortalName labels synthetic result-queue entries for simple-protocol
// queries in debug logs.
const simplePortalName = "(simple)"

// OnQuery tracks a simple-protocol query ('Q'). The backend answers each
// statement in the string with its own result cycle (RowDescription, DataRows,
// CommandComplete), so each statement enqueues one synthetic executing entry —
// without them a simple query's CommandComplete pops a pending
// extended-protocol portal and desyncs every later result on the connection.
// Statements are planned like OnParse: a literal PII write is refused
// (fail-loud) instead of stored as plaintext, and SELECT results decrypt
// through the same read-plan path once the RowDescription arrives. A simple
// query implicitly syncs (its response ends with ReadyForQuery), so it also
// pushes the Sync boundaries.
func (s *Session) OnQuery(q *pgproto3.Query) error {
	analyses, err := rewrite.AnalyzeAll(q.String)
	switch {
	case err != nil || len(analyses) == 0:
		// Unparsable (dialect edge) or an empty query string: the backend
		// answers with a single result cycle (or EmptyQueryResponse).
		debugf("kkp: query passthrough (stmts=%d, err=%v) sql=%q", len(analyses), err, truncate(q.String))
		s.execQueue = append(s.execQueue, &Portal{Name: simplePortalName, Stmt: &PreparedStatement{SQL: q.String}})
	default:
		for _, a := range analyses {
			plan, perr := s.planner.PlanWrite(a)
			if perr != nil {
				debugf("kkp: query FAIL plan: kind=%v table=%q err=%v sql=%q", a.Kind, a.Table, perr, truncate(a.SQL))
				return fmt.Errorf("wire: simple query: %w", perr)
			}
			debugf("kkp: query kind=%v table=%q sql=%q", a.Kind, a.Table, truncate(a.SQL))
			// Each entry carries its own statement text so per-statement
			// logging and the PII heuristics do not see its neighbours.
			s.execQueue = append(s.execQueue, &Portal{
				Name: simplePortalName,
				Stmt: &PreparedStatement{SQL: a.SQL, Analysis: a, WritePlan: plan},
			})
		}
	}
	s.OnSync()
	return nil
}

// OnSync pushes a Sync boundary onto both result queues. The backend's
// matching ReadyForQuery consumes it, so batches pipelined behind an
// unconsumed ReadyForQuery keep their entries.
func (s *Session) OnSync() {
	s.execQueue = append(s.execQueue, syncBoundary)
	s.describes = append(s.describes, pendingDescribe{boundary: true})
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

// OnRowDescription learns the result columns of the statement being described
// or executed. A RowDescription answers the oldest outstanding Describe when
// one is pending (extended protocol); only the simple protocol emits a
// RowDescription without a Describe, directly before that statement's
// DataRows. Either way the columns are cached on the statement so later
// Bind/Execute cycles that carry no Describe at all (pgjdbc's server-prepared
// reuse) can still build their decrypt plan.
func (s *Session) OnRowDescription(rd *pgproto3.RowDescription) {
	columns := make([]string, len(rd.Fields))
	for i, f := range rd.Fields {
		columns[i] = string(f.Name)
	}

	if len(s.describes) > 0 && !s.describes[0].boundary {
		pd := s.describes[0]
		s.describes = s.describes[1:]
		if pd.stmt == nil {
			debugf("kkp: rowdesc — describe of unknown statement/portal, skipping decrypt-plan build")
			return
		}
		s.learnColumns(pd.stmt, columns)
		if pd.portal != nil {
			pd.portal.ReadPlan = s.planRead(pd.stmt, columns)
		}
		return
	}

	// No Describe outstanding: simple-protocol result shape for the current
	// executing entry.
	p := s.CurrentExecuting()
	if p == nil || p.Stmt == nil {
		debugf("kkp: rowdesc — no executing portal/analysis, skipping decrypt-plan build")
		return
	}
	s.learnColumns(p.Stmt, columns)
	p.ReadPlan = s.planRead(p.Stmt, columns)
}

// learnColumns caches a statement's result columns and fail-louds when a
// PII-touching SELECT yields no read plan — the silent-ciphertext failure
// mode the runtime-SQL conformance contract is meant to catch. The check is a
// hint, not an error — production alerts on the metric.
func (s *Session) learnColumns(ps *PreparedStatement, columns []string) {
	ps.Columns = columns
	plan := s.planRead(ps, columns)
	table := ""
	if ps.Analysis != nil {
		table = ps.Analysis.Table
	}
	fields := 0
	if plan != nil {
		fields = len(plan.Fields)
	}
	debugf("kkp: rowdesc stmt=%q table=%q cols=%v readPlanFields=%d", ps.Name, table, columns, fields)

	if (plan == nil || plan.IsEmpty()) && piiTouchedButNotPlanned(ps.SQL, columns) {
		observe.UnrecognizedPIISQL.Inc()
		log.Printf("kkp: WARN unrecognised PII-touching SELECT — passthrough — stmt=%q cols=%v sql=%q",
			ps.Name, columns, truncate(ps.SQL))
	}
}

// planRead builds the decrypt plan for a statement's result columns; nil for
// a statement without analysis (unparsable SQL → passthrough).
func (s *Session) planRead(ps *PreparedStatement, columns []string) *rewrite.ReadPlan {
	if ps.Analysis == nil {
		return nil
	}
	return s.planner.PlanRead(ps.Analysis.Table, columns)
}

// ensureReadPlan resolves a portal's decrypt plan, deriving it from the
// statement's cached columns when no RowDescription flowed for this portal:
// pgjdbc describes a server-prepared statement once and then executes it many
// times with a bare Bind/Execute, so the portal itself is never described
// (the verify-email incident: those rows left the proxy undecrypted).
func (s *Session) ensureReadPlan(p *Portal) *rewrite.ReadPlan {
	if p.ReadPlan == nil && p.Stmt != nil && len(p.Stmt.Columns) > 0 {
		p.ReadPlan = s.planRead(p.Stmt, p.Stmt.Columns)
	}
	return p.ReadPlan
}

// OnNoData consumes the pending Describe of a statement or portal that
// returns no rows, keeping later RowDescriptions attributed correctly.
func (s *Session) OnNoData() {
	if len(s.describes) > 0 && !s.describes[0].boundary {
		s.describes = s.describes[1:]
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
		if containsIdent(su, t) {
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

// containsIdent reports whether ident occurs in the upper-cased SQL text as a
// standalone identifier (or identifier prefix when ident ends in '_'), so
// that e.g. RESET_CREDENTIALS_FLOW does not count as a mention of CREDENTIAL.
func containsIdent(su, ident string) bool {
	for from := 0; ; {
		i := strings.Index(su[from:], ident)
		if i < 0 {
			return false
		}
		i += from
		before := i == 0 || !isIdentChar(su[i-1])
		end := i + len(ident)
		after := strings.HasSuffix(ident, "_") || end == len(su) || !isIdentChar(su[end])
		if before && after {
			return true
		}
		from = i + 1
	}
}

func isIdentChar(c byte) bool {
	return c == '_' || (c >= 'A' && c <= 'Z') || (c >= '0' && c <= '9')
}

// OnCommandComplete advances past the executing portal once its result ends.
func (s *Session) OnCommandComplete() { s.popExecuting() }

// OnEmptyQueryResponse advances past an empty-query result.
func (s *Session) OnEmptyQueryResponse() { s.popExecuting() }

// OnPortalSuspended advances past a row-limited Execute; the client resumes
// with another Execute for the same portal, which re-enqueues it (the portal
// keeps its read plan).
func (s *Session) OnPortalSuspended() { s.popExecuting() }

// OnErrorResponse drops the rest of the failing batch: after an error the
// backend skips all subsequent messages until Sync, so no Execute or Describe
// queued before the boundary will ever produce its results. Entries behind
// the boundary belong to pipelined later batches and stay.
func (s *Session) OnErrorResponse() {
	for len(s.execQueue) > 0 && s.execQueue[0] != syncBoundary {
		s.execQueue = s.execQueue[1:]
	}
	for len(s.describes) > 0 && !s.describes[0].boundary {
		s.describes = s.describes[1:]
	}
}

// OnReadyForQuery consumes one Sync boundary from both queues, together with
// any dead entries of the batch it closes (a desync leftover: an entry that
// never saw its CommandComplete). Entries of pipelined later batches stay.
func (s *Session) OnReadyForQuery() {
	dead := 0
	for len(s.execQueue) > 0 {
		head := s.execQueue[0]
		s.execQueue = s.execQueue[1:]
		if head == syncBoundary {
			break
		}
		dead++
	}
	for len(s.describes) > 0 {
		head := s.describes[0]
		s.describes = s.describes[1:]
		if head.boundary {
			break
		}
		dead++
	}
	if dead > 0 {
		debugf("kkp: ready-for-query dropped %d dead pipeline entries — resync", dead)
	}
}

func (s *Session) popExecuting() {
	if len(s.execQueue) > 0 && s.execQueue[0] != syncBoundary {
		s.execQueue = s.execQueue[1:]
	}
}

// CurrentExecuting returns the portal at the head of the execute queue, or
// nil when the queue is empty or paused at a Sync boundary.
func (s *Session) CurrentExecuting() *Portal {
	if len(s.execQueue) == 0 || s.execQueue[0] == syncBoundary {
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
