package wire

import "github.com/jackc/pgproto3/v2"

// Relay runs the bidirectional message pump after both legs are authenticated.
// It forwards every message between the client (Keycloak) and
// the backend (CNPG), applying encrypt-on-Bind on the way out and
// decrypt-on-DataRow on the way back. It returns when either direction ends
// (EOF, error, or Terminate); the caller closes both connections so the other
// direction unblocks.
func Relay(session *Session, client *pgproto3.Backend, server *pgproto3.Frontend) error {
	errc := make(chan error, 2)
	go func() { errc <- session.pumpClientToBackend(client, server) }()
	go func() { errc <- session.pumpBackendToClient(server, client) }()
	return <-errc
}

// pumpClientToBackend forwards frontend messages from the client to the backend,
// updating session state and encrypting bound PII parameters.
func (s *Session) pumpClientToBackend(client *pgproto3.Backend, server *pgproto3.Frontend) error {
	for {
		msg, err := client.Receive()
		if err != nil {
			return err
		}
		if err := s.observeFrontend(msg); err != nil {
			return err
		}
		if err := server.Send(msg); err != nil {
			return err
		}
		if _, done := msg.(*pgproto3.Terminate); done {
			return nil
		}
	}
}

// pumpBackendToClient forwards backend messages from the backend to the client,
// updating session state and decrypting PII result fields.
func (s *Session) pumpBackendToClient(server *pgproto3.Frontend, client *pgproto3.Backend) error {
	for {
		msg, err := server.Receive()
		if err != nil {
			return err
		}
		if err := s.observeBackend(msg); err != nil {
			return err
		}
		if err := client.Send(msg); err != nil {
			return err
		}
	}
}

// observeFrontend updates session state and transforms outgoing frontend
// messages in place. It holds the session lock to serialize with the backend
// pump goroutine.
func (s *Session) observeFrontend(msg pgproto3.FrontendMessage) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	switch m := msg.(type) {
	case *pgproto3.Parse:
		return s.OnParse(m)
	case *pgproto3.Bind:
		s.OnBind(m)
		return s.EncryptBind(m)
	case *pgproto3.Describe:
		s.OnDescribe(m)
	case *pgproto3.Execute:
		s.OnExecute(m)
	case *pgproto3.Sync:
		s.OnSync()
	case *pgproto3.Query:
		return s.OnQuery(m)
	case *pgproto3.Close:
		s.OnClose(m)
	}
	return nil
}

// observeBackend updates session state and transforms incoming backend messages
// in place. It holds the session lock to serialize with the frontend pump
// goroutine.
func (s *Session) observeBackend(msg pgproto3.BackendMessage) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	switch m := msg.(type) {
	case *pgproto3.RowDescription:
		s.OnRowDescription(m)
	case *pgproto3.NoData:
		s.OnNoData()
	case *pgproto3.DataRow:
		return s.DecryptDataRow(m)
	case *pgproto3.CommandComplete:
		s.OnCommandComplete()
	case *pgproto3.PortalSuspended:
		s.OnPortalSuspended()
	case *pgproto3.EmptyQueryResponse:
		s.OnEmptyQueryResponse()
	case *pgproto3.ErrorResponse:
		s.OnErrorResponse()
	case *pgproto3.ReadyForQuery:
		s.OnReadyForQuery()
	}
	return nil
}
