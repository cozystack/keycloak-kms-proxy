package wire

import (
	"fmt"
	"io"

	"github.com/jackc/pgproto3/v2"
)

// scramMechanism is the only SASL mechanism the proxy offers/accepts.
const scramMechanism = "SCRAM-SHA-256"

// AuthenticateUpstream runs the proxy-as-SCRAM-server handshake on a client
// (Keycloak) connection: it reads the startup message, declines
// in-band SSL/GSS (TLS is terminated at the listener), performs the SASL
// exchange via scram, and sends AuthenticationOk. It returns the Backend for
// the subsequent message pump and the startup parameters to forward downstream.
func AuthenticateUpstream(conn io.ReadWriter, scram *ScramServer) (*pgproto3.Backend, map[string]string, error) {
	backend := pgproto3.NewBackend(pgproto3.NewChunkReader(conn), conn)

	params, err := readStartup(conn, backend)
	if err != nil {
		return nil, nil, err
	}
	// PostgreSQL clients (pgjdbc, libpq) send n=* in SCRAM and carry the real
	// identity in the StartupMessage; surface that for the verifier lookup.
	scram.SetUsername(params["user"])

	if err := runUpstreamSASL(backend, scram); err != nil {
		// Mirror PostgreSQL: report the failure to the client before closing.
		_ = backend.Send(&pgproto3.ErrorResponse{Severity: "FATAL", Code: "28P01", Message: "authentication failed"})
		return nil, nil, err
	}
	return backend, params, nil
}

func readStartup(conn io.Writer, backend *pgproto3.Backend) (map[string]string, error) {
	for {
		msg, err := backend.ReceiveStartupMessage()
		if err != nil {
			return nil, fmt.Errorf("wire: receive startup: %w", err)
		}
		switch m := msg.(type) {
		case *pgproto3.StartupMessage:
			return m.Parameters, nil
		case *pgproto3.SSLRequest, *pgproto3.GSSEncRequest:
			// TLS/GSS is terminated at the listener; decline in-band.
			if _, err := conn.Write([]byte{'N'}); err != nil {
				return nil, fmt.Errorf("wire: decline ssl/gss: %w", err)
			}
		default:
			return nil, fmt.Errorf("wire: unexpected startup message %T", msg)
		}
	}
}

func runUpstreamSASL(backend *pgproto3.Backend, scram *ScramServer) error {
	if err := backend.Send(&pgproto3.AuthenticationSASL{AuthMechanisms: []string{scramMechanism}}); err != nil {
		return err
	}
	clientFirst, err := receiveSASLInitial(backend)
	if err != nil {
		return err
	}
	serverFirst, err := scram.ServerFirst(clientFirst)
	if err != nil {
		return err
	}
	if err = backend.Send(&pgproto3.AuthenticationSASLContinue{Data: serverFirst}); err != nil {
		return err
	}
	clientFinal, err := receiveSASLResponse(backend)
	if err != nil {
		return err
	}
	serverFinal, err := scram.ServerFinal(clientFinal)
	if err != nil {
		return err
	}
	if err = backend.Send(&pgproto3.AuthenticationSASLFinal{Data: serverFinal}); err != nil {
		return err
	}
	return backend.Send(&pgproto3.AuthenticationOk{})
}

// AuthenticateDownstream performs the proxy-as-SCRAM-client handshake against
// the backend (CNPG) on an established connection: it sends the
// startup message, satisfies AuthenticationSASL via scram, and consumes the
// backend's AuthenticationOk. The post-auth ParameterStatus/BackendKeyData/
// ReadyForQuery messages are forwarded to the client by the message pump. It
// returns the Frontend for that pump.
func AuthenticateDownstream(conn io.ReadWriter, params map[string]string, scram *ScramClient) (*pgproto3.Frontend, error) {
	frontend := pgproto3.NewFrontend(pgproto3.NewChunkReader(conn), conn)
	startup := &pgproto3.StartupMessage{ProtocolVersion: pgproto3.ProtocolVersionNumber, Parameters: params}
	if err := frontend.Send(startup); err != nil {
		return nil, fmt.Errorf("wire: send startup: %w", err)
	}
	if err := runDownstreamSASL(frontend, scram); err != nil {
		return nil, err
	}
	return frontend, nil
}

func runDownstreamSASL(frontend *pgproto3.Frontend, scram *ScramClient) error {
	saslReq, err := expectBackend[*pgproto3.AuthenticationSASL](frontend)
	if err != nil {
		return err
	}
	if !containsString(saslReq.AuthMechanisms, scramMechanism) {
		return fmt.Errorf("wire: backend does not offer %s: %v", scramMechanism, saslReq.AuthMechanisms)
	}

	clientFirst, err := scram.ClientFirst()
	if err != nil {
		return err
	}
	if err = frontend.Send(&pgproto3.SASLInitialResponse{AuthMechanism: scramMechanism, Data: clientFirst}); err != nil {
		return err
	}

	cont, err := expectBackend[*pgproto3.AuthenticationSASLContinue](frontend)
	if err != nil {
		return err
	}
	clientFinal, err := scram.ClientFinal(cont.Data)
	if err != nil {
		return err
	}
	if err = frontend.Send(&pgproto3.SASLResponse{Data: clientFinal}); err != nil {
		return err
	}

	final, err := expectBackend[*pgproto3.AuthenticationSASLFinal](frontend)
	if err != nil {
		return err
	}
	if err = scram.VerifyServerFinal(final.Data); err != nil {
		return err
	}
	_, err = expectBackend[*pgproto3.AuthenticationOk](frontend)
	return err
}

// expectBackend reads one backend message and asserts its type.
func expectBackend[T pgproto3.BackendMessage](frontend *pgproto3.Frontend) (T, error) {
	var zero T
	msg, err := frontend.Receive()
	if err != nil {
		return zero, fmt.Errorf("wire: receive: %w", err)
	}
	typed, ok := msg.(T)
	if !ok {
		return zero, fmt.Errorf("wire: unexpected backend message %T", msg)
	}
	return typed, nil
}

func containsString(haystack []string, needle string) bool {
	for _, s := range haystack {
		if s == needle {
			return true
		}
	}
	return false
}

func receiveSASLInitial(backend *pgproto3.Backend) ([]byte, error) {
	if err := backend.SetAuthType(pgproto3.AuthTypeSASL); err != nil {
		return nil, err
	}
	msg, err := backend.Receive()
	if err != nil {
		return nil, fmt.Errorf("wire: receive sasl-initial: %w", err)
	}
	sir, ok := msg.(*pgproto3.SASLInitialResponse)
	if !ok {
		return nil, fmt.Errorf("wire: expected SASLInitialResponse, got %T", msg)
	}
	if sir.AuthMechanism != scramMechanism {
		return nil, fmt.Errorf("wire: unsupported SASL mechanism %q", sir.AuthMechanism)
	}
	return sir.Data, nil
}

func receiveSASLResponse(backend *pgproto3.Backend) ([]byte, error) {
	if err := backend.SetAuthType(pgproto3.AuthTypeSASLContinue); err != nil {
		return nil, err
	}
	msg, err := backend.Receive()
	if err != nil {
		return nil, fmt.Errorf("wire: receive sasl-response: %w", err)
	}
	sr, ok := msg.(*pgproto3.SASLResponse)
	if !ok {
		return nil, fmt.Errorf("wire: expected SASLResponse, got %T", msg)
	}
	return sr.Data, nil
}
