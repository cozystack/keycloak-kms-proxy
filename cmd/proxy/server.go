package main

import (
	"crypto/rand"
	"crypto/tls"
	"errors"
	"fmt"
	"io"
	"log"
	"net"
	"os"
	"sync"
	"time"

	"github.com/cozystack/keycloak-kms-proxy/internal/config"
	"github.com/cozystack/keycloak-kms-proxy/internal/crypto"
	"github.com/cozystack/keycloak-kms-proxy/internal/rewrite"
	"github.com/cozystack/keycloak-kms-proxy/internal/wire"
)

// server accepts Keycloak connections and relays each to the CNPG backend,
// terminating SCRAM on both legs and applying the encryption transforms.
// The per-connection relay (TLS handshake, dual SCRAM,
// message pump) is exercised end to end at the integration milestone; this
// type owns config, the shared cipher/planner, and the accept-loop lifecycle.
type server struct {
	cfg              *config.ProxyConfig
	cipher           *crypto.Cipher
	planner          *rewrite.Planner
	verifier         wire.ScramVerifier
	tlsConfig        *tls.Config
	backendTLSConfig *tls.Config

	mu       sync.Mutex
	listener net.Listener
	wg       sync.WaitGroup
}

// newServer builds a server from validated config and an opened cipher. The
// upstream SCRAM verifier is derived once from the configured Keycloak
// credential.
func newServer(cfg *config.ProxyConfig, cipher *crypto.Cipher) (*server, error) {
	salt := make([]byte, scramSaltLen)
	if _, err := rand.Read(salt); err != nil {
		return nil, fmt.Errorf("proxy: generate scram salt: %w", err)
	}
	planner := rewrite.NewPlanner(cfg.Fields)
	if cfg.Lenient {
		planner = rewrite.NewLenientPlanner(cfg.Fields)
	}

	// TLS re-origination to the backend (CNPG). When BackendCAFile is
	// set, load it once at startup and reuse for every downstream dial.
	var backendTLS *tls.Config
	if cfg.BackendCAFile != "" {
		ca, err := os.ReadFile(cfg.BackendCAFile) //nolint:gosec // trusted env path
		if err != nil {
			return nil, fmt.Errorf("proxy: read backend CA: %w", err)
		}
		serverName := cfg.BackendServerName
		if serverName == "" {
			host, _, splitErr := net.SplitHostPort(cfg.BackendAddr)
			if splitErr == nil {
				serverName = host
			} else {
				serverName = cfg.BackendAddr
			}
		}
		backendTLS, err = wire.LoadBackendCA(ca, serverName)
		if err != nil {
			return nil, fmt.Errorf("proxy: backend CA: %w", err)
		}
		log.Printf("backend TLS enabled (CA=%s, serverName=%s)", cfg.BackendCAFile, serverName)
	}

	return &server{
		cfg:              cfg,
		cipher:           cipher,
		planner:          planner,
		verifier:         wire.MakeScramVerifier(cfg.UpstreamPassword, salt, scramIterations),
		backendTLSConfig: backendTLS,
	}, nil
}

const (
	scramSaltLen    = 16
	scramIterations = 4096
)

// listen binds the proxy's listen address. When TLSCertFile/TLSKeyFile are
// configured the cert+key is loaded into s.tlsConfig; the handler performs the
// PG in-band SSLRequest negotiation per connection.
func (s *server) listen() error {
	ln, err := net.Listen("tcp", s.cfg.ListenAddr)
	if err != nil {
		return err
	}
	if s.cfg.TLSCertFile != "" {
		cert, err := tls.LoadX509KeyPair(s.cfg.TLSCertFile, s.cfg.TLSKeyFile)
		if err != nil {
			_ = ln.Close()
			return fmt.Errorf("proxy: load TLS keypair: %w", err)
		}
		s.tlsConfig = &tls.Config{
			Certificates: []tls.Certificate{cert},
			MinVersion:   tls.VersionTLS12,
		}
		log.Printf("TLS termination enabled (cert=%s)", s.cfg.TLSCertFile)
	}
	s.mu.Lock()
	s.listener = ln
	s.mu.Unlock()
	return nil
}

// addr returns the bound address (useful when listening on :0 in tests).
func (s *server) addr() string {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.listener == nil {
		return ""
	}
	return s.listener.Addr().String()
}

// serve accepts connections until the listener is closed. When
// MaxConnections > 0 the server caps the number of concurrent in-flight
// relays — Accept blocks on a semaphore so the kernel queue absorbs the
// backpressure instead of the process opening unbounded sessions.
func (s *server) serve() error {
	s.mu.Lock()
	ln := s.listener
	s.mu.Unlock()

	var sem chan struct{}
	if s.cfg.MaxConnections > 0 {
		sem = make(chan struct{}, s.cfg.MaxConnections)
	}
	for {
		conn, err := ln.Accept()
		if err != nil {
			if errors.Is(err, net.ErrClosed) {
				return nil
			}
			return err
		}
		if sem != nil {
			sem <- struct{}{} // blocks here when the limit is reached
		}
		// Idle timeout for the upstream handshake — bounds slow-loris.
		if s.cfg.HandshakeTimeout > 0 {
			_ = conn.SetDeadline(time.Now().Add(s.cfg.HandshakeTimeout))
		}
		// Register the connection under the lock close() takes before
		// waiting, so a conn accepted concurrently with close either
		// increments the WaitGroup before close waits or is dropped.
		s.mu.Lock()
		closed := s.listener == nil
		if !closed {
			s.wg.Add(1)
		}
		s.mu.Unlock()
		if closed {
			_ = conn.Close()
			if sem != nil {
				<-sem
			}
			return nil
		}
		go func() {
			defer s.wg.Done()
			defer func() {
				if sem != nil {
					<-sem
				}
			}()
			s.handle(conn)
		}()
	}
}

// close stops accepting and waits for in-flight connections to finish.
func (s *server) close() error {
	s.mu.Lock()
	ln := s.listener
	s.listener = nil
	s.mu.Unlock()
	if ln == nil {
		return nil
	}
	err := ln.Close()
	s.wg.Wait()
	return err
}

// newSession builds the per-connection state machine wired to this server's
// planner and cipher.
func (s *server) newSession() *wire.Session {
	return wire.NewSession(s.planner, s.cipher)
}

// upstreamVerifier resolves the SCRAM verifier for the upstream (Keycloak) leg.
func (s *server) upstreamVerifier(username string) (wire.ScramVerifier, bool) {
	return s.verifier, username == s.cfg.UpstreamUser
}

// handle relays a single client connection to the backend: terminate SCRAM
// upstream, dial and authenticate downstream, then run the encrypting message
// pump. TLS termination/re-origination is layered on at the
// listener/dial sites (deployment).
func (s *server) handle(clientConn net.Conn) {
	defer func() { _ = clientConn.Close() }()
	metricConnections.Inc()

	upConn, upReader, err := wire.MaybeUpgradeTLS(clientConn, s.tlsConfig)
	if err != nil {
		log.Printf("ssl negotiation from %s failed: %v", clientConn.RemoteAddr(), err)
		return
	}

	session := s.newSession()
	scramServer := wire.NewScramServer(s.upstreamVerifier, nil)
	backend, params, err := wire.AuthenticateUpstream(connAdapter{Reader: upReader, Writer: upConn}, scramServer)
	if err != nil {
		metricAuthFailures.Inc()
		metricRelayEnded.WithLabelValues("upstream-auth-failed").Inc()
		log.Printf("upstream auth from %s failed: %v", clientConn.RemoteAddr(), err)
		return
	}

	backendConn, err := wire.DialBackendTLS(s.cfg.BackendAddr, s.backendTLSConfig)
	if err != nil {
		log.Printf("dial backend %s: %v", s.cfg.BackendAddr, err)
		return
	}
	defer func() { _ = backendConn.Close() }()

	scramClient := wire.NewScramClient(s.cfg.BackendUser, s.cfg.BackendPassword, nil)
	frontend, err := wire.AuthenticateDownstream(backendConn, downstreamParams(params, s.cfg.BackendUser), scramClient)
	if err != nil {
		log.Printf("downstream auth to %s failed: %v", s.cfg.BackendAddr, err)
		return
	}

	if err := wire.Relay(session, backend, frontend); err != nil {
		metricRelayEnded.WithLabelValues("error").Inc()
		log.Printf("relay for %s ended: %v", clientConn.RemoteAddr(), err)
		return
	}
	metricRelayEnded.WithLabelValues("ok").Inc()
}

// connAdapter combines a read path (which may carry pushed-back startup bytes
// from MaybeUpgradeTLS) with a write path (the underlying conn or tls.Conn)
// into the io.ReadWriter that AuthenticateUpstream expects.
type connAdapter struct {
	io.Reader
	io.Writer
}

// downstreamParams forwards the client's startup parameters to the backend but
// authenticates as the proxy's own backend user.
func downstreamParams(upstream map[string]string, backendUser string) map[string]string {
	params := make(map[string]string, len(upstream))
	for k, v := range upstream {
		params[k] = v
	}
	params["user"] = backendUser
	return params
}
