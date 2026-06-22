package wire

import (
	"bytes"
	"crypto/tls"
	"encoding/binary"
	"fmt"
	"io"
	"net"
)

// sslRequestCode is the PG protocol code for SSLRequest (RFC §47 — 80877103).
const sslRequestCode = 80877103

// MaybeUpgradeTLS performs the PostgreSQL in-band SSL negotiation on a freshly
// accepted client connection. If the client sends SSLRequest
// and tlsConfig is non-nil, the proxy responds 'S' and the connection is
// upgraded to TLS; the returned conn/reader read and write through the
// tls.Conn. Otherwise the proxy declines ('N' for SSLRequest, or no response
// for a direct StartupMessage) and returns the original conn with a reader
// that preserves any consumed bytes so AuthenticateUpstream sees them.
func MaybeUpgradeTLS(conn net.Conn, tlsConfig *tls.Config) (net.Conn, io.Reader, error) {
	head := make([]byte, 8)
	if _, err := io.ReadFull(conn, head); err != nil {
		return nil, nil, fmt.Errorf("wire: read startup prefix: %w", err)
	}
	if !isSSLRequest(head) {
		// Not SSLRequest — preserve the bytes for AuthenticateUpstream.
		return conn, io.MultiReader(bytes.NewReader(head), conn), nil
	}
	if tlsConfig == nil {
		if _, err := conn.Write([]byte{'N'}); err != nil {
			return nil, nil, fmt.Errorf("wire: decline ssl: %w", err)
		}
		return conn, conn, nil
	}
	if _, err := conn.Write([]byte{'S'}); err != nil {
		return nil, nil, fmt.Errorf("wire: accept ssl: %w", err)
	}
	tlsConn := tls.Server(conn, tlsConfig)
	if err := tlsConn.Handshake(); err != nil {
		return nil, nil, fmt.Errorf("wire: tls handshake: %w", err)
	}
	return tlsConn, tlsConn, nil
}

func isSSLRequest(head []byte) bool {
	if len(head) != 8 {
		return false
	}
	if binary.BigEndian.Uint32(head[0:4]) != 8 {
		return false
	}
	return binary.BigEndian.Uint32(head[4:8]) == sslRequestCode
}
