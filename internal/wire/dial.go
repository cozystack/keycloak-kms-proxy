package wire

import (
	"crypto/tls"
	"crypto/x509"
	"encoding/binary"
	"fmt"
	"io"
	"net"
)

// DialBackendTLS opens a TCP connection to addr, performs the PG in-band
// SSLRequest negotiation, and, if the backend agrees ('S'), upgrades to TLS
// against tlsConfig. If the backend declines ('N') the
// function returns an error — production must refuse plaintext when a TLS
// config was supplied. Pass tlsConfig=nil to keep the legacy plaintext dial.
func DialBackendTLS(addr string, tlsConfig *tls.Config) (net.Conn, error) {
	c, err := net.Dial("tcp", addr)
	if err != nil {
		return nil, err
	}
	if tlsConfig == nil {
		return c, nil
	}

	// PG SSLRequest: 4-byte length=8, 4-byte magic.
	req := make([]byte, 8)
	binary.BigEndian.PutUint32(req[0:4], 8)
	binary.BigEndian.PutUint32(req[4:8], sslRequestCode)
	if _, err := c.Write(req); err != nil {
		_ = c.Close()
		return nil, fmt.Errorf("wire: send SSLRequest to %s: %w", addr, err)
	}
	reply := make([]byte, 1)
	if _, err := io.ReadFull(c, reply); err != nil {
		_ = c.Close()
		return nil, fmt.Errorf("wire: read SSLRequest reply from %s: %w", addr, err)
	}
	if reply[0] != 'S' {
		_ = c.Close()
		return nil, fmt.Errorf("wire: backend %s refused TLS (replied %q)", addr, reply[0])
	}
	tc := tls.Client(c, tlsConfig)
	if err := tc.Handshake(); err != nil {
		_ = c.Close()
		return nil, fmt.Errorf("wire: tls handshake with %s: %w", addr, err)
	}
	return tc, nil
}

// LoadBackendCA reads a PEM CA file and returns a *tls.Config suitable for
// DialBackendTLS. serverName is what the cert SAN must match (e.g. the
// service DNS). If caPEM is empty the call returns nil + nil so callers can
// chain through to the plaintext dial.
func LoadBackendCA(caPEM []byte, serverName string) (*tls.Config, error) {
	if len(caPEM) == 0 {
		return nil, nil
	}
	pool := x509.NewCertPool()
	if !pool.AppendCertsFromPEM(caPEM) {
		return nil, fmt.Errorf("wire: PEM has no CA certs")
	}
	return &tls.Config{
		RootCAs:    pool,
		ServerName: serverName,
		MinVersion: tls.VersionTLS12,
	}, nil
}
