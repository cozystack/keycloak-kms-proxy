package wire

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/binary"
	"encoding/pem"
	"io"
	"math/big"
	"net"
	"testing"
	"time"
)

// genTestCert generates a 1-hour self-signed cert+key for serverName and
// returns the PEM-encoded chain (cert), key, and a tls.Certificate ready to
// install on a tls.Listener.
func genTestCert(t *testing.T, serverName string) (caPEM []byte, srvCert tls.Certificate) {
	t.Helper()
	priv, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("rsa: %v", err)
	}
	tmpl := &x509.Certificate{
		SerialNumber:          big.NewInt(1),
		Subject:               pkix.Name{CommonName: serverName},
		NotBefore:             time.Now().Add(-time.Minute),
		NotAfter:              time.Now().Add(time.Hour),
		DNSNames:              []string{serverName},
		IPAddresses:           []net.IP{net.ParseIP("127.0.0.1"), net.ParseIP("::1")},
		KeyUsage:              x509.KeyUsageDigitalSignature | x509.KeyUsageKeyEncipherment | x509.KeyUsageCertSign,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		IsCA:                  true,
		BasicConstraintsValid: true,
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &priv.PublicKey, priv)
	if err != nil {
		t.Fatalf("create cert: %v", err)
	}
	certPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})
	keyPEM := pem.EncodeToMemory(&pem.Block{Type: "RSA PRIVATE KEY", Bytes: x509.MarshalPKCS1PrivateKey(priv)})
	srvCert, err = tls.X509KeyPair(certPEM, keyPEM)
	if err != nil {
		t.Fatalf("x509 keypair: %v", err)
	}
	return certPEM, srvCert
}

// fakeBackend listens on 127.0.0.1, performs the PG SSLRequest handshake
// with a configurable reply, and (if the reply was 'S') completes the TLS
// handshake using cert. It signals completion on done so the test can wait.
func fakeBackend(t *testing.T, reply byte, cert tls.Certificate) (addr string, done chan error) {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	done = make(chan error, 1)
	go func() {
		defer func() { _ = ln.Close() }()
		c, err := ln.Accept()
		if err != nil {
			done <- err
			return
		}
		defer func() { _ = c.Close() }()
		head := make([]byte, 8)
		if _, err := io.ReadFull(c, head); err != nil {
			done <- err
			return
		}
		if binary.BigEndian.Uint32(head[0:4]) != 8 || binary.BigEndian.Uint32(head[4:8]) != sslRequestCode {
			done <- io.ErrUnexpectedEOF
			return
		}
		if _, err := c.Write([]byte{reply}); err != nil {
			done <- err
			return
		}
		if reply == 'S' {
			tc := tls.Server(c, &tls.Config{Certificates: []tls.Certificate{cert}, MinVersion: tls.VersionTLS12})
			if err := tc.Handshake(); err != nil {
				done <- err
				return
			}
			_ = tc.Close()
		}
		done <- nil
	}()
	return ln.Addr().String(), done
}

func TestDialBackendTLS_Accept(t *testing.T) {
	t.Parallel()
	caPEM, cert := genTestCert(t, "127.0.0.1")
	addr, done := fakeBackend(t, 'S', cert)

	cfg, err := LoadBackendCA(caPEM, "127.0.0.1")
	if err != nil {
		t.Fatalf("LoadBackendCA: %v", err)
	}
	c, err := DialBackendTLS(addr, cfg)
	if err != nil {
		t.Fatalf("DialBackendTLS: %v", err)
	}
	_ = c.Close()
	if err := <-done; err != nil {
		t.Errorf("backend: %v", err)
	}
}

func TestDialBackendTLS_BackendRefused(t *testing.T) {
	t.Parallel()
	caPEM, cert := genTestCert(t, "127.0.0.1")
	addr, done := fakeBackend(t, 'N', cert)
	cfg, err := LoadBackendCA(caPEM, "127.0.0.1")
	if err != nil {
		t.Fatalf("LoadBackendCA: %v", err)
	}
	_, err = DialBackendTLS(addr, cfg)
	if err == nil {
		t.Fatal("DialBackendTLS accepted a backend that refused TLS")
	}
	<-done
}

func TestDialBackendTLS_NilConfigPlaintext(t *testing.T) {
	t.Parallel()
	// Backend that immediately closes without expecting SSLRequest — the
	// dial with nil tlsConfig must skip negotiation entirely.
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	go func() {
		c, _ := ln.Accept()
		if c != nil {
			_ = c.Close()
		}
	}()
	defer func() { _ = ln.Close() }()

	c, err := DialBackendTLS(ln.Addr().String(), nil)
	if err != nil {
		t.Fatalf("plaintext dial: %v", err)
	}
	_ = c.Close()
}

func TestLoadBackendCA_Empty(t *testing.T) {
	t.Parallel()
	cfg, err := LoadBackendCA(nil, "x")
	if err != nil || cfg != nil {
		t.Errorf("nil CA: cfg=%v err=%v, want nil/nil", cfg, err)
	}
}
