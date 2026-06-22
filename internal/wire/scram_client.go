package wire

import (
	"crypto/subtle"
	"encoding/base64"
	"errors"
	"fmt"
	"strconv"
	"strings"
)

// cbindName is the channel-binding type used on the downstream leg; PostgreSQL
// uses tls-server-end-point (the hash of the server certificate).
const cbindName = "tls-server-end-point"

// ScramClient runs the SCRAM-SHA-256 client side for the downstream leg: the
// proxy authenticates to CNPG with its own credentials. When
// cbind is non-nil it requests SCRAM-SHA-256-PLUS, binding to the CNPG server
// certificate hash.
type ScramClient struct {
	username string
	password string
	cbind    []byte
	nonce    func() (string, error)

	gs2Header       string
	clientNonce     string
	clientFirstBare string
	serverSignature []byte
	step            int
}

// NewScramClient builds a SCRAM client for the given credentials.
func NewScramClient(username, password string, cbind []byte) *ScramClient {
	return &ScramClient{username: username, password: password, cbind: cbind, nonce: randomNonce}
}

// ClientFirst returns the client-first message (RFC 5802 §5).
func (c *ScramClient) ClientFirst() ([]byte, error) {
	if c.step != 0 {
		return nil, errors.New("scram: client-first out of order")
	}
	nonce, err := c.nonce()
	if err != nil {
		return nil, err
	}
	if c.cbind != nil {
		c.gs2Header = "p=" + cbindName + ",,"
	} else {
		c.gs2Header = "n,,"
	}
	c.clientNonce = nonce
	c.clientFirstBare = "n=" + encodeSaslName(c.username) + ",r=" + nonce
	c.step = 1
	return []byte(c.gs2Header + c.clientFirstBare), nil
}

// ClientFinal consumes the server-first message and returns the client-final
// message carrying the client proof (RFC 5802 §5).
func (c *ScramClient) ClientFinal(serverFirst []byte) ([]byte, error) {
	if c.step != 1 {
		return nil, errors.New("scram: client-final out of order")
	}
	combinedNonce, salt, iterations, err := parseServerFirst(string(serverFirst))
	if err != nil {
		return nil, err
	}
	if !strings.HasPrefix(combinedNonce, c.clientNonce) {
		return nil, errors.New("scram: server nonce does not extend client nonce")
	}

	salted := saltedPassword(c.password, salt, iterations)
	clientKey := scramHMAC(salted, []byte("Client Key"))
	storedKey := scramH(clientKey)

	channelBinding := base64.StdEncoding.EncodeToString(append([]byte(c.gs2Header), c.cbind...))
	withoutProof := "c=" + channelBinding + ",r=" + combinedNonce
	authMessage := c.clientFirstBare + "," + string(serverFirst) + "," + withoutProof

	clientSignature := scramHMAC(storedKey, []byte(authMessage))
	clientProof := xorBytes(clientKey, clientSignature)
	c.serverSignature = scramHMAC(scramHMAC(salted, []byte("Server Key")), []byte(authMessage))
	c.step = 2

	return []byte(withoutProof + ",p=" + base64.StdEncoding.EncodeToString(clientProof)), nil
}

// VerifyServerFinal checks the server signature in the server-final message,
// authenticating the backend to the proxy (RFC 5802 §5).
func (c *ScramClient) VerifyServerFinal(serverFinal []byte) error {
	if c.step != 2 {
		return errors.New("scram: verify out of order")
	}
	msg := string(serverFinal)
	if !strings.HasPrefix(msg, "v=") {
		return errors.New("scram: server-final missing signature")
	}
	got, err := base64.StdEncoding.DecodeString(msg[2:])
	if err != nil {
		return fmt.Errorf("scram: bad server signature: %w", err)
	}
	if subtle.ConstantTimeCompare(got, c.serverSignature) != 1 {
		return errors.New("scram: server signature mismatch")
	}
	c.step = 3
	return nil
}

func parseServerFirst(msg string) (nonce string, salt []byte, iterations int, err error) {
	for _, field := range strings.Split(msg, ",") {
		switch {
		case strings.HasPrefix(field, "r="):
			nonce = field[2:]
		case strings.HasPrefix(field, "s="):
			salt, err = base64.StdEncoding.DecodeString(field[2:])
			if err != nil {
				return "", nil, 0, fmt.Errorf("scram: bad salt: %w", err)
			}
		case strings.HasPrefix(field, "i="):
			iterations, err = strconv.Atoi(field[2:])
			if err != nil {
				return "", nil, 0, fmt.Errorf("scram: bad iteration count: %w", err)
			}
		}
	}
	if nonce == "" || len(salt) == 0 || iterations <= 0 {
		return "", nil, 0, errors.New("scram: malformed server-first")
	}
	return nonce, salt, iterations, nil
}

// encodeSaslName applies the =2C/=3D escaping of usernames (RFC 5802).
func encodeSaslName(s string) string {
	s = strings.ReplaceAll(s, "=", "=3D")
	s = strings.ReplaceAll(s, ",", "=2C")
	return s
}
