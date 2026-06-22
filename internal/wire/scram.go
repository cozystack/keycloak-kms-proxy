package wire

import (
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/base64"
	"errors"
	"fmt"
	"strings"

	"golang.org/x/crypto/pbkdf2"
)

// ScramVerifier holds the stored SCRAM-SHA-256 credentials for a user (RFC 5802
// §3): the salt and iteration count plus the derived StoredKey and ServerKey.
// The cleartext password is never stored.
type ScramVerifier struct {
	Salt       []byte
	Iterations int
	StoredKey  []byte
	ServerKey  []byte
}

// MakeScramVerifier derives a verifier from a cleartext password, for
// configuration and tests (RFC 5802 §3).
func MakeScramVerifier(password string, salt []byte, iterations int) ScramVerifier {
	salted := saltedPassword(password, salt, iterations)
	clientKey := scramHMAC(salted, []byte("Client Key"))
	return ScramVerifier{
		Salt:       salt,
		Iterations: iterations,
		StoredKey:  scramH(clientKey),
		ServerKey:  scramHMAC(salted, []byte("Server Key")),
	}
}

// VerifierLookup returns the stored verifier for a username.
type VerifierLookup func(username string) (ScramVerifier, bool)

// ScramServer runs the SCRAM-SHA-256 server side for the upstream leg: the proxy
// authenticates Keycloak. When channel binding is in use, cbind
// holds the binding data (e.g. the tls-server-end-point hash of the proxy's own
// certificate) that the client's gs2 header must match. The authoritative
// username may be set out-of-band via SetUsername — PostgreSQL clients send
// n=* in SCRAM and carry the real username in the StartupMessage.
type ScramServer struct {
	lookup   VerifierLookup
	cbind    []byte
	nonce    func() (string, error)
	username string

	verifier        ScramVerifier
	clientFirstBare string
	serverFirst     string
	gs2Header       string
	step            int
}

// NewScramServer builds a SCRAM server that resolves credentials via lookup. If
// cbind is non-nil, SCRAM-SHA-256-PLUS channel binding is required and verified
// against it; otherwise the client must not request channel binding.
func NewScramServer(lookup VerifierLookup, cbind []byte) *ScramServer {
	return &ScramServer{lookup: lookup, cbind: cbind, nonce: randomNonce}
}

// SetUsername fixes the authoritative username for verifier lookup, overriding
// the SCRAM n= field. PostgreSQL clients send n=* in SCRAM and carry the real
// identity in the StartupMessage; the caller (AuthenticateUpstream) wires that
// here.
func (s *ScramServer) SetUsername(username string) { s.username = username }

// ServerFirst processes the client-first message and returns the server-first
// message (RFC 5802 §5).
func (s *ScramServer) ServerFirst(clientFirst []byte) ([]byte, error) {
	if s.step != 0 {
		return nil, errors.New("scram: server-first out of order")
	}
	gs2, bare, username, clientNonce, err := parseClientFirst(string(clientFirst))
	if err != nil {
		return nil, err
	}
	if cberr := s.checkChannelBindingFlag(gs2); cberr != nil {
		return nil, cberr
	}
	lookupName := username
	if s.username != "" {
		lookupName = s.username
	}
	verifier, ok := s.lookup(lookupName)
	if !ok {
		return nil, fmt.Errorf("scram: unknown user %q", lookupName)
	}

	serverNonce, err := s.nonce()
	if err != nil {
		return nil, err
	}

	s.verifier = verifier
	s.gs2Header = gs2
	s.clientFirstBare = bare
	s.serverFirst = fmt.Sprintf("r=%s%s,s=%s,i=%d",
		clientNonce, serverNonce,
		base64.StdEncoding.EncodeToString(verifier.Salt),
		verifier.Iterations)
	s.step = 1
	return []byte(s.serverFirst), nil
}

// ServerFinal verifies the client-final message and returns the server-final
// message carrying the server signature (RFC 5802 §5).
func (s *ScramServer) ServerFinal(clientFinal []byte) ([]byte, error) {
	if s.step != 1 {
		return nil, errors.New("scram: server-final out of order")
	}
	channelBinding, withoutProof, proof, err := parseClientFinal(string(clientFinal))
	if err != nil {
		return nil, err
	}
	if cberr := s.verifyChannelBinding(channelBinding); cberr != nil {
		return nil, cberr
	}

	authMessage := s.clientFirstBare + "," + s.serverFirst + "," + withoutProof
	clientSignature := scramHMAC(s.verifier.StoredKey, []byte(authMessage))
	if len(proof) != len(clientSignature) {
		return nil, errors.New("scram: malformed client proof")
	}
	clientKey := xorBytes(proof, clientSignature)
	if subtle.ConstantTimeCompare(scramH(clientKey), s.verifier.StoredKey) != 1 {
		return nil, errors.New("scram: authentication failed")
	}

	serverSignature := scramHMAC(s.verifier.ServerKey, []byte(authMessage))
	s.step = 2
	return []byte("v=" + base64.StdEncoding.EncodeToString(serverSignature)), nil
}

func (s *ScramServer) checkChannelBindingFlag(gs2 string) error {
	flag := gs2
	if i := strings.IndexByte(gs2, ','); i >= 0 {
		flag = gs2[:i]
	}
	usesBinding := strings.HasPrefix(flag, "p=")
	if usesBinding != (s.cbind != nil) {
		return errors.New("scram: channel binding flag does not match server policy")
	}
	return nil
}

func (s *ScramServer) verifyChannelBinding(channelBinding string) error {
	raw, err := base64.StdEncoding.DecodeString(channelBinding)
	if err != nil {
		return fmt.Errorf("scram: bad channel binding: %w", err)
	}
	expected := append([]byte(s.gs2Header), s.cbind...)
	if subtle.ConstantTimeCompare(raw, expected) != 1 {
		return errors.New("scram: channel binding mismatch")
	}
	return nil
}

func parseClientFirst(msg string) (gs2Header, bare, username, nonce string, err error) {
	first := strings.IndexByte(msg, ',')
	if first < 0 {
		return "", "", "", "", errors.New("scram: malformed client-first (gs2 flag)")
	}
	second := strings.IndexByte(msg[first+1:], ',')
	if second < 0 {
		return "", "", "", "", errors.New("scram: malformed client-first (authzid)")
	}
	cut := first + 1 + second + 1
	gs2Header = msg[:cut]
	bare = msg[cut:]

	for _, field := range strings.Split(bare, ",") {
		switch {
		case strings.HasPrefix(field, "n="):
			username = decodeSaslName(field[2:])
		case strings.HasPrefix(field, "r="):
			nonce = field[2:]
		}
	}
	// PostgreSQL clients commonly send an empty SCRAM n= (libpq) or n=* (pgjdbc)
	// and carry the real identity in the StartupMessage; the verifier lookup
	// uses ScramServer.SetUsername. Only the nonce is structurally required.
	if nonce == "" {
		return "", "", "", "", errors.New("scram: client-first missing nonce")
	}
	return gs2Header, bare, username, nonce, nil
}

func parseClientFinal(msg string) (channelBinding, withoutProof string, proof []byte, err error) {
	idx := strings.LastIndex(msg, ",p=")
	if idx < 0 {
		return "", "", nil, errors.New("scram: client-final missing proof")
	}
	withoutProof = msg[:idx]
	proofB64 := msg[idx+len(",p="):]
	proof, err = base64.StdEncoding.DecodeString(proofB64)
	if err != nil {
		return "", "", nil, fmt.Errorf("scram: bad proof: %w", err)
	}

	for _, field := range strings.Split(withoutProof, ",") {
		if strings.HasPrefix(field, "c=") {
			channelBinding = field[2:]
		}
	}
	if channelBinding == "" {
		return "", "", nil, errors.New("scram: client-final missing channel binding")
	}
	return channelBinding, withoutProof, proof, nil
}

// decodeSaslName reverses the SASLprep =2C/=3D escaping of usernames (RFC 5802).
func decodeSaslName(s string) string {
	s = strings.ReplaceAll(s, "=2C", ",")
	s = strings.ReplaceAll(s, "=3D", "=")
	return s
}

func saltedPassword(password string, salt []byte, iterations int) []byte {
	return pbkdf2.Key([]byte(password), salt, iterations, sha256.Size, sha256.New)
}

func scramHMAC(key, data []byte) []byte {
	h := hmac.New(sha256.New, key)
	h.Write(data)
	return h.Sum(nil)
}

func scramH(data []byte) []byte {
	sum := sha256.Sum256(data)
	return sum[:]
}

func xorBytes(a, b []byte) []byte {
	out := make([]byte, len(a))
	for i := range a {
		out[i] = a[i] ^ b[i]
	}
	return out
}

func randomNonce() (string, error) {
	raw := make([]byte, 18)
	if _, err := rand.Read(raw); err != nil {
		return "", fmt.Errorf("scram: nonce: %w", err)
	}
	return base64.RawStdEncoding.EncodeToString(raw), nil
}
