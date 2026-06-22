package crypto

import (
	"encoding/base64"
	"errors"
	"fmt"
	"strconv"
	"strings"
)

// Scheme identifies the encryption scheme applied to a value.
type Scheme uint8

const (
	// SchemeDeterministic is AES-SIV: equal plaintext yields equal ciphertext,
	// used for searched columns (username, email).
	SchemeDeterministic Scheme = iota
	// SchemeNonDeterministic is AES-GCM: a fresh nonce per encryption, used for
	// unsearched columns (names, credential secrets, long attribute values).
	SchemeNonDeterministic
)

// String renders the scheme for diagnostics.
func (s Scheme) String() string {
	switch s {
	case SchemeDeterministic:
		return "deterministic"
	case SchemeNonDeterministic:
		return "non-deterministic"
	default:
		return "Scheme(" + strconv.Itoa(int(s)) + ")"
	}
}

const (
	// sentinel marks a value as one of our encrypted envelopes. The MLukman
	// provider uses a "$"-prefix marker as precedent.
	sentinel = "$KKP$"
	// escapeMarker follows the sentinel to denote an escaped plaintext that
	// legitimately begins with the sentinel; "=" is never a valid envelope
	// header start (which always begins with a format-version digit).
	escapeMarker = "="
	// markerFormatVersion versions the textual envelope format itself.
	markerFormatVersion = 1
	// fieldSep separates header fields; it is absent from base64url payloads.
	fieldSep = "."

	schemeCharDeterministic    = "d"
	schemeCharNonDeterministic = "n"

	headerFields = 4
)

// Sentinel-related errors. Parse wraps these so callers can match with
// errors.Is.
var (
	// ErrMalformedEnvelope means the value carried the sentinel but its header
	// could not be parsed.
	ErrMalformedEnvelope = errors.New("crypto: malformed ciphertext envelope")
	// ErrUnsupportedFormat means the marker format version is newer/unknown.
	ErrUnsupportedFormat = errors.New("crypto: unsupported marker format version")
	// ErrUnknownScheme means the scheme id is not recognized.
	ErrUnknownScheme = errors.New("crypto: unknown encryption scheme")
)

// Envelope is the self-describing wrapper around an encrypted value: the
// scheme, the DEK/scheme version (for rotation), and the opaque AEAD output
// (the per-encryption nonce is embedded in Ciphertext for non-deterministic
// values).
type Envelope struct {
	Scheme     Scheme
	KeyVersion uint32
	Ciphertext []byte
}

// Marshal renders the envelope to its textual on-the-wire form,
// "$KKP$<fmt>.<scheme>.<keyver>.<payloadB64url>".
func (e Envelope) Marshal() (string, error) {
	var schemeChar string
	switch e.Scheme {
	case SchemeDeterministic:
		schemeChar = schemeCharDeterministic
	case SchemeNonDeterministic:
		schemeChar = schemeCharNonDeterministic
	default:
		return "", fmt.Errorf("%w: %d", ErrUnknownScheme, uint8(e.Scheme))
	}

	payload := base64.RawURLEncoding.EncodeToString(e.Ciphertext)
	return fmt.Sprintf("%s%d%s%s%s%d%s%s",
		sentinel, markerFormatVersion, fieldSep,
		schemeChar, fieldSep,
		e.KeyVersion, fieldSep,
		payload), nil
}

// Parse inspects a stored value. When it carries a valid envelope header, the
// parsed Envelope is returned with ok=true. A value without the sentinel, or
// an escaped sentinel collision, is plaintext: ok=false and err=nil so the
// proxy passes it through (use Unescape to recover the original). A value that
// carries the sentinel but is otherwise corrupt returns a non-nil error.
func Parse(stored string) (Envelope, bool, error) {
	if !strings.HasPrefix(stored, sentinel) {
		return Envelope{}, false, nil
	}
	rest := stored[len(sentinel):]
	if strings.HasPrefix(rest, escapeMarker) {
		return Envelope{}, false, nil
	}

	parts := strings.SplitN(rest, fieldSep, headerFields)
	if len(parts) != headerFields {
		return Envelope{}, false, fmt.Errorf("%w: want %d header fields", ErrMalformedEnvelope, headerFields)
	}

	if fv, err := strconv.Atoi(parts[0]); err != nil {
		return Envelope{}, false, fmt.Errorf("%w: bad format version %q", ErrMalformedEnvelope, parts[0])
	} else if fv != markerFormatVersion {
		return Envelope{}, false, fmt.Errorf("%w: %d", ErrUnsupportedFormat, fv)
	}

	scheme, err := parseScheme(parts[1])
	if err != nil {
		return Envelope{}, false, err
	}

	keyVer, err := strconv.ParseUint(parts[2], 10, 32)
	if err != nil {
		return Envelope{}, false, fmt.Errorf("%w: bad key version %q", ErrMalformedEnvelope, parts[2])
	}

	ciphertext, err := base64.RawURLEncoding.DecodeString(parts[3])
	if err != nil {
		return Envelope{}, false, fmt.Errorf("%w: bad payload: %v", ErrMalformedEnvelope, err) //nolint:errorlint // payload error is informational only
	}

	return Envelope{Scheme: scheme, KeyVersion: uint32(keyVer), Ciphertext: ciphertext}, true, nil
}

func parseScheme(s string) (Scheme, error) {
	switch s {
	case schemeCharDeterministic:
		return SchemeDeterministic, nil
	case schemeCharNonDeterministic:
		return SchemeNonDeterministic, nil
	default:
		return 0, fmt.Errorf("%w: %q", ErrUnknownScheme, s)
	}
}

// Escape protects a plaintext value that legitimately begins with the sentinel
// so it is not later mistaken for an encrypted envelope. It is a
// no-op for values that do not collide.
func Escape(plaintext string) string {
	if strings.HasPrefix(plaintext, sentinel) {
		return sentinel + escapeMarker + plaintext
	}
	return plaintext
}

// Unescape reverses Escape, recovering the original plaintext. It is a no-op
// for values that were not escaped.
func Unescape(stored string) string {
	prefix := sentinel + escapeMarker
	if strings.HasPrefix(stored, prefix) {
		return stored[len(prefix):]
	}
	return stored
}
