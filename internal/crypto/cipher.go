package crypto

import (
	"errors"
	"fmt"
)

// ErrKeyVersionMismatch means a stored value was encrypted under a different
// DEK/scheme version than this Cipher holds. The rotation layer
// routes such values to a Cipher pinned to the matching version.
var ErrKeyVersionMismatch = errors.New("crypto: key version mismatch")

// Cipher is the per-value encryption facade: it selects a
// primitive by scheme, wraps ciphertext in the self-describing marker on write,
// and on read either decrypts a marked value or passes a markerless (plaintext,
// not-yet-migrated) value through untouched for backfill coexistence. It also
// optionally exposes a blind-index hasher so the
// proxy can populate and search shadow hash columns.
type Cipher struct {
	primitives map[Scheme]Primitive
	index      *BlindIndex
	keyVersion uint32
}

// NewCipher builds a Cipher at the given key version from the supplied AEAD
// primitives and an optional blind-index hasher (may be nil). Each primitive
// registers under its own Scheme; duplicate or nil primitives are rejected.
func NewCipher(keyVersion uint32, index *BlindIndex, primitives ...Primitive) (*Cipher, error) {
	m := make(map[Scheme]Primitive, len(primitives))
	for _, p := range primitives {
		if p == nil {
			return nil, errors.New("crypto: nil primitive")
		}
		if _, dup := m[p.Scheme()]; dup {
			return nil, fmt.Errorf("crypto: duplicate primitive for scheme %v", p.Scheme())
		}
		m[p.Scheme()] = p
	}
	return &Cipher{primitives: m, index: index, keyVersion: keyVersion}, nil
}

// BlindIndex returns the cipher's blind-index hasher, or nil if none was
// configured.
func (c *Cipher) BlindIndex() *BlindIndex { return c.index }

// Encrypt encrypts plaintext under the requested scheme and returns the textual
// envelope to store. associatedData binds the ciphertext to its column context
// and must be reproduced on Decrypt.
func (c *Cipher) Encrypt(scheme Scheme, plaintext, associatedData []byte) (string, error) {
	p, ok := c.primitives[scheme]
	if !ok {
		return "", fmt.Errorf("%w: %v", ErrUnknownScheme, scheme)
	}
	ciphertext, err := p.Encrypt(plaintext, associatedData)
	if err != nil {
		return "", fmt.Errorf("crypto: encrypt: %w", err)
	}
	env := Envelope{Scheme: scheme, KeyVersion: c.keyVersion, Ciphertext: ciphertext}
	return env.Marshal()
}

// Decrypt inspects a stored value. A marked value is decrypted (its scheme and
// key version come from the marker). A markerless value is plaintext that has
// not been migrated yet: it is unescaped and returned unchanged.
func (c *Cipher) Decrypt(stored string, associatedData []byte) ([]byte, error) {
	env, ok, err := Parse(stored)
	if err != nil {
		return nil, err
	}
	if !ok {
		return []byte(Unescape(stored)), nil
	}
	if env.KeyVersion != c.keyVersion {
		return nil, fmt.Errorf("%w: have %d, value uses %d", ErrKeyVersionMismatch, c.keyVersion, env.KeyVersion)
	}
	p, ok := c.primitives[env.Scheme]
	if !ok {
		return nil, fmt.Errorf("%w: %v", ErrUnknownScheme, env.Scheme)
	}
	plaintext, err := p.Decrypt(env.Ciphertext, associatedData)
	if err != nil {
		return nil, fmt.Errorf("crypto: decrypt: %w", err)
	}
	return plaintext, nil
}
