package wire

import (
	"bytes"
	"errors"
	"fmt"
	"log"
	"strings"

	"github.com/jackc/pgproto3/v2"

	"github.com/cozystack/keycloak-kms-proxy/internal/crypto"
	"github.com/cozystack/keycloak-kms-proxy/internal/observe"
	"github.com/cozystack/keycloak-kms-proxy/internal/rewrite"
)

// errNoCipher is returned when a statement needs transformation but the session
// has no cipher configured.
var errNoCipher = errors.New("wire: cipher not configured")

// EncryptBind rewrites the bound parameters of a Bind message in place,
// encrypting the PII parameters identified by the statement's write plan,
// evaluating attribute conditions against the bound attribute name, and (for
// blind-index columns) computing HMAC of the plaintext *before* it is
// encrypted and appending it as a new bound parameter so the previously
// rewritten SQL can persist it into the hash column.
func (s *Session) EncryptBind(b *pgproto3.Bind) error {
	stmt := s.statements[b.PreparedStatement]
	if stmt == nil || stmt.WritePlan == nil || stmt.WritePlan.IsEmpty() {
		return nil
	}
	if s.cipher == nil {
		return errNoCipher
	}

	// Compute every blind-index hash from the plaintext sources first, so we
	// see them before encryptParam mutates the slots in place.
	if err := s.appendBlindIndexWrites(b, stmt.WritePlan.BlindIndexWrites); err != nil {
		return err
	}

	for _, pr := range stmt.WritePlan.Params {
		if err := s.encryptParam(b, pr); err != nil {
			return err
		}
	}
	for _, cond := range stmt.WritePlan.AttributeConditions {
		if err := s.applyAttributeCondition(b, cond); err != nil {
			return err
		}
	}
	for _, pr := range stmt.WritePlan.LikeParams {
		if err := s.encryptLikeParam(b, pr); err != nil {
			return err
		}
	}
	for _, f := range stmt.WritePlan.BlindIndexFilters {
		if err := s.hashBlindIndexParam(b, f); err != nil {
			return err
		}
	}
	return nil
}

// appendBlindIndexWrites computes the HMAC of every blind-indexed source
// parameter at its plaintext (pre-encryption) form and appends it to
// b.Parameters at the SQL-allocated slot. ParameterFormatCodes is extended to
// match when it was per-parameter so PG does not reinterpret formats.
func (s *Session) appendBlindIndexWrites(b *pgproto3.Bind, writes []rewrite.BlindIndexWrite) error {
	if len(writes) == 0 {
		return nil
	}
	bi := s.cipher.BlindIndex()
	if bi == nil {
		return errors.New("wire: blind-index write requested but cipher has no key")
	}

	// Pre-allocate space for the new parameters at the SQL-assigned positions.
	maxNew := 0
	for _, w := range writes {
		if w.NewParam > maxNew {
			maxNew = w.NewParam
		}
	}
	if cap(b.Parameters) < maxNew {
		grown := make([][]byte, maxNew)
		copy(grown, b.Parameters)
		b.Parameters = grown
	} else if len(b.Parameters) < maxNew {
		b.Parameters = b.Parameters[:maxNew]
	}

	for _, w := range writes {
		srcIdx := w.SourceParam - 1
		dstIdx := w.NewParam - 1
		if srcIdx < 0 || srcIdx >= len(b.Parameters) || dstIdx < 0 || dstIdx >= len(b.Parameters) {
			return fmt.Errorf("wire: blind-index params out of range (source=$%d, dest=$%d)", w.SourceParam, w.NewParam)
		}
		value := b.Parameters[srcIdx]
		if value == nil {
			b.Parameters[dstIdx] = nil
			continue
		}
		normalized := []byte(crypto.NormalizeLowercase(string(value)))
		hash, err := bi.Compute(normalized, rewrite.AAD(w.Table, w.Column))
		if err != nil {
			return fmt.Errorf("wire: blind index for %s.%s: %w", w.Table, w.Column, err)
		}
		b.Parameters[dstIdx] = []byte(hash)
	}

	// Extend per-parameter format codes to text (0) for the new slots, so PG
	// reads them as text. Empty or single-element codes already apply uniformly.
	if len(b.ParameterFormatCodes) > 1 {
		for len(b.ParameterFormatCodes) < maxNew {
			b.ParameterFormatCodes = append(b.ParameterFormatCodes, 0)
		}
	}
	return nil
}

// hashBlindIndexParam replaces the bound LIKE value with its HMAC so the
// previously-rewritten `<hash_col> = $n` filter matches the stored hash.
// Keycloak's admin search typically wraps user input in `%term%`; strip a
// single leading and trailing `%` before hashing so the lookup is by the
// exact term. Patterns with internal wildcards or wildcards after stripping
// pass through unchanged (the equality will simply find no rows).
func (s *Session) hashBlindIndexParam(b *pgproto3.Bind, f rewrite.BlindIndexFilter) error {
	idx := f.Param - 1
	if idx < 0 || idx >= len(b.Parameters) {
		return fmt.Errorf("wire: parameter $%d out of range", f.Param)
	}
	value := b.Parameters[idx]
	if value == nil {
		return nil
	}

	plaintext := stripOuterWildcards(value)
	if hasLikeWildcards(plaintext) {
		return nil
	}

	bi := s.cipher.BlindIndex()
	if bi == nil {
		return fmt.Errorf("wire: blind index requested for %s.%s but cipher has no key", f.Table, f.Column)
	}
	// Normalise like the deterministic-encryption path so case-insensitive
	// searches match: every blind-indexed column is deterministic + lowercase.
	plaintext = []byte(crypto.NormalizeLowercase(string(plaintext)))
	hash, err := bi.Compute(plaintext, rewrite.AAD(f.Table, f.Column))
	if err != nil {
		return fmt.Errorf("wire: blind index $%d: %w", f.Param, err)
	}
	b.Parameters[idx] = []byte(hash)
	return nil
}

// stripOuterWildcards removes a single leading and trailing `%` so admin UI
// patterns of the form `%term%` reduce to `term`. Escaped `\%` is treated as
// literal.
func stripOuterWildcards(p []byte) []byte {
	if len(p) > 0 && p[0] == '%' {
		p = p[1:]
	}
	if n := len(p); n > 0 && p[n-1] == '%' {
		// Only strip if the trailing `%` is not an escape.
		if n < 2 || p[n-2] != '\\' {
			p = p[:n-1]
		}
	}
	return p
}

// encryptLikeParam encrypts a deterministic-PII LIKE filter parameter only when
// the bound value carries no SQL wildcards (% or _), rewriting the
// `col LIKE :p` filter to an effective equality search. Wildcards leave
// the parameter unchanged so the search semantics on plaintext rows are
// preserved (and on encrypted rows it simply returns no matches).
func (s *Session) encryptLikeParam(b *pgproto3.Bind, pr rewrite.ParamRule) error {
	idx := pr.Param - 1
	if idx < 0 || idx >= len(b.Parameters) {
		return fmt.Errorf("wire: parameter $%d out of range", pr.Param)
	}
	value := b.Parameters[idx]
	if value == nil || hasLikeWildcards(value) {
		return nil
	}
	return s.encryptParam(b, pr)
}

// hasLikeWildcards reports whether the LIKE pattern carries any wildcard
// (% or _) outside of a backslash escape (the SQL default LIKE escape).
func hasLikeWildcards(p []byte) bool {
	for i := 0; i < len(p); i++ {
		switch p[i] {
		case '\\':
			i++ // skip the escaped character.
		case '%', '_':
			return true
		}
	}
	return false
}

func (s *Session) applyAttributeCondition(b *pgproto3.Bind, cond rewrite.AttributeCondition) error {
	name := paramValue(b, cond.NameParam)
	match := name != nil && bytes.HasPrefix(name, []byte(cond.Prefix))
	for _, pr := range cond.ValueParams {
		if match {
			if err := s.encryptParam(b, pr); err != nil {
				return err
			}
			continue
		}
		// Not a PII attribute: leave the value plaintext, but escape a value
		// that collides with the ciphertext sentinel so reads do not mistake
		// it for an envelope.
		escapeParam(b, pr.Param)
	}
	return nil
}

func (s *Session) encryptParam(b *pgproto3.Bind, pr rewrite.ParamRule) error {
	idx := pr.Param - 1
	if idx < 0 || idx >= len(b.Parameters) {
		return fmt.Errorf("wire: parameter $%d out of range", pr.Param)
	}
	value := b.Parameters[idx]
	if value == nil {
		return nil // SQL NULL.
	}

	plaintext := value
	if pr.Rule.LowercaseNormalize {
		plaintext = []byte(crypto.NormalizeLowercase(string(value)))
	}
	stored, err := s.cipher.Encrypt(pr.Rule.Scheme, plaintext, rewrite.AAD(pr.Table, pr.Column))
	if err != nil {
		return fmt.Errorf("wire: encrypt $%d (%s.%s): %w", pr.Param, pr.Table, pr.Column, err)
	}
	observe.EncryptTotal.WithLabelValues(pr.Table, pr.Column).Inc()
	b.Parameters[idx] = []byte(stored)
	return nil
}

// DecryptDataRow rewrites the field values of a DataRow in place, decrypting the
// PII fields identified by the executing portal's read plan.
// Markerless (not-yet-migrated) values pass through unchanged. It is a no-op
// when nothing in the row is encrypted.
func (s *Session) DecryptDataRow(dr *pgproto3.DataRow) error {
	portal := s.CurrentExecuting()
	if portal == nil {
		debugf("kkp: datarow — NO executing portal (race? popped early?) — passthrough %d values", len(dr.Values))
		flagCiphertextLeak(dr, "no-portal")
		return nil
	}
	plan := s.ensureReadPlan(portal)
	if plan == nil {
		debugf("kkp: datarow portal=%q stmt=%q — NO read plan built — passthrough", portal.Name, func() string {
			if portal.Stmt != nil {
				return portal.Stmt.Name
			}
			return ""
		}())
		flagCiphertextLeak(dr, "no-plan")
		return nil
	}
	if plan.IsEmpty() {
		flagCiphertextLeak(dr, "empty-plan")
		return nil
	}
	if s.cipher == nil {
		return errNoCipher
	}

	debugf("kkp: datarow portal=%q decrypting %d fields", portal.Name, len(plan.Fields))
	for _, f := range plan.Fields {
		if f.Index < 0 || f.Index >= len(dr.Values) {
			continue
		}
		value := dr.Values[f.Index]
		if value == nil {
			continue // SQL NULL.
		}
		plaintext, err := s.cipher.Decrypt(string(value), rewrite.AAD(f.Table, f.Column))
		if err != nil {
			observe.DecryptFailures.WithLabelValues(f.Table, f.Column, classifyErr(err)).Inc()
			return fmt.Errorf("wire: decrypt field %d (%s.%s): %w", f.Index, f.Table, f.Column, err)
		}
		observe.DecryptTotal.WithLabelValues(f.Table, f.Column).Inc()
		dr.Values[f.Index] = plaintext
	}
	return nil
}

// flagCiphertextLeak fail-louds (metric + WARN) when a DataRow that could not
// be matched to a decrypt plan carries what looks like one of our ciphertext
// envelopes — the silent-passthrough failure mode behind the verify-email
// incident (raw $KKP$ blobs reaching Keycloak).
func flagCiphertextLeak(dr *pgproto3.DataRow, reason string) {
	for _, v := range dr.Values {
		if v == nil {
			continue
		}
		if _, ok, err := crypto.Parse(string(v)); ok || err != nil {
			observe.CiphertextPassthrough.WithLabelValues(reason).Inc()
			log.Printf("kkp: WARN ciphertext passed through undecrypted (%s) — read-path gap", reason)
			return
		}
	}
}

// classifyErr buckets decrypt errors into low-cardinality reasons for the
// kkp_decrypt_failures_total metric. Refine as new failure modes appear.
func classifyErr(err error) string {
	msg := err.Error()
	switch {
	case strings.Contains(msg, "marker"):
		return "marker"
	case strings.Contains(msg, "key version"):
		return "key-version"
	case strings.Contains(msg, "authentication"), strings.Contains(msg, "tag"):
		return "auth-tag"
	default:
		return "other"
	}
}

func paramValue(b *pgproto3.Bind, param int) []byte {
	idx := param - 1
	if idx < 0 || idx >= len(b.Parameters) {
		return nil
	}
	return b.Parameters[idx]
}

func escapeParam(b *pgproto3.Bind, param int) {
	idx := param - 1
	if idx < 0 || idx >= len(b.Parameters) || b.Parameters[idx] == nil {
		return
	}
	b.Parameters[idx] = []byte(crypto.Escape(string(b.Parameters[idx])))
}
