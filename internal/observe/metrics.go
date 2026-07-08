// Package observe holds the proxy's Prometheus counters that are emitted
// from the data path (wire/rewrite). They register against the default
// Prometheus registry on import, so the metrics endpoint in cmd/proxy
// exposes them automatically.
package observe

import "github.com/prometheus/client_golang/prometheus"

var (
	// DecryptTotal counts every PII field decrypt the proxy applies on a
	// DataRow return value. Labels identify the column so dashboards can
	// see traffic shape (login flow vs admin REST etc.).
	DecryptTotal = prometheus.NewCounterVec(prometheus.CounterOpts{
		Name: "kkp_decrypt_total",
		Help: "Number of PII column values decrypted on DataRow.",
	}, []string{"table", "column"})

	// DecryptFailures counts decrypt errors broken out by reason. Production
	// dashboards alert on any non-zero value here — it signals DEK
	// divergence (e.g. proxy reading rows written under a different key) or
	// data corruption.
	DecryptFailures = prometheus.NewCounterVec(prometheus.CounterOpts{
		Name: "kkp_decrypt_failures_total",
		Help: "Number of PII column decrypt failures, by table/column/reason.",
	}, []string{"table", "column", "reason"})

	// EncryptTotal counts every PII parameter the proxy encrypts on Bind.
	EncryptTotal = prometheus.NewCounterVec(prometheus.CounterOpts{
		Name: "kkp_encrypt_total",
		Help: "Number of PII parameter values encrypted on Bind.",
	}, []string{"table", "column"})

	// UnrecognizedPIISQL counts SELECTs that mention a PII table but the
	// analyser could not extract a target — i.e. the read path silently
	// passed ciphertext through. Tracks the conformance gap at runtime.
	UnrecognizedPIISQL = prometheus.NewCounter(prometheus.CounterOpts{
		Name: "kkp_unrecognized_pii_sql_total",
		Help: "PII-touching SELECTs the analyser could not plan against (silent-ciphertext hazard).",
	})

	// KMSCallTotal counts calls to the KMS layer (wrap/unwrap of DEKs) so
	// capacity planning has hard numbers. The proxy caches DEKs after the
	// first unwrap, so steady-state this should be flat after warmup.
	KMSCallTotal = prometheus.NewCounterVec(prometheus.CounterOpts{
		Name: "kkp_kms_calls_total",
		Help: "Calls to the KMS (Encrypt/Decrypt of DEKs), by op and outcome.",
	}, []string{"op", "outcome"})

	// CiphertextPassthrough counts DataRows that left the proxy still
	// carrying a ciphertext envelope because no decrypt plan matched, by
	// reason. Any non-zero value is an incident: the client saw raw $KKP$
	// blobs (the verify-email failure class).
	CiphertextPassthrough = prometheus.NewCounterVec(prometheus.CounterOpts{
		Name: "kkp_ciphertext_passthrough_total",
		Help: "DataRows passed through undecrypted despite carrying a ciphertext envelope, by reason.",
	}, []string{"reason"})

	// DoubleEncrypted counts decrypted values that still carry a ciphertext
	// envelope: rows whose stored value IS a leaked ciphertext (written back
	// by the client during a passthrough window and encrypted again). Used
	// to inventory corrupted rows for cleanup.
	DoubleEncrypted = prometheus.NewCounterVec(prometheus.CounterOpts{
		Name: "kkp_double_encrypted_total",
		Help: "Decrypted values still carrying a ciphertext envelope (double-encrypted rows), by table/column.",
	}, []string{"table", "column"})
)

func init() {
	prometheus.MustRegister(
		DecryptTotal, DecryptFailures, EncryptTotal,
		UnrecognizedPIISQL, KMSCallTotal, CiphertextPassthrough,
		DoubleEncrypted,
	)
}
