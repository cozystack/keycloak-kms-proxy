// Package crypto implements the column-value encryption primitives: the
// self-describing ciphertext envelope marker, deterministic
// AEAD (AES-SIV) for searched columns, and non-deterministic AEAD (AES-GCM)
// for unsearched columns. Values without a marker are treated as plaintext
// to support backfill coexistence on a live database.
package crypto
