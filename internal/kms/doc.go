// Package kms provides the pluggable KMS interface and its implementations:
// a fake/static KMS for tests and bootstrap, and HashiCorp Vault
// Transit for production. It implements envelope encryption — the KEK wraps
// the DEK — and KEK rotation that re-wraps the DEK without re-encrypting data.
package kms
