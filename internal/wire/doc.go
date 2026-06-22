// Package wire implements the stateful, per-connection PostgreSQL wire
// protocol state machine built on jackc/pgproto3. It terminates
// SCRAM on both legs, tracks prepared statements, and applies
// encrypt-on-Bind / decrypt-on-DataRow to PII-touching statements while
// passing everything else through as raw bytes.
package wire
