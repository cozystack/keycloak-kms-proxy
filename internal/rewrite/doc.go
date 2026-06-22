// Package rewrite parses SQL with pganalyze/pg_query_go and maps statement
// parameters and result columns to the PII columns they touch.
// It drives which Bind parameters are encrypted and which DataRow fields are
// decrypted; unknown statements that touch PII tables must fail loudly.
package rewrite
