# Dependency License Review

This review confirms the proxy's dependency tree is
compatible with the customer's open-source policy. The proxy itself is
Apache-2.0 (see top-level `LICENSE`). The table below is the snapshot
of *direct* imports from `go.mod` that actually enter the runtime
binary; transitive dependencies are listed when the customer policy
requires the full graph (regenerate with `go mod download && go-licenses
report .`).

## Direct runtime dependencies

| Module | Version pinned | License | Role |
|---|---|---|---|
| `github.com/jackc/pgproto3/v2` | go.mod | MIT | PostgreSQL wire-protocol frames (read/write Parse, Bind, DataRow, …) |
| `github.com/pganalyze/pg_query_go/v6` | go.mod | BSD-3-Clause (vendored PostgreSQL parser is PostgreSQL License) | SQL `Analyze` — derives `Table` / `WriteColumns` / `FilterColumns` |
| `github.com/tink-crypto/tink-go/v2` | go.mod | Apache-2.0 | AEAD primitives (`AesGcm`, `AesSiv`, `KMSEnvelopeAEAD`) |
| `github.com/hashicorp/vault/api` | go.mod | MPL-2.0 | Vault Transit KMS client |
| `github.com/prometheus/client_golang` | go.mod | Apache-2.0 | `/metrics` endpoint + counters |
| `github.com/go-logr/logr` (indirect) | go.mod | Apache-2.0 | Structured logger interface used by some deps |

## License-by-license summary

- **Apache-2.0**: tink, prometheus client, logr, the proxy itself.
  Permissive, compatible with both proprietary distribution and AGPL-
  compatible work.
- **MIT**: pgproto3. Most permissive; no concerns.
- **BSD-3-Clause / PostgreSQL License**: pg_query_go and its vendored
  PostgreSQL parser. The PostgreSQL License is BSD-style; vendoring is
  explicitly allowed and the attribution lives in the dependency
  directory.
- **MPL-2.0**: the Vault API client. File-level copyleft — if we
  *modify* a Vault API file we must release the modified file, but
  using the library as-is (which is the whole point) is unconditional.

There is **no** GPL, AGPL, or LGPL pull-in. The proxy can therefore be
shipped under Apache-2.0 to a customer with the usual permissive-policy
boilerplate.

## How to regenerate this report

```bash
cd <repo>
go install github.com/google/go-licenses@latest
go-licenses report ./cmd/proxy ./cmd/backfill ./cmd/capture-keycloak-sql \
  > /tmp/full-license-tree.csv
```

Diff the CSV against the previous run on every dependency bump. Treat a
new copyleft license (GPL/AGPL/LGPL) appearance as a blocker.

## Caveats

- This document covers source-level licensing. Cryptographic export
  controls (Wassenaar, US BIS, RF FSB) are a separate review the
  customer must do for their jurisdiction; the proxy's primitives are
  industry-standard AES, which is generally export-allowed but not
  globally.
- FIPS 140-3 validation is a separate question.
  `tink-go` is not currently a FIPS-validated build; a FIPS option is
  tracked but not yet shipped.
