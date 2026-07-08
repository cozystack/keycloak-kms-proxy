# keycloak-kms-proxy

[![ci](https://github.com/cozystack/keycloak-kms-proxy/actions/workflows/ci.yml/badge.svg)](https://github.com/cozystack/keycloak-kms-proxy/actions/workflows/ci.yml)
[![license](https://img.shields.io/badge/license-Apache--2.0-blue.svg)](./LICENSE)

A transparent PostgreSQL wire-protocol proxy that sits between Keycloak and its CloudNativePG (CNPG) database and encrypts/decrypts PII columns on the fly. Keycloak talks to the proxy exactly as it would to PostgreSQL; the proxy forwards traffic to the real CNPG cluster, encrypting designated column values on writes and decrypting them on reads. The data encryption key is wrapped by a KMS (HashiCorp Vault Transit or a static fake), so it never lives inside the database.

## Threat model

The point of a wire-protocol proxy (rather than storage encryption or in-DB triggers) is **where the key lives**: in the proxy process and the KMS, *outside* PostgreSQL. That defends against a DB administrator with a live-DB shell or a SQL dump on a running database, and against a Keycloak pod that bypasses the application and reads the DB directly. It does not protect against an attacker who has compromised the proxy process itself, or Keycloak itself (Keycloak legitimately sees plaintext). The structured analysis is in [docs/threat-model.md](./docs/threat-model.md).

## How it works

The proxy terminates SCRAM on both legs — it is a SCRAM server to Keycloak and a SCRAM client to CNPG — and re-originates TLS. The data path is stateful per connection: it tracks `Parse → Bind → Execute` so it knows which bound parameters carry PII values and which `DataRow` fields are encrypted on the way back. Writes encrypt at `Bind`; reads decrypt at `DataRow`. Anything the proxy does not recognise (DDL, Liquibase migrations, `COPY`, ...) is byte passthrough.

Every encrypted value carries a self-describing `$KKP$<fmt>.<scheme>.<keyver>.<base64url-ciphertext>` marker. A markerless value is treated as plaintext that has not been migrated yet, so the proxy can run against a partially-encrypted database while [backfill](#backfill) catches up.

## Default field set

| Column | Scheme | Notes |
|---|---|---|
| `USER_ENTITY.USERNAME` / `USER_ENTITY.EMAIL` | deterministic (AES-SIV) + lower-case | login by username/email keeps working |
| `USER_ENTITY.FIRST_NAME` / `USER_ENTITY.LAST_NAME` | non-deterministic (AES-GCM) | not searched |
| `USER_ATTRIBUTE.VALUE` / `USER_ATTRIBUTE.LONG_VALUE` (when `NAME LIKE 'pii-%'`) | non-deterministic | `LONG_VALUE_HASH` is left untouched so Keycloak's blind-index search keeps working |
| `CREDENTIAL.SECRET_DATA` / `CREDENTIAL.CREDENTIAL_DATA` | non-deterministic | defence-in-depth on top of password hashing |

Set `KKP_FIELDS=disabled` for pure passthrough or `KKP_FIELDS=email-only` for just `USER_ENTITY.EMAIL`. Unknown values are rejected.

## Build and run

The proxy binary lives in [`cmd/proxy`](./cmd/proxy); `pg_query_go` links against the embedded PostgreSQL parser via cgo, so the multi-stage [`Dockerfile`](./Dockerfile) builds with `CGO_ENABLED=1` on `golang:1.26.2-bookworm` and ships on `gcr.io/distroless/base-debian12:nonroot`. `make image` builds the container image; `make build`, `make test`, and `make lint` cover the Go toolchain.

Tagged releases publish a container image to `ghcr.io/cozystack/keycloak-kms-proxy` (e.g. `:v0.1.0`, `:latest`).

### Environment

| Variable | Purpose |
|---|---|
| `KKP_LISTEN_ADDR` | listen address (e.g. `:5432`) |
| `KKP_BACKEND_ADDR` | CNPG read-write address |
| `KKP_UPSTREAM_USER` / `KKP_UPSTREAM_PASSWORD` | credential the proxy verifies on the upstream (Keycloak) SCRAM leg |
| `KKP_BACKEND_USER` / `KKP_BACKEND_PASSWORD` | credential the proxy uses on the downstream (CNPG) SCRAM leg |
| `KKP_KEK` | base64 32-byte KEK for the static KMS (mutually exclusive with the Vault settings below) |
| `KKP_VAULT_ADDR` / `KKP_VAULT_KEY_NAME` / `KKP_VAULT_MOUNT` | Vault Transit KMS settings |
| `KKP_VAULT_TOKEN` | static Vault token auth (mutually exclusive with AppRole below) |
| `KKP_VAULT_ROLE_ID` / `KKP_VAULT_SECRET_ID` / `KKP_VAULT_APPROLE_MOUNT` | Vault AppRole auth: the proxy logs in and re-authenticates on demand (mount defaults to `approle`) |
| `KKP_DEKSET_FILE` | path to a JSON-encoded wrapped DEK set (lets the proxy and the backfill tool share a key) |
| `KKP_FIELDS` | `disabled`, `email-only`, or empty for the full default set |
| `KKP_LENIENT` | `true` downgrades fail-loud rules to passthrough — required for the Keycloak Liquibase bootstrap window only, must be off in steady state |
| `KKP_TLS_CERT_FILE` / `KKP_TLS_KEY_FILE` | PEM cert + key for TLS termination on the listener |
| `KKP_METRICS_ADDR` | optional Prometheus `/metrics` address (e.g. `:9090`) |

## Deployment

The proxy is a standard `Deployment` + `Service`. It is wired into the data path by pointing Keycloak's `KC_DB_URL_HOST`/`KC_DB_URL_PORT` at the proxy `Service`; the proxy in turn dials the real CNPG read-write `Service`. A `Secret` carries the SCRAM credentials and the KEK (static KMS) or the Vault token (Vault Transit). The pod runs unprivileged (`runAsNonRoot`, `readOnlyRootFilesystem`, dropped capabilities, `seccompProfile: RuntimeDefault`) and is PodSecurity-restricted compliant.

On [Cozystack](https://cozystack.io) the proxy is integrated into the `keycloak` system package as an optional, flag-gated feature — enabling encryption in the Keycloak chart deploys the proxy and repoints Keycloak at it automatically. See the Cozystack `keycloak` package for the values flag.

The operator-facing guides live under [`docs/`](./docs): [operator-guide](./docs/operator-guide.md), [runbook](./docs/runbook.md), [migration of an existing Keycloak](./docs/migration-existing-keycloak.md), and [compliance mapping](./docs/compliance.md).

## Backfill

`cmd/backfill` ([generate-dekset](./cmd/backfill/generate.go), [encrypt-rows](./cmd/backfill/encrypt.go)) is the offline-migration tool for an existing Keycloak. With Keycloak stopped it (a) mints a wrapped DEK set, and (b) walks every configured PII column and converts plaintext rows to ciphertext idempotently — the `$KKP$` marker means a re-run is a no-op on already-encrypted rows. Mount the resulting `dekset.json` into the proxy as a `Secret` (`KKP_DEKSET_FILE`) and switch `KKP_FIELDS` to encrypt; Keycloak comes back online with the same data. The end-to-end procedure is in [docs/migration-existing-keycloak.md](./docs/migration-existing-keycloak.md).

## KMS options

- **Static KMS** (`KKP_KEK`): a 32-byte AES-256 KEK provided in-cluster as a `Secret`. Suitable for tests and bootstrap.
- **Vault Transit** (`KKP_VAULT_*`): the KEK lives in Vault. KEK rotation (`vault write -f transit/keys/<key>/rotate`) is transparent to the proxy — the `vault:vN:` version tag on each wrapped DEK lets Vault decrypt across rotations without re-encrypting any column data. Optionally run `vault write transit/rewrap/<key> ciphertext=…` later to bring the stored wrap up to the latest KEK version.
- **Vault auth**: either a static token (`KKP_VAULT_TOKEN`) or **AppRole** (`KKP_VAULT_ROLE_ID` + `KKP_VAULT_SECRET_ID`, mount via `KKP_VAULT_APPROLE_MOUNT`). With AppRole the proxy performs the login itself and transparently re-authenticates when the issued token expires, so no long-lived token has to sit in a Secret. The proxy touches Vault only at startup and on DEK rotation, so a short-lived AppRole token is sufficient. The `secret_id` must stay reusable, though — provision the role without `secret_id_num_uses=1` and with a `secret_id_ttl` no shorter than the token TTL, otherwise the on-demand re-login will fail once the secret id is consumed or expires. Give the role a `token_ttl` comfortably above the 30s renew skew, and point `KKP_VAULT_ADDR` at an HTTPS endpoint — the `secret_id` is sent on every re-login.

## Search support

Login by username/email goes through equality (`getRealmUserByEmail` / `getRealmUserByUsername`) on the deterministic columns — the proxy encrypts the bound parameter and matches the stored ciphertext, including a case-insensitive match because both sides are lower-cased before encryption.

Keycloak's admin REST search typically wraps the user input as `LIKE '%term%'`. The proxy detects `LIKE`/`ILIKE` filters (including `LOWER(col) LIKE :p`) on deterministic PII columns and, when the bound value carries no `%` or `_`, encrypts it at `Bind` so the equality matches stored ciphertext. Patterns that do carry wildcards are forwarded unchanged — they would not match on encrypted columns. Broader pattern matching needs a blind-index shadow column.

## Generating the conformance corpus on Keycloak upgrade

[`cmd/gen-keycloak-tests`](./cmd/gen-keycloak-tests) parses a pinned Keycloak `model/jpa` source tree and emits a deterministic golden corpus (`testdata/keycloak/<version>/corpus.json`) describing entities, columns and `@NamedQuery` declarations. [`internal/keycloakmodel`](./internal/keycloakmodel) cross-checks the hand-derived `Keycloak260()` model against that corpus, so schema/query drift on a Keycloak upgrade surfaces as a reviewable diff *before* the upgrade lands in the cluster:

```sh
git clone --depth 1 --branch <new-tag> https://github.com/keycloak/keycloak /tmp/keycloak-<new>
make gen-keycloak-tests SRC=/tmp/keycloak-<new>
go test ./internal/keycloakmodel/...
```

## Repository layout

```
cmd/
  proxy/                 proxy server binary
  backfill/              plaintext → ciphertext migration tool + DEK set generator
  gen-keycloak-tests/    Keycloak sources → golden conformance corpus
  capture-keycloak-sql/  proxy log → runtime SQL conformance golden
internal/
  wire/                  PG wire state machine (pgproto3); SCRAM both legs; TLS in-band negotiation; encrypt-on-Bind / decrypt-on-DataRow pump
  rewrite/               SQL parse (pg_query_go); WHERE-clause column/param extraction; encrypt-on-Bind plan with fail-loud
  crypto/                envelope marker; AES-SIV / AES-GCM primitives; Cipher facade; DEK (de)serialization
  kms/                   KMS interface; static + Vault Transit; DEK envelope; KEK rotation
  config/                proxy config + environment loading; encrypted-field set + defaults
  keycloakmodel/         pinned Keycloak schema/queries model + corpus loader
  observe/               Prometheus metrics
docs/                    operator guide, runbook, threat model, compliance, migration
testdata/keycloak/26.0.0/corpus.json
```

## License

[Apache License 2.0](./LICENSE).
