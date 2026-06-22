# Threat Model — keycloak-kms-proxy

This document is the structured STRIDE-style security review. It's the
artefact we hand to a security reviewer or customer security team. Update
on every architecture change.

## Scope and trust boundaries

- **In scope:** the proxy process, its KMS dependency, the database it
  writes to, the network leg between Keycloak and the database. We talk
  about a single deployment (proxy + CNPG cluster) inside a Kubernetes
  cluster; multi-tenant key isolation is a follow-up.
- **Out of scope:** Keycloak's own auth flows (token issuance,
  session security, brute-force protection) — those are Keycloak's
  responsibility. The proxy intentionally does **not** see plaintext
  passwords for credentials it stores; it sees BCrypt hashes from
  Keycloak.

Trust boundaries:

```
┌───────────────────────────────────────────────────────────┐
│                       Operator (root)                     │
│       can read every Secret, exec into every pod          │
└───────────────────────────────────────────────────────────┘
                ▲                            ▲
                │                            │
┌───────────────┴────────┐       ┌───────────┴────────────┐
│   Keycloak (Quarkus)   │       │   Proxy process(es)    │  ← trust boundary 1:
│   sees plaintext PII   │ wire  │   holds plaintext +    │   inside this box
│                        │◀─────▶│   the active DEK in    │   PII is in the clear
└────────────────────────┘ +TLS  │   memory               │
        ▲                        └───────────┬────────────┘
        │ HTTPS                              │
        │ admin REST / OIDC                  │ TLS + SCRAM
        │                                    ▼
┌───────┴────────┐                ┌──────────────────────┐
│  end clients   │                │   CNPG / Postgres    │  ← trust boundary 2:
└────────────────┘                │   sees only          │   inside this box
                                  │   ciphertext         │   PII is encrypted
                                  └──────────┬───────────┘
                                             │
                                       Vault Transit
                                       (KEK, wraps DEK)
                                  ← trust boundary 3:
                                  inside Vault the KEK is
                                  in a sealed core
```

## What the proxy protects against (and confidence)

| # | Threat | Vector | Mitigated by | Confidence |
|---|---|---|---|---|
| T1 | DB-admin reads PII | `psql` into CNPG primary | Column-level encryption; PII columns hold `$KKP$…` ciphertext; key lives in proxy + KMS | High |
| T2 | SQL-dump of live DB carries PII | `pg_dump` against CNPG directly | Same as T1; verified — pg_dump output is ciphertext | High |
| T3 | Compromised Keycloak pod queries DB directly | Pod escape → connects to CNPG | Same as T1 + downstream SCRAM credential lives in proxy Secret, not in Keycloak | Medium (Keycloak itself sees plaintext, so a Keycloak-pod compromise reveals the user it's currently serving anyway) |
| T4 | Snapshot of CNPG PV exfiltrated | Volume snapshot to elsewhere | Same as T1 + LUKS at storage layer (deployment concern, not the proxy's) | High |
| T5 | KEK leaks from `kkp-proxy` Secret | RBAC misconfig, kubectl get | The static-KMS path is for tests; production uses Vault Transit | Medium — depends on deployment shape; static KMS is documented as test-only |
| T6 | Compromised CI/build pipeline pushes malicious proxy image | Supply chain | Image build is reproducible (`make image`) and the SHA shows up in the `image:` line; deployment is observable. **Not addressed in code** — covered by the platform's sign+verify policy. | Low — out of the proxy's hands |
| T7 | Equality leakage on deterministic columns (`username`, `email`) | Frequency analysis on stored ciphertext | Columns are unique by definition; equality leakage = "two rows share a value" is the same information you get from `... WHERE … IS NOT NULL` on a unique column | Accepted residual |
| T8 | Padding-oracle / chosen-ciphertext attack on AEAD | Crafted ciphertext via the proxy | AEAD primitives (`tink-go`) authenticate every cipher block; a tampered ciphertext fails decrypt and the proxy refuses the row | High |

## What the proxy explicitly does NOT protect

These are accepted residuals; the customer security team must sign off:

- **Compromised proxy process** — the proxy holds plaintext, the active
  DEK, the DB credentials/verifier. Memory dumps or in-process attackers
  win.
- **Compromised Keycloak runtime** — Keycloak legitimately decrypts every
  PII it serves; a Keycloak code-execution flaw exposes whatever Keycloak
  itself loads.
- **TOCTOU between Keycloak and the proxy** — the auth flow trusts
  Keycloak's BCrypt verdict; if Keycloak says "credentials match", the
  proxy returns plaintext claims.
- **Side channels** (timing, cache, power) on AEAD operations — not
  hardened.
- **Cryptanalytic break** of AES-SIV or AES-GCM. Out of scope.

## STRIDE classification of the proxy's own surfaces

| Surface | S | T | R | I | D | E |
|---|---|---|---|---|---|---|
| Upstream listener (Keycloak → proxy) | SCRAM verifier on every connection (channel binding pending) | TLS to listener prevents wire-level tampering | n/a | TLS prevents wiretap | Per-replica connection cap (open) | proxy never invokes anything as the calling identity |
| Downstream dial (proxy → CNPG) | SCRAM client + TLS to CNPG with CA validation | Same | n/a | TLS protects the wire | If CNPG hangs the proxy waits up to `socketTimeout` (configured in Keycloak's pgjdbc URL today) | Proxy authenticates as its own backend user; no impersonation |
| KMS calls (Vault / static) | Vault token in pod env or projected SA; static KMS reads from Secret | TLS to Vault (Vault's responsibility) | KMS calls counted by metric (`kkp_kms_calls_total`) | Vault audit log captures unwraps | KMS quota limits (capacity planning) | Vault Transit policy scoped to the configured key only |
| Health endpoints `/healthz`, `/readyz` | None (intentionally on a separate port) | n/a | n/a | No PII leakage from the endpoint | Cheap TCP probe to backend, no expensive work | n/a |
| Metrics endpoint `/metrics` | None (intentionally on a separate port; same deploy shape as kube-prometheus) | n/a | Counter values are non-PII (table+column labels are low-cardinality) | Labels do not carry user data | Histogram cardinality bounded by the field set | n/a |
| Admin REST is **not** a proxy surface | The proxy has no admin API by design | — | — | — | — | — |

## Failure modes that operators must alert on

These are exposed as Prometheus counters:

- `kkp_decrypt_failures_total` > 0 — DEK divergence (rolled DEK that
  doesn't match column markers) or data corruption. Page-worthy.
- `kkp_unrecognized_pii_sql_total` rate > 0 — a new SQL shape sneaked
  past the analyser; until the conformance corpus is regenerated, that
  query is passthrough → ciphertext to the client. Page-worthy.
- `kkp_kms_calls_total{outcome="error"}` rate > 0 — Vault Transit
  unreachable / quota exhausted; logins start failing.
- `kkp_upstream_auth_failures_total` rate > steady baseline — credential
  rotation issue or brute-force; correlate with Keycloak's own auth
  events.

## What changes when the deployment shape changes

- Single-tenant per cluster (today): one KEK, one wrapped DEK set.
- Multi-tenant per cluster (future): one DEK set **per tenant**, derived
  from a per-tenant KEK. Currently *not* implemented; explicit follow-up
  before any multi-tenant install.
- Read replica behind the proxy: a CNPG read replica must be reached via
  the proxy too — bypassing the proxy on the read path means clients see
  ciphertext.

## Review history

- **2026-06-02** — initial draft. Reviewed against the integration-test
  walkthrough, with the proxy verified end to end on a test cluster.

When this list grows, every entry must link to either a PR that closed an
item, or an incident post-mortem that opened one.
