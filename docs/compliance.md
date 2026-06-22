# Compliance Mapping — keycloak-kms-proxy

Customer-facing artefact. Maps the proxy's
controls to the regulatory clauses customers most often sign to. The
mapping is **technical**: it says what the proxy demonstrably does today,
what the operator's deployment must do alongside it, and what is **not**
covered. Sign-off from the customer's security team is still required.

## Scope

What the proxy is, and is not, from a compliance standpoint:

- **Is:** a Postgres-wire transparent **column-encryption gateway** for
  Keycloak PII. Encrypts/decrypts designated columns on the fly using
  envelope encryption (DEK wrapped by a KEK in a KMS).
- **Is not:** a database, a key-management system, an identity broker, or
  an audit-log sink. It uses each of those (CNPG, Vault, Keycloak,
  Kubernetes audit log) but does not replace them.

## GDPR (Regulation (EU) 2016/679)

| Clause | Article | What the proxy does | Operator must also do |
|---|---|---|---|
| Pseudonymisation as a safeguard | Art. 4(5), Recital 28 | Replaces PII column values with marker-prefixed AEAD ciphertext keyed by a DEK that is not in the database | Manage KEK custody (Vault unseal) separately from DB backups |
| State of the art encryption | Art. 32(1)(a) | AES-SIV (deterministic, for searchable PII) + AES-GCM (non-deterministic) via `tink-go`; primitive choice documented in §6 of this file | Plan rotation cadence (Art. 32) — proxy supports KEK rotation without data re-encryption |
| Confidentiality / integrity | Art. 32(1)(b) | AEAD authenticates every ciphertext; tampered rows fail decrypt and are refused | TLS in transit (proxy↔Keycloak and proxy↔CNPG — both wired) |
| Ability to restore availability and access | Art. 32(1)(c) | DEK is rotation-safe; pg_dump through the proxy preserves the `$KKP$` envelope so a `pg_restore` via the same DEK round-trips | Document DR procedures (operator runbook §6) |
| Regular testing | Art. 32(1)(d) | Runtime SQL conformance test (CI), unit + integration tests, dev-stand walkthrough | Schedule periodic key-rotation and recovery drills |
| Breach notification | Art. 33 | Audit-line per decrypt op + KMS call (Prometheus + log); KEK access is loggable in Vault | Plug those signals into the customer's incident workflow |

Articles 33 & 34 (notification windows, communication to data subjects)
are operator responsibilities; the proxy supplies the technical signal
("decrypt failures spiked", "KEK access from unexpected client") but does
not perform the notification.

## 152-FZ "On Personal Data" (Russian Federation)

| Requirement | Article / protection level (UZ) | Proxy coverage | Operator must also do |
|---|---|---|---|
| Encryption of personal data | Art. 19; requirements for UZ-2 / UZ-3 (FSTEC Orders No. 21 / No. 17) | Columns holding personal data are stored encrypted at the record level (column-level), with the key kept outside the DBMS | The personal-data system class is determined by the operator; a cryptographic primitive (AES) for a level above UZ-3 must be certified by the FSB / FSTEC — the current build uses `tink-go`, which is not certified (see §6) |
| Logging of security events | Art. 19; clause 8.1 of FSTEC Order No. 17 | Prometheus counters for decrypt/encrypt/KMS-call/auth-failure plus a WARN on unrecognized PII queries | Feed these signals into the operator's SIEM |
| Protection of transmission channels | Art. 19; "Composition and content of organizational and technical measures" | TLS on both sides of the proxy (channel binding still open) | TLS certificates and their rotation — deployment level |
| Identification and authentication of subjects | Art. 19 | The proxy is a SCRAM endpoint on both legs; the Keycloak↔proxy and proxy↔CNPG identities are distinct | Password policy — Keycloak |
| Integrity of personal data | Art. 19 | AEAD authentication of every record | Backups — deployment level |
| Recovery | Art. 19 | `pg_dump`/`pg_restore` through the proxy with the same DEK | Operator's DR runbook |

Certification (FSB / FSTEC) is a separate process that the proxy, as a
piece of software, has yet to undergo (this is the same open item as FIPS
validation). The current answer is: "an industry-standard set of
primitives (`tink-go`) is used; a certified build is a separate goal."

## SOC 2-style control mapping

These map to the Trust Services Criteria most often invoked by customers
in due diligence:

| Criterion | Control supplied by the proxy | Evidence (where to look) |
|---|---|---|
| CC6.1 Logical access | SCRAM termination on both legs; downstream DB credential not shared with the application | `KKP_UPSTREAM_USER` ≠ `KKP_BACKEND_USER`; Vault Transit policy |
| CC6.6 Encryption | Column-level AEAD; KEK in Vault | `docs/threat-model.md`, this file, `kkp_decrypt_*` metrics |
| CC6.7 Transmission and disposal | TLS both legs; DEK rotation; KEK rotation | `KKP_TLS_CERT_FILE`, `KKP_BACKEND_CA_FILE`, runbook §2-3 |
| CC7.2 Monitoring and detection | Decrypt/encrypt/auth metrics + WARN on unrecognized PII SQL | Prometheus counters |
| CC7.4 Incident response | Runbook recovery sections; metrics-driven page triggers | `docs/runbook.md` |

## What the proxy does NOT claim

These are honest gaps for the customer review:

- **No formal certification today** (FIPS 140-3, Common Criteria, FSTEC) —
  the cryptographic library is industry-standard but not yet validated.
  This is an open item.
- **No tenant separation** at the key level today; one wrapped DEK set
  per deployment. Multi-tenant key segregation is an explicit follow-up
  before any multi-tenant install.
- **No automatic data-subject access / erasure tooling** beyond Keycloak
  itself. The proxy is column-encryption; "right to erasure" goes
  through Keycloak's user delete, which DELETE-s the encrypted row.
- **Audit log structure is metrics today**, not a structured per-event
  append-only log. A full per-event audit log on top of the metrics now
  in place is tracked as a follow-up item.

## Reviewer's checklist

Before signing off on this proxy for a regulated deployment, confirm:

- [ ] Vault Transit is the KMS in use (not the static-KEK Secret).
- [ ] `KKP_LENIENT=false` is in effect after Liquibase bootstrap
  (runbook §7).
- [ ] TLS terminates on both legs.
- [ ] Backups of the wrapped DEK set live in a different custody chain
  than the CNPG backups (threat model T6).
- [ ] Prometheus is scraping `kkp_*` and alerts are wired to the
  customer's incident workflow.
- [ ] Runtime SQL conformance tests are re-run on every Keycloak version
  bump and the corpus diff is reviewed (runbook §9).
- [ ] An owner is named for each KEK / unseal key custody role.
