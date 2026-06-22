# Migrating an Existing Keycloak Behind keycloak-kms-proxy

The runbook for turning on column-level PII
encryption in a Keycloak installation that already has live users and
credentials. The proxy supports this by design (via its ciphertext
marker), but the steps below must be followed
**in order**; out-of-order operations leave the database in a state
where some rows decrypt and others do not.

## What we're doing

1. Mint a wrapped DEK set under the customer's KMS.
2. Stand up the proxy in front of the existing CNPG cluster **but
   leave Keycloak pointing at CNPG directly** so nothing is encrypted
   yet.
3. Stop Keycloak (planned maintenance window).
4. Run `cmd/backfill encrypt-rows` against the *real* CNPG cluster
   (the proxy is **not** in this path — backfill talks to CNPG
   directly with the DEK). Plaintext rows become `$KKP$…`; rows
   already encrypted (marker present) are skipped.
5. Repoint Keycloak's JDBC URL at the proxy Service.
6. Start Keycloak. Login flows decrypt-on-read through the proxy
   transparently; new writes go through the proxy with encryption
   enabled.

There is also an "online" variant where Keycloak stays up; that
requires a marker-aware coexistence pass (the proxy already supports
this by passing markerless rows through). It is tracked as a
follow-up; for the first migration prefer the
offline window below.

## Prerequisites

- Vault Transit (or static KMS in a Secret for a single-customer dev
  install) provisioned with the KEK that will own this proxy.
- A maintenance window long enough to encrypt the existing `user_entity`,
  `user_attribute`, and `credential` rows. On a 50k-user realm,
  backfill takes minutes; on a 5M-user realm budget the slowest of
  table scan + per-row encrypt + write, plus a safety margin for the
  customer's slow disk.
- A current **encrypted** backup of CNPG, in case rollback is needed.
  Backfill is idempotent, but a snapshot before the run is cheap
  insurance.

## Step 1 — Mint the wrapped DEK set

```bash
KEK_B64=$(vault read -field=ciphertext transit/keys/kkp/export …)
# Or: KEK_B64=$(openssl rand -base64 32 | tr -d '\n')   # static KMS only.
go run ./cmd/backfill generate-dekset \
   -kek "$KEK_B64" \
   -out dekset.json
```

The output `dekset.json` is what the proxy will mount as
`KKP_DEKSET_FILE`. Treat it like a secret (it is encrypted DEK material,
not the KEK, but it is the bridge — if you lose this file *and* the KEK
gets rotated without a backup of the new wrap, the older `$KKP$…` rows
become unreadable). Store it as a Kubernetes Secret in the proxy
namespace.

## Step 2 — Stand up the proxy

Deploy the proxy at this stage but **do not switch Keycloak yet**.
This validates:

- The proxy reaches CNPG (TLS handshake succeeds — log line `backend
  TLS enabled`).
- The proxy authenticates to CNPG (SCRAM client succeeds — no log
  errors).
- `/readyz` returns 200.
- Vault is reachable (`kkp_kms_calls_total` increments on the first
  request after warmup).

If any of those fail, fix before continuing.

## Step 3 — Maintenance window: stop Keycloak

```bash
kubectl -n $NS scale deploy/keycloak --replicas=0
```

Wait for the pods to drain. From this point forward every connection
to CNPG should be either (a) the operator's `psql` for sanity checks,
or (b) the backfill process.

## Step 4 — Backfill

Backfill connects to CNPG **directly** and rewrites plaintext PII
columns to ciphertext. It does **not** go through the proxy because the
proxy expects already-encrypted on-disk markers and would refuse some
writes; the tool owns its own DEK so it can write the same envelope
the proxy will later read.

```bash
DSN="postgres://keycloak:$KC_DB_PW@kc-db-rw.<ns>.svc:5432/keycloak?sslmode=verify-full"
go run ./cmd/backfill encrypt-rows \
  -dsn "$DSN" \
  -kek "$KEK_B64" \
  -dekset dekset.json \
  -fields default      # or 'email-only' for a staged rollout
```

The tool is idempotent — running it twice on a row that already has
the marker is a no-op. On a partial failure (network blip, OOM), just
re-run.

Sanity check after backfill:

```bash
kubectl -n $NS exec kc-db-1 -c postgres -- psql -U postgres -d keycloak -At -c \
  "SELECT COUNT(*) FILTER (WHERE email LIKE '\$KKP\$%')
        , COUNT(*) FILTER (WHERE email IS NOT NULL AND email NOT LIKE '\$KKP\$%')
   FROM user_entity"
```

You want column 1 > 0 and column 2 = 0 (no leftover plaintext email).

## Step 5 — Repoint Keycloak

```yaml
- name: KC_DB_URL_HOST
  value: "kkp-proxy.<ns>.svc"
- name: KC_DB_URL_PROPERTIES
  # prepareThreshold=0 closes the rollout-vs-PS-cache hazard.
  # sslmode=verify-full + sslrootcert path use the CNPG CA mount.
  value: "?sslmode=verify-full&prepareThreshold=0&tcpKeepAlive=true&socketTimeout=30&sslrootcert=/etc/cnpg-ca/ca.crt"
```

Apply, then start Keycloak:

```bash
kubectl -n $NS scale deploy/keycloak --replicas=<previous>
kubectl -n $NS rollout status deploy/keycloak --timeout=5m
```

## Step 6 — Verify

Run the post-deploy verification gate from
[operator-guide.md](./operator-guide.md#verification-gate-after-deployment):

1. `/readyz` on the proxy → 200.
2. `kkp_decrypt_failures_total` → 0 after several logins.
3. A known-good user logs in and the JWT carries plaintext claims.
4. Raw CNPG row for that user shows `$KKP$…` in PII columns.
5. Re-run backfill — it should report "0 rows to encrypt" (idempotency).

## If something is wrong: rollback

You have two layers of safety:

1. **The encrypted backup taken before backfill.** If backfill
   corrupted the data (extremely unlikely — `cmd/backfill` is
   tested), restore the backup, then debug.
2. **The proxy off-path.** If reads through the proxy fail
   (`kkp_decrypt_failures_total` > 0 on real traffic), you can
   *temporarily* repoint Keycloak back at CNPG. Encrypted rows will
   appear as `$KKP$…` strings in usernames/emails/etc., which breaks
   user-facing flows. Use this only if the alternative is downtime; the
   real fix is to identify which DEK was used to write the rows.

## Once it's stable

Once the migrated tenant has been running cleanly for a week or two,
turn `KKP_LENIENT=false` (runbook §7) and confirm the proxy log carries
no `prepare …: rewrite: PII value is not a bound parameter` lines.
After that, the migration is "done" and the deployment matches the
production shape described in `operator-guide.md`.
