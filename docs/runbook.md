# keycloak-kms-proxy — Operator Runbook

This is the day-2 operations companion. It is the page an
on-call operator should reach when something is misbehaving on a running
stand. Each section ends with **verification steps** so you can confirm the
fix landed; the steps are copy-pasteable kubectl/curl one-liners.

The instructions below assume:

```bash
NS=keycloak-kms-proxy-demo                  # your stand's namespace
KUBECONFIG=…/clusters/<env>/kubeconfig
```

The runbook covers operational tasks that came out of building the proxy
and verifying it on a test cluster. It is **not** a replacement for incident
post-mortems — those live separately.

## 1. Rollout the proxy (and Keycloak with it)

The proxy holds per-connection state, and prepared-statement plans live
for the lifetime of a Hibernate connection. A proxy rollout invalidates
them, so a Keycloak rollout has to follow.

```bash
kubectl -n $NS rollout restart deploy/kkp-proxy
kubectl -n $NS rollout status deploy/kkp-proxy --timeout=2m
kubectl -n $NS rollout restart deploy/keycloak    # mandatory
kubectl -n $NS rollout status deploy/keycloak --timeout=3m
```

Verification:

```bash
# Health endpoints serve 200:
kubectl -n $NS port-forward deploy/kkp-proxy 18081:8081 >/dev/null &
curl -sS http://localhost:18081/healthz   # → ok
curl -sS http://localhost:18081/readyz    # → ok
```

If you skip the Keycloak restart, expect
`kkp: datarow … — NO read plan built — passthrough` in the proxy log and
ciphertext leaking to clients on the affected connections.

## 2. KEK rotation (Vault Transit) — no data re-encryption needed

The wrapped DEK carries a `vault:vN:` tag so Vault Transit
can still decrypt older wraps after a rotation.

```bash
vault write -f transit/keys/kkp/rotate
# That's it — the running proxy keeps working.
# To bring the stored wrapped DEK up to the latest KEK version:
vault write transit/rewrap/kkp ciphertext=vault:v1:…
```

Verification (live): create a user, log in, then rotate, then log in again
— both succeed.

## 3. DEK rotation (re-encrypting column values)

Marker-driven. High-level shape — the
tooling exists today as `cmd/backfill encrypt-rows`:

1. `cmd/backfill generate-dekset … -out new-dekset.json` — mints a new
   wrapped DEK set under the **same** KEK so the proxy can both decrypt
   the old marker version and write the new one.
2. Mount `new-dekset.json` into the proxy (Secret rotation) and rollout.
3. Run `cmd/backfill encrypt-rows` against the live DB with both DEK sets;
   it walks rows that still carry the old marker version and rewrites
   them.
4. After every PII column shows the new marker version, retire the old
   DEK from the set.

## 4. Recovery from out-of-band SQL changes

If anyone runs ad-hoc SQL on the PII tables bypassing the proxy
(`kubectl exec kc-db-1 -- psql` is the obvious one), expect
**`WHERE email = '…'` not to match** because the WHERE clause is comparing
plaintext to ciphertext. Symptom: `user_not_found` in
Keycloak `LOGIN_ERROR` events even though `SELECT id FROM user_entity` via
psql shows the row.

Recovery path used in dev:

```bash
# 1. Stop guessing what's in the DB. Wipe Keycloak's cache so it
#    re-reads through the proxy:
kubectl -n $NS exec deploy/keycloak -- /opt/keycloak/bin/kcadm.sh \
  config credentials --server http://localhost:8080 --realm master \
  --user admin --password "$ADMIN_PW"
kubectl -n $NS exec deploy/keycloak -- /opt/keycloak/bin/kcadm.sh \
  create realms/master/clear-user-cache

# 2. If a credential row is partially encrypted (some columns plaintext,
#    some encrypted), delete the row via the admin REST API — the
#    proxy understands DELETE and won't corrupt anything new:
kubectl -n $NS port-forward svc/keycloak 28080:8080 >/dev/null &
curl -s -X DELETE -H "Authorization: Bearer $TOK" \
  "http://localhost:28080/admin/realms/master/users/$STALE_ID"

# 3. If the cluster is truly wedged, the cheapest path is to recreate the
#    namespace. Re-apply your proxy Deployment/Service/Secret manifests
#    (or re-deploy the Cozystack keycloak package) reusing the SAME KEK +
#    wrapped DEK set, so encrypted backup data still decrypts:
kubectl delete ns $NS
# apply your proxy Deployment/Service/Secret manifests here
```

## 5. Recovery: proxy down

The Service IP routes to the running replicas via the regular Service
selector. With more than one replica, a single pod
crash is a non-event for Keycloak — it reopens its pgjdbc connection to a
healthy replica.

If *all* replicas are down:

```bash
kubectl -n $NS get pods -l app.kubernetes.io/name=keycloak-kms-proxy
kubectl -n $NS logs -l app.kubernetes.io/name=keycloak-kms-proxy --tail=200
# A common cause is CrashLoopBackOff because the DEK set Secret is gone
# or the KMS is unreachable.
```

Keycloak will surface this to end users as "internal error" on login,
not silently as plaintext.

## 6. KEK / wrapped DEK disaster recovery

The wrapped DEK set is **meaningless without the KEK**; the KEK is
**meaningless without Vault unseal keys** (or, for the static KMS, the
Kubernetes Secret). Losing both = the encrypted PII is gone, by design
(see the threat model). Therefore:

1. Back up the wrapped DEK set Secret. It is `kkp-dekset` in the same
   namespace as the proxy. The contents are useless without the KEK, so
   the backup can sit in the regular cluster-backup pipeline.
2. Back up the Vault unseal keys via the customer's secret-custody
   process — **never** the same one that backs up the database.
3. Document who holds custody of (1) and (2); split if the threat model
   requires it.

## 7. KKP_LENIENT flip after Liquibase bootstrap

The shipped template sets `KKP_LENIENT=true`
because the Keycloak Liquibase migration
`jpa-changelog-8.0.0.xml::8.0.0-updating-credential-data` writes
`CREDENTIAL.{SECRET_DATA,CREDENTIAL_DATA}` as `CONCAT` literals — not
bound parameters — and the strict planner refuses to silently re-write
literals. Once Keycloak is up:

```bash
kubectl -n $NS set env deploy/kkp-proxy KKP_LENIENT=false
kubectl -n $NS rollout restart deploy/kkp-proxy
kubectl -n $NS rollout restart deploy/keycloak
```

Verification (production must run strict): the proxy log must not contain
`prepare …: rewrite: PII value is not a bound parameter` after bootstrap.

## 8. Verifying that PII is actually encrypted

Three independent checks should all agree:

```bash
# A. Raw row in CNPG — must start with $KKP$
kubectl -n $NS exec kc-db-1 -c postgres -- psql -U postgres -d keycloak -c \
  "SELECT substr(email, 1, 30), substr(secret_data, 1, 30) \
   FROM user_entity LEFT JOIN credential ON user_entity.id = credential.user_id \
   WHERE email IS NOT NULL LIMIT 3"

# B. Login flow ends with a JWT whose claims are plaintext
TOK=$(curl -s … /token | jq -r .access_token)
echo "$TOK" | cut -d. -f2 | base64 -d | jq '{preferred_username, email}'

# C. Prometheus counters show non-zero traffic
kubectl -n $NS port-forward deploy/kkp-proxy 19090:9090 >/dev/null &
curl -sS http://localhost:19090/metrics | grep '^kkp_decrypt_total'
```

If (A) ever shows plaintext where it should be ciphertext, **stop and
investigate** — that's either `KKP_FIELDS=disabled` left on by mistake or
out-of-band writes (see §4).

## 9. Upgrading Keycloak version

The runtime SQL conformance corpus (checked by a CI diff gate) is
pinned to a Keycloak release. The procedure:

```bash
# 1. capture a fresh corpus from the new Keycloak running through the
#    proxy (KKP_DEBUG_RELAY=true must be on for capture):
kubectl -n $NS logs deploy/kkp-proxy --since=2m > /tmp/proxy.log
make capture-runtime-sql LOG=/tmp/proxy.log KC_VERSION=<new>

# 2. diff vs the pinned version to see what new SQL shapes Hibernate
#    emits:
git diff testdata/keycloak/<old>/runtime-sql.txt \
         testdata/keycloak/<new>/runtime-sql.txt

# 3. run the conformance tests against the new corpus:
go test ./internal/rewrite/... -run RuntimeCorpus
```

If the diff contains a PII-touching SQL shape that the analyser doesn't
extract a table from, the conformance test fails — that's the gate.
Patch `internal/rewrite/analyze.go` (and add a unit test) before merging
the corpus bump.

## 10. Channel-binding decision (open)

The proxy terminates SCRAM on both legs, so it
*can* support `SCRAM-SHA-256-PLUS` with channel binding; what's missing
is wiring the listener's TLS cert hash (`tls-server-end-point`) into the
SCRAM server, and the CNPG cert hash into the SCRAM client. This is
tracked as an open item — the SCRAM code already accepts a `cbind`
argument; the extraction wiring is the open piece.
