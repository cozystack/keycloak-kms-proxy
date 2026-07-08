# Operator Guide — keycloak-kms-proxy

The deployment-shape document for an operator who is responsible for
running keycloak-kms-proxy in front of a real Keycloak installation.
Day-2 procedures live in [runbook.md](./runbook.md); the threat model
and compliance mapping live in [threat-model.md](./threat-model.md) and
[compliance.md](./compliance.md). This file is "what to build".

## Deployment shapes we support

### Single replica + static KMS (development / first-touch)

A single proxy pod in front of a CNPG cluster and Keycloak. The KEK is
a Kubernetes `Secret`, and the wrapped DEK set is a `Secret` minted once
by the operator. Good for proof of concept and the encryption-demo
walkthrough. **Not for production** because the KEK is reachable by
every operator with `kubectl get secret`.

```
Keycloak ── kkp-proxy ── CNPG
              │
              ├─ KKP_KEK from Secret kkp-proxy
              └─ KKP_DEKSET_FILE from Secret kkp-dekset
```

### HA pair + Vault Transit (production minimum)

The shape we recommend for any tenant carrying real PII. Two proxy
replicas behind a single Service; KEK lives in Vault Transit; the
wrapped DEK set still rides as a Kubernetes Secret (it is *meaningless*
without the KEK, so Secret-level RBAC is enough).

```
Keycloak ── kkp-proxy Service ──┬── replica 1 ──┐
                                └── replica 2 ──┼── CNPG (TLS)
                                                │
                          KKP_VAULT_ADDR ───────┴── Vault Transit (sealed)
```

Required for this shape:

- `replicas: 2` on the proxy Deployment.
- `KKP_VAULT_ADDR`, `KKP_VAULT_KEY_NAME`, `KKP_VAULT_MOUNT`, and exactly
  one Vault auth mode (`KKP_KEK` MUST be unset):
  - **Kubernetes** (`KKP_VAULT_KUBERNETES_ROLE`; mount via
    `KKP_VAULT_KUBERNETES_MOUNT`, default `kubernetes`; token via
    `KKP_VAULT_KUBERNETES_JWT_FILE`, default the in-pod path) —
    **recommended**. The proxy logs in with its projected ServiceAccount
    token, which the kubelet rotates, so no long-lived credential is
    stored. Bind the Vault role to the proxy's ServiceAccount + namespace.
  - **AppRole** (`KKP_VAULT_ROLE_ID` + `KKP_VAULT_SECRET_ID`, mount via
    `KKP_VAULT_APPROLE_MOUNT`, default `approle`). Provision a reusable
    `secret_id` (avoid `secret_id_num_uses=1`, keep `secret_id_ttl` no
    shorter than the token TTL) — the proxy reuses it for every on-demand
    re-login.
  - **Static token** (`KKP_VAULT_TOKEN`) — simplest, a long-lived token in
    a Secret.

  For the login methods point `KKP_VAULT_ADDR` at HTTPS (credentials
  travel on every login) and keep `token_ttl` above the proxy's 30s renew
  skew.
- `KKP_BACKEND_CA_FILE` + `KKP_BACKEND_SERVER_NAME` pointing at the
  CNPG `*-ca` Secret + the read-write Service DNS.
- `KKP_TLS_CERT_FILE`/`KKP_TLS_KEY_FILE` for the listener side
  (cert-manager `Issuer` recommended).
- `KKP_LENIENT=false` after the Liquibase bootstrap window
  (runbook §7).
- `KKP_HEALTH_ADDR=:8081` + `livenessProbe`/`readinessProbe`.
- `KKP_METRICS_ADDR=:9090` wired into the customer's Prometheus.

The two configuration blocks this shape adds on top of the development
shape are the Vault Transit wiring and the cert-manager TLS termination
plus hardening; the production manifests assemble them.

### HA + Vault + multi-replica Keycloak

The same proxy shape; Keycloak runs as a StatefulSet (its own
prerogative) and points at the proxy Service. Sticky-session is **not**
required at the proxy — each Keycloak connection is sticky to one proxy
replica for its lifetime, but new connections may land on either. The
DEK is shared via the Secret so both replicas decrypt the same on-disk
ciphertext.

## Required Secrets

| Secret | Provider | Purpose |
|---|---|---|
| `kkp-proxy` | operator | Holds `KKP_KEK` (static KMS, **dev only**) and `KKP_UPSTREAM_PASSWORD` (the SCRAM verifier credential the proxy presents to Keycloak) |
| `kkp-dekset` | operator (mint via `cmd/backfill generate-dekset`) | Holds the wrapped DEK set; the proxy reads it as `KKP_DEKSET_FILE` |
| `kc-db-ca` (CNPG-managed name varies) | CNPG operator | CA bundle for `KKP_BACKEND_CA_FILE` so the downstream TLS leg is verified |
| `kc-db-app` (CNPG default) | CNPG operator | `KKP_BACKEND_PASSWORD` (the credential the proxy uses to authenticate to CNPG) |
| `keycloak-creds` | operator | Keycloak's own admin password + `KC_DB_PASSWORD` (must match `KKP_UPSTREAM_PASSWORD` because the proxy verifies it on the upstream leg) |
| Vault auth | platform | Kubernetes auth bound to the proxy ServiceAccount (recommended — no stored credential), AppRole `role_id`/`secret_id` in a Secret, or a static Vault token (`KKP_VAULT_TOKEN`) |

## Required network policies

The proxy is the only pod that should be able to dial CNPG on 5432.
Keycloak should only be able to dial the proxy Service. Sketch:

```yaml
# Only the proxy reaches CNPG:5432
apiVersion: networking.k8s.io/v1
kind: NetworkPolicy
metadata:
  name: cnpg-only-proxy
spec:
  podSelector: {matchLabels: {cnpg.io/cluster: kc-db}}
  ingress:
    - from:
        - podSelector: {matchLabels: {app.kubernetes.io/name: keycloak-kms-proxy}}
      ports: [{port: 5432}]

# Only Keycloak reaches the proxy Service
apiVersion: networking.k8s.io/v1
kind: NetworkPolicy
metadata:
  name: proxy-only-keycloak
spec:
  podSelector: {matchLabels: {app.kubernetes.io/name: keycloak-kms-proxy}}
  ingress:
    - from:
        - podSelector: {matchLabels: {app.kubernetes.io/name: keycloak}}
      ports: [{port: 5432}]
```

The proxy also needs egress to Vault on its API port; metric and health
endpoints are scraped by the cluster's Prometheus / probe agent, so add
ingress for them as well.

## Required RBAC

The proxy itself needs **none** beyond mounting the secrets above. The
`backfill` and `capture-keycloak-sql` tools the operator runs out of
band need:

- `get` on the relevant CNPG / wrapped-DEK Secrets.
- `port-forward` for the demo capture procedure.

## Required external tooling

- `cert-manager` for the proxy's listener TLS (production manifests
  reference it; dev stand uses a `SelfSigned` Issuer).
- Vault server with a Transit mount (`vault secrets enable transit`)
  and a key named per `KKP_VAULT_KEY_NAME`.
- Prometheus scraping the proxy's `/metrics`.

## Configuration surface (`KKP_*` env)

The proxy reads its entire configuration from environment variables.
The list, with a brief intent for each:

| Variable | Purpose |
|---|---|
| `KKP_LISTEN_ADDR` | TCP listen address (e.g. `:5432`) |
| `KKP_BACKEND_ADDR` | CNPG read-write address (`kc-db-rw.<ns>.svc:5432`) |
| `KKP_UPSTREAM_USER` / `KKP_UPSTREAM_PASSWORD` | The SCRAM verifier the proxy presents to Keycloak |
| `KKP_BACKEND_USER` / `KKP_BACKEND_PASSWORD` | The SCRAM credential the proxy uses against CNPG |
| `KKP_FIELDS` | `""` (default set), `disabled`, `email-only`, `email-only-blind-index` |
| `KKP_LENIENT` | `true` for bootstrap; **must be `false` in production** |
| `KKP_KEK` | Static KMS — dev only |
| `KKP_DEKSET_FILE` | Path to the wrapped DEK set (required so DEK survives restarts) |
| `KKP_VAULT_ADDR` / `KKP_VAULT_KEY_NAME` / `KKP_VAULT_MOUNT` | Vault Transit KMS — production default |
| `KKP_VAULT_KUBERNETES_ROLE` / `KKP_VAULT_KUBERNETES_MOUNT` / `KKP_VAULT_KUBERNETES_JWT_FILE` | Vault Kubernetes auth (recommended) — login with the pod ServiceAccount token (mount default `kubernetes`) |
| `KKP_VAULT_ROLE_ID` / `KKP_VAULT_SECRET_ID` / `KKP_VAULT_APPROLE_MOUNT` | Vault AppRole auth — the proxy logs in and re-authenticates on demand (mount default `approle`) |
| `KKP_VAULT_TOKEN` | Static Vault token auth (exactly one auth mode) |
| `KKP_TLS_CERT_FILE` / `KKP_TLS_KEY_FILE` | Listener TLS termination |
| `KKP_BACKEND_CA_FILE` / `KKP_BACKEND_SERVER_NAME` | TLS re-origination to CNPG |
| `KKP_HEALTH_ADDR` | `/healthz` + `/readyz` endpoint (k8s probes) |
| `KKP_METRICS_ADDR` | Prometheus `/metrics` |
| `KKP_DEBUG_RELAY` | Verbose Parse + RowDescription tracing — production should leave it off |

## Wiring Keycloak

The two non-obvious bits:

```yaml
- name: KC_DB_URL_PROPERTIES
  # prepareThreshold=0: disable pgjdbc PS caching so every query re-Parses
  # through the proxy. tcpKeepAlive + socketTimeout help pgjdbc
  # detect connections closed by a proxy rollout.
  value: "?sslmode=verify-full&prepareThreshold=0&tcpKeepAlive=true&socketTimeout=30&sslrootcert=/etc/cnpg-ca/ca.crt"
- name: KC_DB_URL_HOST
  value: "kkp-proxy.<ns>.svc"
```

(For dev stands without listener TLS use `?sslmode=disable&prepareThreshold=0`.)

`KC_DB_USERNAME`/`KC_DB_PASSWORD` must match `KKP_UPSTREAM_USER`/
`KKP_UPSTREAM_PASSWORD` — that's the credential the proxy verifies.

## Verification gate after deployment

A green deployment is one where every line below succeeds:

1. `kubectl rollout status` on both deployments.
2. `curl /readyz` on the proxy returns 200.
3. `curl /metrics | grep kkp_decrypt_failures_total` returns 0.
4. Keycloak `LOGIN_ERROR` events are absent on a known-good test login.
5. A `SELECT email FROM user_entity LIMIT 1` against CNPG (psql in
   `kc-db-1`) returns `$KKP$…`, not plaintext.
6. The same row through the Keycloak admin REST returns plaintext.
7. `runtime SQL conformance` test on the customer's pinned Keycloak
   version was run and the diff against the previous version reviewed.

If any of those fails, **do not declare the deployment done** — follow
the runbook section that matches the symptom.

## Out of scope for the operator guide

- Building or hardening Keycloak itself (Keycloak's own ops guide).
- Building or hardening CNPG (CNPG's own ops guide).
- Building or hardening Vault (HashiCorp).
- The customer's identity-and-access-management policy (who can read the
  Vault unseal keys, who can run `pg_dump`, who can `kubectl exec`).
- DR drill schedules.

Those each pull a separate doc, owned by the team that operates the
named system.
