# Production-oriented Cloudflare architecture

ControlForge 0.3 adds a deployable SOC control plane while preserving the Python
detector and endpoint-assurance package. The edge service lives under `cloud/` and
targets the stable TypeScript Workers runtime. Python Workers were not selected for
the control plane because that runtime is currently beta.

```text
endpoint collector / signed integrations
        | TLS + timestamp + nonce + HMAC
        v
Cloudflare Worker ingestion boundary
        | validate, tenant-scope, deduplicate
        +----------------------+
        v                      v
       D1                 Cloudflare Queue ----> dead-letter queue
                                  |
                                  v
                    deterministic rule and correlation engine
                                  |
                                  v
                     alerts + cases + append-only audit
                         |                    |
                         v                    v
             optional model triage    response proposals
                                             |
                                 two-person approval for active actions
                                             |
                                             v
                                  signed endpoint action polling
```

## Security boundaries

- Collector credentials are generated server-side and returned once. D1 stores only
  AES-GCM ciphertext; the encryption key is a Worker secret.
- Collector requests first satisfy a dedicated Cloudflare Access Service Auth policy,
  then are bound to method, path, body hash, UTC timestamp, and a unique nonce using
  ControlForge HMAC-SHA256. Replayed nonces and requests more than five minutes old fail.
- Ingestion accepts at most 1,000 events, 8 MB per request, and 64 KB per normalized event.
- Cloudflare Queues provides at-least-once delivery. Stable tenant-scoped event and alert
  identifiers make consumers idempotent. A dead-letter queue retains poison messages.
- Every query includes tenant context. Cloudflare Access validates the issuer and
  application audience, and human principals must have an explicit D1 membership. Once
  Access is configured, the bootstrap administrator token is rejected. Browser
  authorization cookies are HTTP-only and bound by Cloudflare's binding-cookie control.
- Audit rows carry an HMAC and D1 triggers reject update and delete operations.
- The selected model provider receives only an existing deterministic alert, must cite supplied evidence,
  and cannot disable human review.
- Read-only response actions can be policy-approved. Active and high-impact actions need
  a second principal. The endpoint agent currently executes only read-only diagnostics;
  uninstalled active adapters report failure without changing the endpoint.

## Operational components

- Worker: authenticated API, dashboard, queue consumer, cron cleanup, case workflow.
- D1: tenants, credentials, nonces, events, alerts, cases, assessments, actions, audit.
- Queue: asynchronous detection and correlation.
- Dead-letter queue: terminal queue failures.
- Endpoint collector: read-only control probe, Cloudflare service identity, signed HMAC
  client, and SQLite delivery spool.
- Model triage: a fixed-host provider adapter with schema-constrained output, local
  validation, evidence-reference bounds, and a Worker secret. Production currently uses
  Meta Model API `muse-spark-1.2-contributor`; Gemini remains an optional adapter.

## Deployment gate

```bash
source .venv/bin/activate
make verify
cd cloud
npm ci
npm run check
npx wrangler deploy --dry-run
```

Provision D1 and both queues before deployment. Apply `migrations/0001_initial.sql`,
set `ADMIN_TOKEN`, `CREDENTIAL_KEK`, and `AUDIT_HMAC_SECRET` as Worker secrets, deploy,
then configure the Access issuer, audience, human membership, and a scoped Service Auth
token for collectors. Verify default denial, service-token-plus-HMAC ingestion, queue
processing, and tenant-scoped browser retrieval. Set `TRIAGE_PROVIDER`, the corresponding
fixed model identifier, and its Worker API-key secret only when live triage is desired.

## Remaining production expansion

This release is a production-oriented foundation, not a claim of enterprise EDR/SIEM
feature parity. High-volume deployments should shard D1 by tenant, add long-retention R2
event archives, connect an organizational identity provider and at least one additional
independent responder identity through Cloudflare Access, configure WAF/rate limiting and
alerting, and add separately tested operating-system containment adapters before enabling
active endpoint response.
