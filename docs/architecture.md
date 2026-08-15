# Architecture

## Design goals

ControlForge separates observation, policy evaluation, detection, persistence, and delivery so each boundary can be tested independently.

### Endpoint assurance path

1. `SystemProbe` collects only configured process names and filesystem metadata.
2. `EndpointAssuranceEngine` evaluates installation, running state, and heartbeat freshness.
3. Each control produces a typed finding with evidence and a remediation recommendation.
4. The CLI uses explicit exit codes: `0` healthy, `2` failed controls.

The fixture probe allows every branch to be reproduced without requiring an EDR installation or vendor tenant.

### Detection path

1. Pydantic validates incoming events at the trust boundary.
2. `SigmaSubsetEvaluator` compares normalized fields against versioned YAML rules.
3. Stateful detectors maintain bounded, per-actor windows for correlation.
4. Alerts receive deterministic identifiers based on rule and event identity.
5. `AuditStore` persists events and alerts with parameterized SQL and uniqueness constraints.

### Exposure-intelligence path

1. `HibpClient` accepts only syntactically valid DNS names and a fixed HIBP HTTPS host.
2. The API key is supplied through an environment variable rather than a command-line argument.
3. Verified-domain breach aliases and optional infostealer-log aliases are hashed immediately with SHA-256; plaintext aliases are not returned by the adapter or persisted.
4. `ExposureMonitor` assigns stable rule identifiers and severity while preserving provider attribution.
5. `ExposureService` writes normalized synthetic events and deduplicated alerts through the same audit boundary as event detections.

### Edge-correlation path

1. Versioned rules detect individual HTTP reconnaissance events.
2. `CredentialStuffingDetector` maintains a bounded per-source window and requires both failure-volume and distinct-account thresholds.
3. `SessionReplayDetector` accepts only hashed session identifiers and correlates cross-IP reuse within a bounded interval.
4. Edge signals remain detection-only; ControlForge does not block requests or revoke sessions.

### AI-assisted triage path

1. A deterministic detector produces an alert before any model is called.
2. The alert reasons are numbered and wrapped as untrusted telemetry so embedded instructions are not treated as policy.
3. Gemini is constrained to a typed JSON schema containing a summary, confidence, hypotheses, read-only next steps, and evidence references.
4. `TriageService` rejects references outside the supplied alert and rejects output that attempts to bypass human review.
5. AI output remains advisory and cannot suppress alerts, change severity, or trigger containment.

### Interface path

- The CLI is optimized for scheduled jobs and pipeline execution.
- FastAPI exposes the same application services to integration clients.
- OpenAPI schemas are generated from the same typed models used internally.

### Standalone SOC path

1. A single runtime owns a private `0600` SQLite database, WAL durability, ordered migrations,
   and a lifetime shared lock that makes restore prove the runtime is offline.
2. Console bootstrap and WebAuthn passkeys create hashed sessions with Secure/HttpOnly/Strict
   cookies, origin checks, CSRF verification, role capabilities, and bounded public-route rate
   limits.
3. One-use enrollment grants produce UUID collector credentials encrypted with AES-256-GCM.
   The same device may resume a locally failed claim only before its first authenticated check-in;
   a different device, expired grant, or already-seen endpoint fails closed.
4. Device-bound HMAC ingestion atomically creates durable detection jobs. A supervised worker
   reclaims expired leases and transactionally converges on one alert occurrence. Same-rule
   occurrences from the same device (or normalized actor fallback) link to one active semantic
   case; closing it frees the key for a fresh successor case without rewriting history.
5. Alerts retain the event digest, exact rule version/digest/snapshot, detector version, evidence,
   and fingerprint version. Original and current replay write separate evaluation records rather
   than rewriting the historical alert.
6. Case notes, dispositions, false-positive reasons, close, and reopen transitions are tenant- and
   role-scoped. Each case mutation appends to an HMAC chain with append-only checkpoints. Queue
   recurrence counts are exact; detail reads bound evidence to the newest 200 alerts, activity to
   500 entries, and dispositions to 200 while explicitly reporting truncation.
7. Online SQLite snapshots are streamed into AES-256-GCM backup artifacts using a purpose-separated
   HKDF key. Restore authenticates and verifies schema, tenant, checksum, integrity, and foreign keys
   before an atomic offline replacement.
8. The admin console is a CSP-nonce, same-origin web application. The local macOS app reads only a
   bounded redacted status snapshot, including enum-only containment posture and a bounded release
   time. It receives no action identifiers, rationale, PF recovery material, evidence, administrator,
   or response capability.

### Cloud SOC path

1. A fixed-host endpoint collector signs each request over its method, path, body hash,
   timestamp, and nonce using an encrypted-at-rest collector credential.
2. The Worker validates and tenant-scopes batches, writes idempotent D1 event records,
   and enqueues newly accepted event identities in bounded groups to control Queue
   operations without changing event-level detector semantics.
3. A queue consumer runs deterministic stateless and D1-windowed correlations, then
   creates alerts and cases. At-least-once delivery is absorbed by stable identifiers.
   A bounded cron reconciliation processes durable unprocessed rows directly from D1;
   it does not repeatedly re-enqueue the same backlog and amplify Queue operations.
4. Audit events are HMAC-protected and database triggers make the audit table append-only.
5. Read-only response actions can be policy-approved. Active or high-impact actions need
   a different approving principal before a signed endpoint agent can retrieve them.
6. The endpoint agent always supports read-only diagnostics. A separately enabled macOS PF
   adapter can execute only fixed, signed isolate/release actions with a management allowlist,
   15-minute maximum, owned state, rollback, and reconciliation. It remains disabled by default;
   unsupported, expired, or unconfigured actions fail closed.

## Deliberate trade-offs

- **Local SQLite over a managed database:** reduces setup cost and keeps the project reproducible. The store interface can later be backed by PostgreSQL.
- **Documented Sigma subset over pretending full compatibility:** keeps evaluation behavior understandable and fully tested. Full pySigma interoperability remains roadmap work.
- **Read-only local probes over vendor credentials:** demonstrates control-health architecture without inventing production integrations or encouraging unsafe credential handling.
- **Sanctioned exposure API over dark-web scraping:** HIBP provides attributable, authorized breach and infostealer intelligence without crawling criminal forums or retaining leaked credentials.
- **Model-assisted explanation over model-authored detection:** deterministic rules remain the security decision boundary; a configured model adapter can organize evidence but cannot create or close an incident.
- **Synchronous local FastAPI processing:** remains useful for bounded local scans; the
  Cloudflare control plane uses authenticated queue-backed ingestion for deployment.
- **D1 and Queues for the initial cloud control plane:** make deployment reproducible and
  provide durable asynchronous processing. Enterprise-volume retention should add
  per-tenant database sharding and immutable R2 archives.
