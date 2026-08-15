# Threat model

## Assets

- endpoint control status;
- normalized security events;
- detection rules and alert decisions;
- analyst investigation history;
- future vendor API credentials.
- HIBP subscription credentials and verified-domain exposure intelligence;
- hashed application session identifiers and edge authentication telemetry.

## Trust boundaries

- local operating-system process and filesystem observations;
- inbound API event batches;
- YAML rule and agent configuration;
- SQLite persistence;
- CLI/API output consumed by operators or automation.

## Primary threats and controls

| Threat | Current control |
|---|---|
| Shell injection through control configuration | Fixed subprocess argument list; `shell=False`; paths are treated as data |
| SQL injection through event fields | Parameterized SQL only |
| Unbounded event ingestion | API batches capped at 10,000 events; alert queries capped at 1,000 |
| Duplicate alert flooding | Deterministic alert IDs and database uniqueness constraints |
| Ambiguous detector decisions | Every alert records matched fields and reasons |
| Malformed telemetry | Pydantic validation at CLI/API boundaries |
| Secret disclosure | Repository contains fixtures only; no vendor credentials are required |
| Unsafe active response | Active actions require a different approving principal; the exact-device macOS PF adapter is disabled by default, uses fixed arguments and owned state, preserves configured management access, expires within 15 minutes, and rolls back on partial failure |
| Exposure API key disclosure | Key is read from an environment variable, never accepted as a CLI argument, logged, or persisted |
| Plaintext breached identity retention | Aliases are SHA-256 hashed immediately; only the digest enters events and alerts |
| Arbitrary outbound requests | Exposure transport is pinned to the HIBP HTTPS host and validates DNS names before path construction |
| Edge-memory exhaustion | Correlation uses time-bounded per-source or per-session state and API batches remain capped |
| Prompt injection through telemetry | Alert reasons are delimited as untrusted data; structured output is post-validated against supplied evidence indexes |
| Hallucinated AI evidence | References outside the deterministic alert are rejected and all triage output requires human review |
| Model credential disclosure | Keys are Worker secrets, are sent only to the adapter's fixed Meta or Google API host, and are never persisted |
| Collector credential theft | Collector secrets are encrypted with a Worker-held AES-GCM key and returned only once |
| Access service-token theft | Collector traffic requires both the Access service token and a separate request-bound HMAC credential; both are stored outside the repository and rotate independently |
| Collector request replay | HMAC covers method, path, body, timestamp, and nonce; nonces are persisted and expire |
| Cross-tenant data access | Every cloud query is tenant-scoped and Access principals require tenant membership |
| Queue redelivery | Stable tenant-scoped identifiers and unique constraints make event and alert writes idempotent |
| Audit record tampering | Records carry an HMAC and database triggers reject updates and deletes |
| Autonomous unsafe action | Active and high-impact actions require a different approving principal; unsupported endpoint adapters fail closed |
| Unsupported response execution | The endpoint collector returns a bounded failure result without changing the host when the separately enabled adapter does not support the exact action or cannot validate its owned state |
| Recurring-alert case flooding | Active cases have a tenant-scoped semantic key derived from rule and device or normalized actor; a partial unique index and transactional link/update aggregate recurrences while closed history remains immutable |
| Unbounded case detail | Case and evidence projections return exact totals plus bounded newest records and explicit truncation indicators |

## Production requirements not claimed by this project

- multi-node standalone high availability, PostgreSQL failover, or enterprise tenant sharding;
- an off-appliance audit-chain anchor, audit-key rotation ceremony, or immutable external archive;
- production-scale D1/Queue chaos and long-duration soak evidence for every migration/runtime;
- field-validated operating-system containment, account resets, or edge blocking. The macOS
  adapter remains disabled until its privileged install and live rollback exercise are verified.
- autonomous AI severity changes, alert closure, or containment.
