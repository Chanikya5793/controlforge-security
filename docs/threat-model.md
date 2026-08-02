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
| Unsafe active response | Version 0.2 is detection/read-only and performs no automated containment |
| Exposure API key disclosure | Key is read from an environment variable, never accepted as a CLI argument, logged, or persisted |
| Plaintext breached identity retention | Aliases are SHA-256 hashed immediately; only the digest enters events and alerts |
| Arbitrary outbound requests | Exposure transport is pinned to the HIBP HTTPS host and validates DNS names before path construction |
| Edge-memory exhaustion | Correlation uses time-bounded per-source or per-session state and API batches remain capped |
| Prompt injection through telemetry | Alert reasons are delimited as untrusted data; structured output is post-validated against supplied evidence indexes |
| Hallucinated AI evidence | References outside the deterministic alert are rejected and all triage output requires human review |
| Gemini credential disclosure | Key is read from `GEMINI_API_KEY`, sent only to the fixed Google API host, and never persisted |

## Production requirements not claimed by this project

- API authentication and authorization;
- tenant isolation;
- encrypted managed persistence and retention controls;
- signed vendor webhooks and credential rotation;
- HA queueing, backpressure, replay, and dead-letter handling;
- SOC-approved rule promotion and analyst disposition workflows.
- automated response, account resets, or edge blocking.
- autonomous AI severity changes, alert closure, or containment.
