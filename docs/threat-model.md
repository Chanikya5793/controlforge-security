# Threat model

## Assets

- endpoint control status;
- normalized security events;
- detection rules and alert decisions;
- analyst investigation history;
- future vendor API credentials.

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
| Unsafe active response | Version 0.1 is detection/read-only and performs no automated containment |

## Production requirements not claimed by this project

- API authentication and authorization;
- tenant isolation;
- encrypted managed persistence and retention controls;
- signed vendor webhooks and credential rotation;
- HA queueing, backpressure, replay, and dead-letter handling;
- SOC-approved rule promotion and analyst disposition workflows.
