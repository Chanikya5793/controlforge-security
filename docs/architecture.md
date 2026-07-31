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

### Interface path

- The CLI is optimized for scheduled jobs and pipeline execution.
- FastAPI exposes the same application services to integration clients.
- OpenAPI schemas are generated from the same typed models used internally.

## Deliberate trade-offs

- **Local SQLite over a managed database:** reduces setup cost and keeps the project reproducible. The store interface can later be backed by PostgreSQL.
- **Documented Sigma subset over pretending full compatibility:** keeps evaluation behavior understandable and fully tested. Full pySigma interoperability remains roadmap work.
- **Read-only local probes over vendor credentials:** demonstrates control-health architecture without inventing production integrations or encouraging unsafe credential handling.
- **Synchronous API processing:** appropriate for bounded demo batches; production ingestion would use authentication, queues, backpressure, and isolated workers.
