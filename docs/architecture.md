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

## Deliberate trade-offs

- **Local SQLite over a managed database:** reduces setup cost and keeps the project reproducible. The store interface can later be backed by PostgreSQL.
- **Documented Sigma subset over pretending full compatibility:** keeps evaluation behavior understandable and fully tested. Full pySigma interoperability remains roadmap work.
- **Read-only local probes over vendor credentials:** demonstrates control-health architecture without inventing production integrations or encouraging unsafe credential handling.
- **Sanctioned exposure API over dark-web scraping:** HIBP provides attributable, authorized breach and infostealer intelligence without crawling criminal forums or retaining leaked credentials.
- **Model-assisted explanation over model-authored detection:** deterministic rules remain the security decision boundary; Gemini can organize evidence but cannot create or close an incident.
- **Synchronous API processing:** appropriate for bounded demo batches; production ingestion would use authentication, queues, backpressure, and isolated workers.
