# ControlForge Standalone 1.0 implementation plan

Status: active implementation program, started 2026-08-22.

## Product contract

ControlForge Standalone is an evidence-first security-operations appliance for one
organization. It must remain useful without Cloudflare, HIBP, Meta, Gemini, or another
paid or hosted provider. Optional providers may enrich an existing deterministic decision;
they may not become availability or security-decision dependencies.

The product has two deliberately different human surfaces:

1. **ControlForge for Mac** is a signed, machine-local user application. It shows only the
   local device's protection, enrollment, delivery, update, privacy, and redacted support
   status. It has no organization-wide investigation or response authority.
2. **ControlForge Admin** is a role-gated website. It provides organization-wide devices,
   detections, evidence, cases, triage, approvals, audit, retention, backups, and appliance
   operations. The same web application must work with self-hosted Core and hosted Cloud
   control planes.

The local and hosted products share versioned event, detection, alert, case, response, and
audit contracts. A rule must not silently make different decisions in the two runtimes.

## Product identity

The differentiator is a proof-carrying decision chain:

```text
authenticated observation
        -> canonical normalized event and digest
        -> versioned deterministic detector
        -> exact matched evidence and contributing events
        -> reproducible alert fingerprint
        -> case activity and human disposition
        -> evidence-bounded optional model assessment
        -> independent approval for consequential action
        -> bounded result and append-only audit lineage
```

ControlForge does not compete on the breadth of a general SIEM, MDM, or endpoint query
engine. It competes on decision provenance, privacy reduction, reproducibility, and
fail-closed response governance.

## Release invariants

1. Deterministic detection runs before optional model assistance.
2. A collector credential is bound to exactly one organization and device.
3. The collector may ingest, retrieve actions, and submit results only for its bound device.
4. Authorization is capability-checked in the service layer for every operation.
5. Viewer, analyst, responder, administrator, endpoint user, and collector are distinct
   principals.
6. No principal may approve its own active or high-impact response proposal.
7. Unsupported or expired response actions fail closed without changing an endpoint.
8. The local application never receives collector credentials, raw Santa records, response
   rationale, organization alerts, or arbitrary file access.
9. Accepted events and their durable detection jobs are committed atomically.
10. Stable identifiers make retries and crash recovery idempotent.
11. Backup, restore, retention, migration, and failure states are visible and audited.
12. External-provider absence cannot prevent collection, deterministic detection, case work,
    or read-only local status.

## Roles and capabilities

| Capability | Endpoint user | Viewer | Analyst | Responder | Admin | Collector |
|---|---:|---:|---:|---:|---:|---:|
| View own machine status | yes | scoped | yes | yes | yes | report only |
| View organization devices, alerts, and cases | no | yes | yes | yes | yes | no |
| Add case notes and dispositions | no | no | yes | yes | yes | no |
| Request optional AI triage | no | no | yes | yes | yes | no |
| Propose read-only action | no | no | yes | yes | yes | no |
| Propose active action | no | no | no | yes | yes | no |
| Approve another principal's active action | no | no | no | yes | yes | no |
| Manage people, roles, devices, rules, and operations | no | no | no | no | yes | no |
| Ingest, poll, and complete work for own device | no | no | no | no | no | yes |

Endpoint installation does not grant analyst access. Organization membership does not grant
endpoint collector authority.

## Target architecture

```text
Protected Mac
  ControlForge.app (unprivileged, local status only)
  signed root collector (telemetry, durable spool, structured actions)
  sanitized local status boundary
                       |
                       | TLS + device-bound signed requests
                       v
Standalone appliance
  TLS/reverse proxy
  authenticated FastAPI control plane
  canonical Python detection worker
  SQLite/WAL durable repository and job queue
  same-origin ControlForge Admin web application
```

The first single-node release targets 10-100 endpoints. It does not require Kafka,
Kubernetes, Redis, Celery, or a distributed database. SQLite must use WAL mode, foreign
keys on every connection, a bounded busy timeout, transactional jobs, local POSIX storage,
and the online backup API. A larger deployment can add a different repository adapter
without changing domain contracts.

## Workstreams

### WS1 - Canonical contracts and detection truth

- Add versioned JSON Schemas for event, alert, case, evidence, and response records.
- Specify fingerprint inputs, canonical serialization, lengths, and tenant/device scope.
- Treat `rules/*.yml` as canonical stateless detection content.
- Generate or validate the Cloudflare rule artifact from the canonical bundle.
- Add shared golden vectors for positive, negative, malformed, and boundary cases.
- Require Python and TypeScript to agree on firing, rule version, severity, reasons,
  contributing events, and fingerprint.
- Preserve stateful correlation inputs in storage so a process restart cannot change a
  decision.

### WS2 - Standalone durable kernel

- Add migrations and schema versioning.
- Add organization, identity, device, credential, enrollment, event, job, alert, case,
  activity, disposition, assessment, response, audit, backup, and appliance-state tables.
- Insert an event and detection job in one transaction.
- Lease jobs with expiry, bounded retry/backoff, and a terminal dead-letter state.
- Make alert/case creation and audit sequencing transactional and idempotent.
- Expose backlog count, oldest age, retries, dead letters, database state, and worker state.

### WS3 - Authentication, authorization, and enrollment

- Use a single-use, expiring, loopback/console bootstrap secret for the first admin.
- Register a passkey and one-time recovery codes; permanently disable bootstrap afterward.
- Use opaque, hashed, server-side sessions with Secure, HttpOnly, SameSite=Strict cookies.
- Require CSRF and origin validation for browser mutations.
- Enforce capabilities in services and verify every route with a role matrix.
- Support optional OIDC later without removing offline local administration.
- Use single-use enrollment tokens and unique device-bound credentials.
- Support credential overlap during safe rotation, then revoke the previous credential.

### WS4 - Machine-local user application

- Treat Apple Silicon macOS 13 or later as the initial explicit support matrix; do not
  claim Intel support until every packaged executable is universal and tested.
- Persist a strict, redacted local status DTO atomically after every collector run.
- Build a signed SwiftUI application installed with the collector package.
- Show overview, components, connection, privacy, support, and managed settings.
- Work offline from the last sanitized status snapshot.
- Show capped backlog honestly as `100+`, not `100`.
- Keep remediation informational unless a separately reviewed helper operation is allowlisted.
- Add keyboard, VoiceOver, 200 percent zoom, reduced-motion, forced-colors, and offline tests.

### WS5 - Admin and analyst website

- Replace manual tenant UUID entry with authenticated membership-derived organization choice.
- Implement operation overview, case queue/detail, evidence timeline, alert detail/replay,
  devices, assessments, approval queue, audit explorer, rules, team, enrollment, retention,
  backup, integration, and system-health surfaces.
- Use one versioned token and component system across Core and Cloud deployments.
- Meet WCAG 2.1 AA: contrast, 44 by 44 targets, focus-visible, semantic status/error
  announcements, keyboard operation, responsive tables, skip navigation, and 200 percent zoom.
- Never label the system autonomous; human review and approval are explicit product states.

### WS6 - Proof-carrying investigation workflow

Current implementation note: standalone and Cloud now expose tenant-scoped case assignment,
notes, transitions, canonical dispositions, false-positive reasons, reopen guards, and audited
UI/API workflows. Both runtimes provide current and stored-snapshot replay for newly recorded
decisions; legacy Cloud alerts without a snapshot report original replay as unavailable. Cloud
migration 0007 and the generated evaluator are deployed. Installed-appliance and physical
acceptance remain separate release evidence.

Standalone migration 8 adds semantic recurring-alert case aggregation matching the hosted
product boundary: rule plus device (normalized actor fallback) owns at most one non-closed case.
Recurrences link without creating queue noise, priority can only escalate, closure frees a fresh
successor, and bounded detail projections expose exact totals and truncation.

- Store source digest, rule ID/version, detector version, reasons, contributing event IDs,
  and correlation window on each alert.
- Add assignment, notes, status transitions, disposition, false-positive reason, and reopen.
- Add Decision Replay against the original rule and, separately, the current rule.
- Preserve historical decisions when rules change.
- Retrieve and display stored model assessments with citations or abstention.

### WS7 - Operations and data ownership

Current implementation note: encrypted online backup/restore, migration preflight and rollback,
diagnostics, and evidence-safe telemetry retention are implemented locally. Retention supports
policy preview and audited exact deletion counts while preserving all referenced alert/case
evidence and the audit chain. A bounded 2,000-event verifier now covers exact retry deduplication,
worker reconstruction, semantic case aggregation, online encrypted midpoint backup, live-restore
rejection, and separate restored-database integrity. Scheduled multi-hour soak and clean-appliance
disaster recovery remain release gates.

- Add configurable retention with preview, audited deletion counts, and audit checkpoints.
- Create authenticated encrypted backups using SQLite online snapshots.
- Restore into a clean appliance and verify row counts, schema, audit integrity, and secrets.
- Add migration compatibility, upgrade preflight, rollback support, and support bundles.
- Exercise disk pressure, database locks, process kill points, network outage, time skew,
  TLS renewal, backlog saturation, and corrupted backups.

### WS8 - Response boundary

- Ship read-only diagnostics first.
- Keep active response unavailable until two independent responders and a tested adapter exist.
- Transactionally enforce proposal, expiry, independent approval, dispatch, result, and audit.
- Implement at most one reversible platform adapter initially.
- Require a maximum duration, management-channel preservation, automatic release,
  idempotency, rollback on partial failure, and out-of-band recovery.
- Require a physical isolate/release/automatic-expiry exercise before claiming availability.

## Implementation order and release gates

### Gate 0 - Characterization baseline

- Existing Python and Worker gates remain green.
- Existing queue-recovery changes are preserved.
- Shared contracts and golden vectors document all current parity and divergence.

### Gate 1 - Endpoint Visibility and RBAC Foundation

- Every cloud and standalone operation has positive and negative role tests.
- Device credentials cannot impersonate another device.
- The website discovers organizations without copied tenant UUIDs.
- The admin website shows device inventory and honest operational health.
- The signed local app shows only sanitized local status and stays useful offline.
- No active-action UI is exposed.

### Gate 2 - Durable standalone operating loop

- One command starts an appliance with no external-provider call.
- A real event becomes one deterministic alert and one case across retry and restart.
- Worker termination at each transaction boundary converges without loss or duplication.
- Backlog, retries, dead letters, and stale devices are observable.

### Gate 3 - Identity and complete investigation

- One-use bootstrap, passkey login, recovery, session expiry, CSRF, and role isolation pass.
- Admin enrolls and rotates a device without manually moving long-lived secrets.
- Analyst assigns, investigates, notes, dispositions, closes, and reopens a case.
- Decision Replay reproduces the original decision and identifies current-rule differences.

### Gate 4 - Operational independence

- Backup during ingestion restores cleanly with matching durable state.
- Retention and schema migration are reversible and audited.
- A representative 24-hour soak has zero accepted-event loss and bounded backlog.
- Clean install, upgrade, rollback, and uninstall work on a separate Mac.

### Gate 5 - Gated response

- Two independent responders are enrolled.
- Same-principal, expired, wrong-device, replayed, and unsupported actions fail closed.
- One reversible adapter passes rollback and physical-device recovery exercises.

## Final acceptance scenario

On clean systems, a new operator installs the standalone appliance, securely creates the
first administrator, enrolls a Mac, sees accurate local protection status, produces a real
test signal, observes the same device and event in the admin website, receives one
deterministic proof-carrying alert and case, investigates and dispositions it, replays the
decision, survives loss of connectivity and process restart, backs up and restores the
appliance, upgrades and rolls back supported components, and completes the workflow without
editing source code or configuring a mandatory third-party service.

Passing source tests does not alone prove this scenario. Evidence must separately record
contract tests, package builds, local runtime exercises, signed installation, browser and
VoiceOver acceptance, clean-device behavior, backup restoration, external-provider calls,
and any physical active-response exercise.
