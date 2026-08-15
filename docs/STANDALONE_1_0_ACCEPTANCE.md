# ControlForge Standalone 1.0 acceptance and evidence plan

Status: pre-release acceptance specification and current automated evidence.

Last reviewed: 2026-08-24.

## Release decision

ControlForge Standalone is **not yet release-ready**. The local control plane now has a
substantial operating loop, but source tests and an in-process API exercise are not evidence
of a clean appliance installation, a trusted TLS deployment, a hardware-backed passkey, or
a physical endpoint signal. The current-source artifact is a signed, notarized, and stapled release candidate,
but it has deliberately not been installed over this Mac's active collector.

The release claim is permitted only after every required row below is `PASS` with evidence
from the named boundary. A database table or UI placeholder is not an implemented workflow.

Evidence states:

- `PASS`: the stated boundary was exercised and its evidence was retained.
- `PARTIAL`: a lower boundary passed, but the complete user workflow did not.
- `NOT IMPLEMENTED`: required callable behavior is absent.
- `UNVERIFIED`: implementation may exist, but the required environment was not exercised.
- `NOT RUN`: an available automated gate was skipped in this run.

## Acceptance matrix

| Stage | Standalone 1.0 acceptance criterion | Current evidence | Current state | Evidence still required for release |
|---|---|---|---|---|
| Install | A clean supported Mac installs one appliance and local app without source edits; upgrade, rollback, and uninstall preserve the documented data contract. | The current-source `ControlForge-0.3.0.pkg` is 14,526,455 bytes with SHA-256 `a80cd724a6202f773074a002e534f78bf9b17c0fb3374606421017d929eacd0a`. It is Developer ID Installer-signed, Apple-accepted under notarization submission `2ff3b42c-d5a3-44a0-ba09-8c8be2187dfe`, stapled, and accepted by `spctl`. Its strict code-sign, payload, bundled standalone launcher, exact installed canonical rule set, credential-rotation, endpoint lifecycle, service lifecycle, local containment-recovery commands, and containment-aware native dashboard boundaries were inspected. | PARTIAL | Install on a separate clean Mac; exercise launch, reboot, crash recovery, upgrade, rollback, endpoint uninstall, appliance-service uninstall, and post-operation data/health checks. |
| Bootstrap | The console emits one expiring token; the first admin completes a hardware-backed passkey ceremony; the token and challenge cannot be reused. | Real identity service and HTTP routes pass using a deterministic test passkey adapter. Production uses `WebAuthnPasskeyAdapter`. | PARTIAL | Supported browser plus real platform authenticator, trusted origin, UV evidence, recovery-code exercise, expiry/replay exercise on the installed appliance. |
| Enroll | An admin creates a bound one-use grant; a Mac claims it once; its credential is device-bound, encrypted at rest, and placed into the intended Keychain boundary without manual long-lived-secret handling. | Grant, claim, encrypted persistence, device binding, replay rejection, activation, uninstall, and endpoint-bound rotation have automated service/API/package tests. Rotation creates an inactive replacement, encrypts it for the predecessor, swaps the fixed System Keychain item, activates only after a replacement-signed acknowledgement, and then revokes the predecessor. No plaintext replacement secret enters the admin response or endpoint spool. | PARTIAL | Root System Keychain/ACL verification on an installed Mac; live claim/check-in/activation; crash-during-swap recovery; live revocation; network-loss recovery; and physical uninstall/PF-release proof. |
| Signal | A real supported endpoint produces a controlled signal; signed ingestion accepts it exactly once and creates one durable job. | The harness sends a synthetic encoded-PowerShell event through the real standalone HMAC/API/storage boundary. | PARTIAL | Real Santa or other documented endpoint telemetry from an enrolled clean Mac, with event digest and device identity correlated to the installed artifact. |
| Investigate | Admin/analyst UI shows the device, alert, case, evidence, rule provenance, queue health, and audit lineage without database access. | Authenticated APIs expose devices, summary, alerts, cases, rule version/digest, detector version, evidence, and job health; same-rule/same-device recurrences aggregate into one active case with exact recurrence counts, priority promotion, fresh successor creation after closure, and explicit bounded-history truncation. The same-origin admin workbench was rendered with tenant-scoped seeded state on desktop, 390 px, and 320 px without document overflow or undersized visible controls. | PARTIAL | Installed-browser alert/case workflow, real passkey ceremony, keyboard/VoiceOver/200% zoom checks, and audit-lineage acceptance against appliance state. |
| Replay | Original replay uses the stored rule snapshot and evidence; current replay reports a changed, same, no-match, or unavailable result without mutating the historical alert. | Original/current replay service and HTTP route are implemented and tested; the harness gets `same` for the original decision. | PASS for local API boundary | Installed-browser acceptance and larger rule-version compatibility corpus remain release evidence, but the current API contract is implemented. |
| Disposition | An authorized analyst records ownership, notes, disposition, false-positive reason, close, and reopen activity; records are tenant-scoped, audited, and append-only. | The service and HTTP APIs implement active-human assignment/unassignment, note, state transition, disposition, close/reopen, RBAC, and HMAC-chained audit verification. Assignment rejects viewers, inactive/missing users, and cross-tenant identities; each change is visible in the queue/detail/timeline and appended to the audit chain. A reopened case requires a fresh current-cycle disposition before it can close again. The harness exercises the case sequence, and the CSP-bound admin source exposes the full case workbench. | PARTIAL | Installed-browser case assignment/detail/note/disposition/close/reopen and role-negative acceptance. |
| Response | One authenticated human proposes an exact-device action; a different human approves it before expiry; the signed device polls and reports an idempotent result; containment is bounded and reversible. | The governance API enforces distinct passkey principals, expiry, exact-device HMAC dispatch, nonce replay rejection, bounded results, idempotency, and audit lineage. A disabled-by-default macOS PF adapter has strict DTOs, fixed command arrays, a dedicated anchor, management allowlisting, 15-minute maximum duration, rollback, and reconciliation tests. A root-only local recovery command reports only redacted posture, disables collector polling before release, and flushes only ControlForge-owned PF state. The harness exercises the governance and adapter boundaries without executing PF. | PARTIAL | Two independent real humans with hardware-backed passkeys; installed root-owned adapter explicitly enabled; actual PF isolation while management remains reachable; existing-connection and packet evidence; explicit and automatic release; physical local-console recovery and deliberate reactivation. |
| Restart | A crash after acceptance or lease does not lose or duplicate events, alerts, or cases; expired leases are reclaimed deterministically. | Durable event/job transaction and lease recovery tests exist. The acceptance harness reconstructs the database/store/worker and reclaims an abandoned lease. A separate 2,000-event endurance run accepted 2,000 unique events plus 2,000 idempotent retries, reconstructed the worker at midpoint, and converged with 2,000 succeeded and zero nonterminal jobs. | PASS for local process boundary | Installed-process kill-point matrix and a longer multi-hour outage/backlog exercise. |
| Backup/restore | An authenticated operator creates an encrypted online backup during ingestion, restores it into a clean appliance, and verifies schema, counts, audit integrity, and secret handling. | `StandaloneBackupService` creates authenticated AES-256-GCM backups from online SQLite snapshots, verifies manifests and schema/tenant identity, rejects tampering and wrong keys, records backup history, requires an offline exclusive lock for atomic restore, and retains bounded verified artifacts. The harness creates, verifies, mutates past the backup point, restores, and re-verifies the case audit chain. The endurance gate additionally created and authenticated a midpoint backup while the simulated runtime shared lock remained held, rejected a live restore, restored into a separate database, and verified exact counts, integrity, and foreign keys. | PARTIAL | Clean-appliance live disaster-recovery exercise using separately preserved keys; sustained concurrent-writer backup drill; external artifact custody and recovery-key policy; installed rollback proof. |
| Diagnose | Health and admin operations show worker error, pending/retry/dead jobs, stale devices, database state, retention state, and bounded support evidence without secrets. | `/health`, dashboard summary, device inventory, job counts, and an evidence-safe retention panel are implemented. The temporary harness now proves stale HMAC time rejection, backup-tamper rejection, SQLite writer-lock failure/recovery, atomic rejection under a page-count disk-exhaustion ceiling, and bounded detector retry-to-dead-letter. Retention is configurable from 30 to 3,650 days, previews exact eligible counts, and preserves alerts, cases, dispositions, responses, and audit evidence. Appliance service health reports bounded days-to-expiry and becomes degraded during a 30-day TLS renewal window while expired or mismatched material still fails closed. | PARTIAL | Installed-service degraded-worker/log exercise, real filesystem-pressure recovery, scheduled-retention soak, trusted certificate renewal/restart, and a retained redacted support bundle from the appliance. |

## Automated non-destructive harness

[`tools/verify_standalone_acceptance.py`](../tools/verify_standalone_acceptance.py) creates a
temporary directory and exercises the current local APIs and SQLite boundary. It makes no
external network request, does not install software, does not use the macOS Keychain, and
does not mutate an existing ControlForge database. Unless `--output` is supplied, all test
state is deleted when the process exits.

The harness currently performs:

1. migration, health, admin HTML, and CSP checks;
2. console-token bootstrap through HTTP using a clearly identified test-only passkey adapter;
3. admin-created, device-bound, one-use enrollment;
4. signed ingestion of one synthetic encoded-PowerShell event;
5. abandoned worker lease plus reconstruction/reclaim;
6. one alert, one case, no-backlog, and duplicate-ingestion checks;
7. a second same-rule/same-device detection aggregated into that case with one recurrence;
8. note, investigate, disposition, close, reopen, and audit-chain verification;
9. original decision replay;
10. two-principal response proposal/approval, self-approval denial, exact-device signed polling,
   nonce replay rejection, redispatch, idempotent bounded results, and audit verification;
11. endpoint-bound encrypted credential rotation, replacement acknowledgement, predecessor
    revocation, and replacement-authenticated idempotent ingestion;
12. a non-executing macOS PF adapter contract exercise covering fixed arguments, dedicated-anchor
    rules, management allowlisting, idempotent isolation, explicit release, the 15-minute cap,
    and automatic release;
13. raw SQLite online-snapshot integrity and count checks;
14. encrypted backup creation, authentication, state mutation, atomic restore, and restored
    audit-chain verification;
15. temporary clock-skew, encrypted-backup-tamper, SQLite-lock/recovery, page-ceiling
    disk-exhaustion, and bounded retry-to-dead-letter fault injection;
16. optional Python/Cloud stateless contract gates;
17. signed/notarized/stapled release-package verification when supplied;
18. explicit `UNVERIFIED` release blockers, including the physical response exercise.

It never writes credential values, bootstrap tokens, recovery codes, cookies, or event
payloads into its evidence JSON. Synthetic identities are fixed for reproducibility; the
report timestamp records the actual UTC execution time.

Run the current-scope exercise:

```bash
source .venv/bin/activate
python tools/verify_standalone_acceptance.py --json
```

Run it with the shared local/Cloud stateless contract gates and retain a non-secret report:

```bash
source .venv/bin/activate
python tools/verify_standalone_acceptance.py \
  --run-contract-gates \
  --signed-package dist/macos/ControlForge-0.3.0.pkg \
  --signed-package-sha256 a80cd724a6202f773074a002e534f78bf9b17c0fb3374606421017d929eacd0a \
  --output /tmp/controlforge-standalone-acceptance.json
```

Require every release boundary to be complete:

```bash
source .venv/bin/activate
python tools/verify_standalone_acceptance.py \
  --run-contract-gates \
  --signed-package dist/macos/ControlForge-0.3.0.pkg \
  --signed-package-sha256 a80cd724a6202f773074a002e534f78bf9b17c0fb3374606421017d929eacd0a \
  --require-release-ready
```

That final command is expected to exit `2` today because the report honestly includes
non-pass boundaries such as `UNVERIFIED`. Exit `0` without `--require-release-ready` means
only that all currently implemented automated checks passed. Exit `1` means an implemented
check failed.

## Bounded restart and backup endurance

[`tools/verify_standalone_endurance.py`](../tools/verify_standalone_endurance.py) uses an
isolated empty directory and no external network. The retained 2026-08-24 run accepted 2,000
unique events plus 2,000 exact retries in batches of 100, reconstructed the worker at midpoint,
and produced 40 deterministic alert occurrences linked to one active semantic case. All 2,000
jobs succeeded with zero pending, leased, retry, or dead jobs. It created and authenticated an
encrypted midpoint backup while the runtime shared operation lock remained held, rejected a
live restore, restored into a separate database, and verified exact counts, SQLite integrity,
and zero foreign-key violations. The JSON report contains counts and timings only—no event
payload, credential, secret, or filesystem path.

```bash
source .venv/bin/activate
python tools/verify_standalone_endurance.py \
  --events 2000 \
  --batch-size 100 \
  --alert-every 50 \
  --output /tmp/controlforge-standalone-endurance.json
```

This is bounded local persistence evidence, not a multi-hour installed-service soak or a
concurrent-writer clean-appliance disaster-recovery exercise.

## Physical Mac evidence capture

[`tools/verify_macos_physical_acceptance.py`](../tools/verify_macos_physical_acceptance.py)
is a separate read-only verifier for the release gates that the temporary harness cannot
exercise. It runs fixed receipt, signature, Gatekeeper, launchd, and System Keychain
metadata queries; validates fixed filesystem ownership and modes; parses only the strict
redacted agent-status contract; and opens the telemetry spool only for SQLite
`quick_check`. It never requests a Keychain secret value or reads telemetry rows. The
machine name is represented only by a truncated SHA-256 fingerprint. The installed phase also
requires the exact ten root-owned canonical YAML files at the stable installed rules path.

Run these phases on the same separate Apple Silicon Mac and retain every JSON file:

```bash
source .venv/bin/activate

python tools/verify_macos_physical_acceptance.py \
  --phase preinstall \
  --package dist/macos/ControlForge-0.3.0.pkg \
  --package-sha256 a80cd724a6202f773074a002e534f78bf9b17c0fb3374606421017d929eacd0a \
  --output /tmp/controlforge-preinstall.json

# Install the package, then capture the untouched disabled-daemon state.
python tools/verify_macos_physical_acceptance.py \
  --phase installed \
  --output /tmp/controlforge-installed.json

# Complete agent-enroll/activation and one successful collector cycle.
python tools/verify_macos_physical_acceptance.py \
  --phase running \
  --output /tmp/controlforge-running.json

# Reboot, wait for a successful cycle, and run the same phase again.
python tools/verify_macos_physical_acceptance.py \
  --phase running \
  --output /tmp/controlforge-after-reboot.json

# After the confirmation-gated uninstall, run from the preserved repository environment.
python tools/verify_macos_physical_acceptance.py \
  --phase uninstalled \
  --output /tmp/controlforge-uninstalled.json
```

The optional `enrolled` phase represents the recovery boundary after a grant was claimed
and credentials/configuration were installed but before `agent-activate` succeeded. The
normal `agent-enroll` happy path proceeds directly to `running`, so it need not produce an
`enrolled` report. A passing JSON record is boundary evidence, not a substitute for the
human/browser, real telemetry, upgrade/rollback, PF isolation/release, and out-of-band
recovery observations listed in the matrix.

## Contract gates

The current cross-runtime gate is deliberately limited to canonical stateless rules:

```bash
source .venv/bin/activate
python tools/compile_detection_rules.py --check
pytest -q tests/test_detection_conformance.py --no-cov

cd cloud
npx vitest run test/detection-conformance.test.ts --coverage=false
```

It proves generated-rule freshness and exact shared projections for contract version, rule
ID/version/digest, title, severity, event identity, actor, tags, and time. It also checks the
deployed Cloud detector's rule-ID parity over the shared vectors.

It does **not** yet prove:

- production-scale stateful correlation parity under soak/chaos across D1 and standalone SQLite,
  although shared
  vectors now cover thresholds, malformed values, duplicates, tenant isolation, ordering, and
  standalone restart recovery;
- exact human-readable reason parity;
- a shared active fingerprint format across both persistence paths (Cloud activates v1 for new
  alerts while standalone preserves its legacy persisted ID contract);
- complete Cloud and standalone response/audit schema parity; case ownership and canonical
  disposition/false-positive contracts are aligned locally;
- immutable historical correlation inputs for Cloud original replay (new Cloud alerts can replay
  their stored detector snapshot, but correlation replay uses currently retained history);
- production soak/rollback drills for the deployed generated Cloud evaluator and migrations
  0002 through 0007.

The fingerprint is specified in
[`contracts/detections/alert-fingerprint-v1.md`](../contracts/detections/alert-fingerprint-v1.md),
and is active for new Cloud alerts. Existing alert and case IDs were deliberately preserved;
semantic occurrence resolution prevents a retry from creating a second v1 alert for a legacy row.

## Manual installed-appliance commands

These commands expose the current runtime; they are not proof of installation or trust by
themselves:

```bash
source .venv/bin/activate

controlforge standalone bootstrap-token \
  --database /var/lib/controlforge/controlforge.db \
  --secrets-directory /var/lib/controlforge/secrets \
  --rules rules \
  --admin-origin https://controlforge.example \
  --rp-id controlforge.example

controlforge standalone serve \
  --database /var/lib/controlforge/controlforge.db \
  --secrets-directory /var/lib/controlforge/secrets \
  --rules rules \
  --admin-origin https://controlforge.example \
  --rp-id controlforge.example \
  --host 127.0.0.1 \
  --port 8443 \
  --tls-certificate /etc/controlforge/tls/fullchain.pem \
  --tls-private-key /etc/controlforge/tls/private-key.pem

sudo /Library/ControlForge/bin/controlforge agent-enroll \
  --api-host controlforge.example \
  --api-port 8443 \
  --device-id mac-primary \
  --display-name 'Primary Mac'
```

Do not paste the printed bootstrap token into logs or an evidence document. A deployment
must terminate on a certificate trusted by the intended admin devices, preserve the exact
origin used by WebAuthn, restrict database/secret permissions, and supervise the service.
The repository has not yet supplied evidence that these requirements were met on a clean
Standalone appliance.

## Required release evidence package

For each release candidate, retain a claim ledger containing:

- commit and clean-worktree identity;
- source gate and coverage outputs;
- generated-contract digests and vector results;
- exact built artifact digests and architectures;
- certificate identity, code-sign verification, notarization, and stapling output;
- clean-install, first launch, bootstrap, hardware passkey, enrollment, and first-check-in
  timestamps;
- real signal event, alert, case, evidence, replay, and disposition identifiers;
- response action, proposer, independent approver, dispatch, result, and audit identifiers;
- PF adapter configuration and root-owned-state evidence, exact command-boundary records,
  management connectivity during isolation, release timestamps, and out-of-band recovery;
- restart/kill-point results and pre/post row counts;
- encrypted backup identity plus clean restore, integrity, schema, audit, and count checks;
- browser accessibility matrix and local-app offline/privacy checks;
- upgrade, rollback, and uninstall results;
- every remaining limitation and unverified boundary.

An older signed/notarized collector package is not evidence for a newly assembled Standalone
package. The newly assembled Standalone-capable release candidate is signed, notarized, and
stapled, but it is not claimed as installed, upgraded, rolled back, removed, or accepted on a
separate clean Mac. There is also no trusted-certificate or physical-hardware acceptance
evidence for this milestone yet.

## Response boundary

Standalone now contains code-level response governance and a disabled-by-default, bounded
macOS PF adapter. Automated tests and the acceptance harness prove the service contracts,
fixed command shapes through an injected runner, management-rule construction, state
ownership, expiry, idempotency, rollback, and reconciliation. They do not prove that PF was
changed on a real endpoint.

**No physical active-response capability is claimed.** The adapter remains disabled by
default, and this milestone has no installed-Mac evidence for isolation, management-channel
preservation, explicit or automatic release, existing-connection handling, normal-connectivity
restoration, or out-of-band recovery. It also does not implement identity disablement, session
revocation, arbitrary command execution, CrowdStrike containment, or autonomous remediation.
Release readiness requires two independent real responders plus the complete physical
isolate/release exercise named in the matrix.
