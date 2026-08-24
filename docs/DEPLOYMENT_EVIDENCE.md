# ControlForge 0.3 deployment evidence

Verified through 2026-08-20 in the `Chanakya Chowdary` Cloudflare account.

## Runtime

- Worker: `controlforge-soc`
- Custom hostname: `https://soc.chanakyachowdary.in`
- Workers.dev fallback: `https://controlforge-soc.chanakya-chowdary.workers.dev`
- Deployed version: `03a817bb-2d61-4507-bf45-6decff298715`
- D1 database: `controlforge-production`
- D1 database ID: `8eea401d-2513-4beb-9fdf-b59d3c7113df`
- Queue: `controlforge-events`
- Dead-letter queue: `controlforge-events-dlq`
- Cron cleanup: every five minutes
- Worker observability: enabled

TLS and routing were verified on the custom hostname. Cloudflare Access now returns a login
redirect for unauthenticated custom-host requests. A valid collector service identity
reached `/health`, which returned HTTP 200, version `0.3.0`, and hardened cache, transport,
framing, content-type, referrer, and permissions headers.

## Live end-to-end acceptance

The local endpoint collector used its encrypted production credential to send signed
control findings through the custom deployment stack. A nullable-field normalization bug
was found during the first attempt; the SQLite spool retained the batch, the client and
status output were corrected, and the retained batch was delivered successfully.

At 2026-08-18 05:31 CDT, after the signed launch daemon delivered the live Santa backlog
and the recovery cron ran, production contained:

- 4,290 endpoint events stored and processed;
- 0 unprocessed events and 0 processing errors;
- 25 deterministic alerts and 25 automatically opened cases;
- 51 integrity-protected audit records;
- 1 persisted Meta contributor-tier triage assessment;
- 0 batches remaining in the local endpoint spool.

The launch daemon had completed 39 runs with last exit code 0. Its final status reported
one delivered batch, zero pending batches, 125 real Santa events collected in that cycle,
and zero rejected Santa lines. The error log's most recent entry predates the successful
runs. The database also contains explicit deployment fixtures documented below; fixture
records are not represented as real endpoint observations.

The original sequential ingestion path timed out after D1 accepted a large Santa batch,
leaving 267 events accepted but not queued. The production fix hashes and inserts batches
in bounded parallel operations, splits Queue writes into provider-supported chunks,
requeues only duplicate events still marked unprocessed, and performs a bounded cron
reconciliation for orphan recovery. A real cron run reduced the backlog from 267 to zero.

## Queue free-tier exhaustion and recovery

On 2026-08-20, continuous Santa telemetry exhausted the Workers Free allowance of 10,000
Queue operations per day. The event store remained intact: immediately before the queue
optimization deployment, production contained 11,845 events, 16 unprocessed records, zero
processing errors, and a latest accepted timestamp of `2026-08-20T03:03:34.628Z`. The
endpoint spool retained at least 100 batches and continued retrying instead of deleting
them. These figures establish durability, not successful processing of the retained
backlog.

Version `78ef936c-1ed7-422b-bf6d-25743361b66f`, created at
`2026-08-20T04:01:33.550Z`, changed the Queue payload from one event identity per message
to at most 50 identities per message. It caps each `sendBatch` call at 25 messages so even
maximum-length event identifiers remain below Cloudflare's aggregate request limit. The
consumer processes identities sequentially within each message, acknowledges only after
the group completes, absorbs partial redelivery through existing idempotency controls,
and remains compatible with single-event messages already in flight. Runtime validation
rejects malformed or oversized grouped payloads into the configured retry/dead-letter
path. The five-minute recovery job uses the same grouped format across tenant boundaries.

The regression suite proves that 205 accepted events produce five Queue messages rather
than 205, duplicate retry remains recoverable, grouped messages process every referenced
event, and the legacy single-event format still processes successfully. Production health
returned HTTP 200 after deployment.

Post-reset verification on 2026-08-21 proved that the retained backlog began delivery:
D1 grew from 11,845 to 57,295 events, an increase of 45,450. The original five-minute
reconciliation repeatedly enqueued rows that were still pending while the queue consumer
worked through the initial burst. A live Worker tail then captured Cloudflare error
`10253`, confirming that the 10,000-operation daily write allowance had been exhausted a
second time. At that point 4,812 D1 events remained pending, with zero processing errors.

The recovery path now processes durable unprocessed D1 rows directly instead of writing
them back to the exhausted Queue. An initial bounded implementation processed 481 events
before encountering the Worker's per-invocation D1 request ceiling. The final production
version, `03a817bb-2d61-4507-bf45-6decff298715`, uses batched D1 updates for up to 500
Santa allow/unknown events after running the deterministic detector and uses the normal
alert/case persistence path for up to 50 other events. The safe classification fails
closed if it unexpectedly produces an alert.

The first final-version cron completed at `2026-08-21T08:20:24.712Z`, reducing pending
events from 4,331 to 3,830 exactly as bounded. The next two runs reduced the count to
3,330 at `2026-08-21T08:25:23.593Z` and 2,830 at
`2026-08-21T08:30:23.373Z`; processing errors remained zero throughout.
The signed macOS launch daemon continued authenticating successfully and retaining its
local spool, but its displayed pending count remained at the 100-batch reporting cap.
This is verified active drainage, not yet proof that the local or cloud backlog is empty.

Later verification proved that cloud reconciliation completed. Production reached 57,695
events with zero pending records and zero processing errors; the last retained cloud event
in that phase was processed at `2026-08-21T22:00:24.007Z`. The macOS launch daemon then
stopped retrying after intermittent DNS, TLS-handshake, and read timeouts, with last exit
code 3. It remained enabled and its four Keychain reads continued to succeed.

A non-privileged `launchctl kickstart` restored the daemon without changing credentials or
spool contents. Two consecutive automatic cycles exited successfully and each acknowledged
10 retained batches, which is the collector's configured per-cycle flush bound. D1 grew to
58,076 events, while pending and processing-error counts both remained zero; the newest
event was received at `2026-08-22T05:04:45.048Z` and processed at
`2026-08-22T05:04:59.548Z`. The local status still reported the 100-batch display cap, so
the signed collector backlog is verified draining but not yet verified empty.
A third automatic cycle acknowledged another 10 batches. D1 then reached 58,635 events;
eight newly received rows briefly appeared in flight and the normal queue consumer reduced
that count to zero by `2026-08-22T05:07:14.824Z`, again with zero processing errors.

## Verification gates

Python package:

- 72 tests passing;
- 87.83 percent coverage;
- Ruff lint and format passing;
- strict MyPy passing for 14 source files;
- Bandit zero findings;
- `controlforge-security` 0.3.0 wheel and source distribution built.

Cloudflare control plane:

- 42 tests passing in the Workers runtime;
- 88.99 percent line coverage;
- 83.90 percent statement coverage;
- 93.75 percent function coverage;
- 69.25 percent branch coverage;
- strict TypeScript and ESLint passing;
- Wrangler dry-run bundle passing before deployment.

## Secrets and access

`ADMIN_TOKEN`, `CREDENTIAL_KEK`, `AUDIT_HMAC_SECRET`, and `META_MODEL_API_KEY` are Worker
secrets. Recovery copies, the production collector HMAC credential, and the Cloudflare
Access service credential are stored in the local macOS Keychain, not the repository or
databases. Collector plaintext is returned only once; D1 contains AES-GCM ciphertext.

Cloudflare Zero Trust Free is active. The `ControlForge SOC` self-hosted application
protects `soc.chanakyachowdary.in` with a 12-hour session, a single-email administrator
allow policy, and a separate one-year Service Auth token for endpoint collectors. The
Access authorization cookie is HTTP-only and uses Cloudflare's binding-cookie protection.
The Worker validates the Access issuer and application audience, and D1 contains the matching
administrator membership. A real Chrome session completed Cloudflare authentication and
loaded 12 events, 6 alerts, and 6 cases from the production tenant. Unauthenticated custom
hostname requests redirect to Access; the old bootstrap token returns HTTP 401 after Access
is enabled. Active and high-impact response remains fail-closed because a second independent
human responder is not yet enrolled.

Production triage uses Meta Model API at the fixed `https://api.meta.ai/v1` host with
`muse-spark-1.2-contributor`. A live high-severity endpoint-control alert produced a
schema-valid assessment, assessment ID `d2b51574-6a43-4074-843a-828767a596d2`, and a
matching append-only `alert.triaged` audit record. The contributor model chose to abstain
with zero confidence and require human review; the system preserved that conservative
result. Deterministic detection and case creation do not depend on the model.

No active endpoint containment adapter is installed. The deployed endpoint agent executes
read-only diagnostics and reports unsupported active actions as failed without changing
the device. Cloudflare Access has only one independent human responder, so response
approval remains fail-closed even though the workflow and audit boundary are deployed.

## Santa endpoint integration and macOS distribution

The Python collector now has a bounded reader for North Pole Security Santa's beta JSON
event log. It uses an inode/device/offset cursor in the existing SQLite spool, resumes
complete records after restart or rotation, rejects unsafe file modes and oversized lines,
and excludes process arguments, environment variables, file descriptors, entitlements,
and Santa's raw machine identifier from cloud events. Deterministic local and Worker rules
cover denied execution (`CF-MACOS-001`), Gatekeeper override (`CF-MACOS-002`), and XProtect
activity (`CF-MACOS-003`).

During deployment validation, two
dual-authenticated, explicitly labeled deployment fixtures traversed the custom hostname
and queue:

- `santa-deploy-verify-20260818-1` was an allowed execution negative control. It was
  processed without error and produced zero alerts.
- `santa-deploy-verify-deny-20260818-1` was a denied execution positive control. It was
  processed without error, produced a high-severity `CF-MACOS-001` alert, and opened a
  case. Neither fixture is represented as real Santa telemetry from this Mac.

The final arm64 installer is `dist/macos/ControlForge-0.3.0.pkg`. After ticket stapling it
is 9,538,836 bytes and has SHA-256
`451bafdb79459559c9245df7736d8ebdde9dcb1f643e8026df8bbe9a0cfed4e5`.
`pkgutil` verifies a trusted-timestamp Developer ID Installer signature for Chanakya
Thotakura, team `YDF2TB9967`. The installed native Swift Keychain wrapper and PyInstaller
runtime both satisfy strict `codesign` verification and are signed with the matching
Developer ID Application identity.

The signed package is installed. The launch daemon reads four collector and Cloudflare
Access values from System Keychain service `com.controlforge.collector.v2` in the original
launchd process, passes one bounded exact-schema JSON object to the Python runtime over an
anonymous stdin pipe, and never places the values in command arguments, environment
variables, files, or logs. The Keychain import/read maintenance commands fail closed for
non-root users. Santa 2026.7 is installed, its system extension and Full Disk Access are
approved, its profile is active in Monitor mode, and live JSON telemetry reached D1.

Apple accepted notarization submission `97d042b3-4285-4abc-8e34-000057c211c8` on
2026-08-19. `stapler staple` and `stapler validate` both succeeded, and `pkgutil` reports
`Notarization: trusted by the Apple notary service`. `spctl --assess --type install`
returned `accepted` with source `Notarized Developer ID`. Gatekeeper enforcement is
globally disabled on this particular Mac (`override=security disabled`), so the assessment
proves the artifact's notarized policy classification but not an enforcement-on install
exercise on a separate clean Mac.

The official standard Santa 2026.7 PKG was downloaded from North Pole Security's GitHub
release. Its published and locally measured SHA-256 values both equal
`7aa84d7e099b3293bd548dc47444eea6543b39415eb5615f8a4cc22bb8b97080`.
`pkgutil` verified a trusted Developer ID Installer signature for North Pole Security,
team `ZMCG7MLDV9`, with a trusted timestamp, and reported Apple notarization. Gatekeeper
accepted the installer as Notarized Developer ID. It was installed and its required
endpoint-security and Full Disk Access approvals were completed before ControlForge live
acceptance.

## Standalone release candidate - 2026-08-22

This section is deliberately separate from the signed/notarized collector evidence above.
The newly assembled Standalone-capable release candidate is:

- `dist/macos/ControlForge-0.3.0.pkg`;
- SHA-256 `3da824c46fa8aca33a28e37c2cedaf124da788f278c4005aad82a997024712d0`;
- 14,439,169 bytes;
- signed with `Developer ID Installer: Chanakya Thotakura (YDF2TB9967)` and a trusted
  timestamp of 2026-08-22 21:43:12 UTC;
- accepted by Apple under notarization submission
  `a4e1c9b8-7f66-4138-ae23-0a1775e90db2`;
- successfully stapled and validated;
- accepted by `spctl` as `Notarized Developer ID`, with the same
  `override=security disabled` limitation on this host;
- strictly code-sign verified for `ControlForge.app`, the Keychain wrapper, and the bundled
  PyInstaller runtime;
- proven to contain the redesigned native Protection, Data & Privacy, and Help dashboard
  strings in the signed macOS 13 application binary;
- proven to expose `agent-enroll --help` from the bundled runtime;
- recursively inspected with `pyi-archive_viewer` to contain
  `controlforge.macos_response`, `controlforge.standalone.response`,
  `controlforge.standalone.identity`, and `controlforge.standalone.api`.

The preceding unsigned build remains useful as reproducibility evidence:

- `dist/macos/ControlForge-0.3.0-unsigned.pkg`;
- SHA-256 `a90263983408751d5057ff49929343e41a8924d146aab717e9aac5d2d29eb51b`;
- arm64 collector wrapper and SwiftUI local app, each with minimum macOS 13.0;
- ad-hoc application signatures only; installer signature status `no signature`;
- BOM owner/group `0:wheel` for the packaged payload;
- payload contains `collector.default.yml`, not `collector.yml`, so postinstall preserves an
  existing enrolled standalone configuration and creates the default only on first install;
- the bundled PyInstaller runtime successfully returns `agent-enroll --help`, proving the new
  endpoint enrollment module is reachable from the packaged entry point.

Both package builds emitted four `write: Permission denied` warnings from `pkgbuild` on the
macOS 27 beta host, but completed successfully; expanded BOM and payload inspection verified
the expected root/wheel metadata and files. The signed release candidate has deliberately not
been installed, upgraded, rolled back, removed, or exercised with a real System Keychain
claim on a separate clean Mac. Signing and notarization do not replace those physical tests.

The integrated source gates for this Standalone checkpoint are 197 Python tests at 88.54
percent coverage with Ruff, strict MyPy, Bandit, and package builds passing. The Cloud runtime
separately passes 97 tests with ESLint, TypeScript, and coverage gates. The non-destructive
Standalone acceptance harness passes its implemented local API, restart, case/audit, decision
replay, encrypted backup/restore, and cloud/local stateless-contract checks while correctly
reporting the clean install, physical endpoint, trusted TLS/hardware passkey, and
active-response boundaries as incomplete or unverified. Its package check can independently
verify the pinned SHA-256, Developer ID signature, Apple notarization, and stapled ticket.

### Pre-signing lifecycle checkpoint

Subsequent source work added fail-closed endpoint activation/uninstall and root launchd
supervision for the standalone appliance. At this intermediate checkpoint, the newest locally
built artifact was intentionally unsigned and was not release evidence:

- `dist/macos/ControlForge-0.3.0-unsigned.pkg`;
- 14,437,112 bytes;
- SHA-256 `c0a061ab44d2dd30023b620b3c5f679a85e729b30432f54efa182a4e59ee45b0`;
- embedded runtime exposes resumable `agent-activate` and confirmation-gated
  `agent-uninstall`;
- uninstall preserves telemetry spool/logs unless separately requested, releases only
  ControlForge-owned PF state, deletes the fixed Keychain pairs, and removes only explicit
  package paths;
- standalone source exposes root-only `service-install`, `service-status`, and
  data-preserving `service-uninstall`, with TLS/schema/secret preflight and rollback.

The current full repository gate passes 272 tests at 87.74 percent coverage with Ruff,
strict MyPy, Bandit zero findings, and wheel/source builds. The Cloud gate passes 111 tests
with ESLint, strict TypeScript, and 88.54 percent line coverage. The acceptance harness passes
all implemented local checks and still reports `release_ready=false`. At this checkpoint no
current-source package had been signed, notarized, installed, booted, or physically exercised.
This unsigned build also
emitted the same four unexplained non-fatal `write: Permission denied` lines before `pkgbuild`;
payload and signature-boundary inspection passed, but the warning remains an open build-host
diagnostic.

## Flagship admin and canonical detection production cutover - 2026-08-22

Before the cutover, D1 was exported to
`/tmp/controlforge-production-pre-dashboard-20260822.sql` with owner-only mode, size 111 MB,
and SHA-256 `86f1517a6a5d6e13ec7f5ebbfbf47643894c5e8a9d11632cf5987c58160ad3c2`.
The preflight recorded 101,334 events, 2,260 alerts, 2,260 cases, zero pending events,
zero processing errors, and zero approved/dispatched actions. The export contains production
data and remains outside the repository.

D1 migrations `0002_device_identity.sql` through `0006_case_ownership.sql` were applied
successfully. Before Worker cutover, the one active legacy credential was bound to the exact
configured endpoint `nw55074-controlforge` and an active device row was created; no device
identity was guessed. `wrangler d1 migrations list --remote` then reported no pending migration.

Worker version `ee0bdfdf-1cf1-4f62-aedd-af77487cb51a` was deployed to the custom domain and
Workers development hostname. Post-deploy evidence:

- unauthenticated custom-domain `/dashboard` returns the expected Cloudflare Access 302;
- the Workers hostname `/health` returns version 0.3.0 and production status `ok`;
- the installed launchd collector completed a live 100-event cycle with one delivered batch,
  zero pending batches, and zero action results;
- D1 updated the bound credential and device `last_seen_at` to 2026-08-22T22:35:24Z;
- the queue converged to zero pending events and zero processing errors;
- new canonical alerts store rule version/digest, detector version, evidence, and the explicit
  legacy fingerprint label;
- two recurring new control alerts linked into one semantic open case;
- signed-in Chrome rendered the membership-derived `ControlForge Production` workspace with
  five investigation groups over 2,262 preserved open case rows, one fresh active endpoint,
  zero processing errors, a bounded 25-row recent-alert stream, and no browser console
  warnings/errors.

The prior raw-row dashboard was therefore replaced in production rather than merely previewed
locally. Historical case rows and IDs were preserved; grouping is a read projection plus a
new-case semantic key, not a destructive rewrite.

## Replay, fingerprint, rotation, and current package checkpoint - 2026-08-24

Before applying the replay/fingerprint migration, production D1 was exported to
`/tmp/controlforge-production-pre-replay-fingerprint-20260824.sql` with owner-only mode. The
export is 140,054,548 bytes and has SHA-256
`e6684638168b40f9d74628afa560355881ead0babb6570c07e4079fdff4a219a`. It contains production
data and remains outside the repository. Preflight queries found zero duplicate semantic
occurrence groups and zero duplicate rows, allowing the additive uniqueness boundary to be
created without rewriting historical alert or case identifiers.

D1 migration `0007_alert_replay_and_fingerprint.sql` applied successfully. Worker version
`1ef4fb8f-5ec5-4101-b3a3-04eb51f4313b` was then deployed. Post-deploy evidence:

- the Workers hostname `/health` returned production status `ok` and version 0.3.0;
- the custom dashboard remained protected by the expected Cloudflare Access redirect;
- migration listing reported no pending migrations;
- new alerts were observed with `alert-fingerprint-v1`, rule version/digest, detector version,
  source digest, matched evidence, and immutable detector snapshot;
- legacy alerts retained their prior IDs and explicit `legacy-cloud-v0` provenance;
- the queue drained from the bounded deployment/export backlog to zero and processing errors
  remained zero.

The deployed route supports original/current replay for new snapshot-bearing alerts and records
append-only replay evaluations. Legacy snapshotless alerts report original replay unavailable.
Authenticated browser replay was not re-exercised in this checkpoint because the existing
Cloudflare Access session had expired; the route, authorization, snapshot verification, and
replay persistence are covered by the 115-test Cloud gate rather than claimed as a fresh live
browser action.

The current-source macOS release candidate is:

- `dist/macos/ControlForge-0.3.0.pkg`;
- 14,526,455 bytes;
- SHA-256 `a80cd724a6202f773074a002e534f78bf9b17c0fb3374606421017d929eacd0a`;
- Developer ID Installer-signed with trusted timestamp 2026-08-24 06:45:29 UTC;
- accepted by Apple under notarization submission
  `2ff3b42c-d5a3-44a0-ba09-8c8be2187dfe`;
- successfully stapled and validated;
- accepted by `spctl` as `Notarized Developer ID`;
- strictly code-sign verified for the SwiftUI app, Keychain wrapper, and bundled runtime;
- inspected to contain the standalone appliance/service launcher, endpoint activation/uninstall,
  PF response adapter, endpoint-bound credential-rotation modules, local out-of-band
  containment status/release commands, native status-contract v2, and the exact ten canonical
  YAML rules at the stable installed rules path with mode `0644`;
- native status-contract v2 reports only not-configured, released, isolated with bounded expiry,
  or needs-attention posture and excludes action IDs, rationale, approvals, PF tokens, addresses,
  commands, and evidence. The app remains backward-compatible with strict v1 snapshots.

The package was deliberately not installed over the active collector. Clean-Mac installation,
System Keychain ACL/swap, reboot/upgrade/rollback/removal, trusted-TLS hardware-passkey, and
physical two-person isolate/release exercises remain release gates. The non-destructive
acceptance report at `/tmp/controlforge-standalone-acceptance-20260824.json` records 18 passing
implemented checks and five explicit unverified physical/environment boundaries. The complete
current-source gate passes 297 Python tests at 87.53 percent coverage, and the Cloud gate passes
115 tests at 88.94 percent line coverage.

## Cloudflare marketing site and signed public pilot - 2026-08-30

The marketing site was deployed as Cloudflare Worker `controlforge-marketing` at
`https://controlforge.chanakyachowdary.in`, version
`cb91880c-1c4f-41b6-acc8-19ed031487f3`. Live checks returned HTTP 200 for `/`,
`/download`, `/security`, and `/docs`, and the custom missing route returned 404.
The production Open Graph image resolves from the same custom origin. Lighthouse
accessibility scoring was 100 for both the homepage and download page; the narrow
layout had no horizontal document overflow, the first keyboard focus was the skip
link, and main, banner, and content-info landmarks were present.

Before signing, the exact clean commit `fa34b23cb7b4bce34009bd6d73733548d1deb1b1`
passed the complete Python gate with 557 tests and 88.94 percent coverage, Bandit
with zero findings, strict MyPy, Ruff and package builds. The Cloud gate passed 115
tests with 88.94 percent line coverage. The website passed ESLint, its production
build and an npm audit with zero known vulnerabilities.

The downloadable staging pilot is 14,774,363 bytes with SHA-256
`e96c42c7865ffe68e1010a1926560089a54342e1745137e23c0e5a7b89ad51be`.
Its manifest records `source_dirty=false`, the exact commit above, `arm64`, macOS
13.0 or newer, staging channel, and `admin-staging.chanakyachowdary.in:443`. Apple
accepted notarization submission `db9238ff-d8c5-453e-afa4-d67d97db9b8a`; stapling,
ticket validation, trusted Developer ID Installer signature and Gatekeeper assessment
passed. A fresh HTTPS download from the custom domain reproduced the exact byte size
and SHA-256 and independently passed `pkgutil`, `stapler`, and `spctl`.

This establishes a publicly downloadable signed **pilot**, not production or general
availability. The current Mac already contains an older ControlForge receipt and
payload, so the physical preinstall verifier correctly failed those two clean-host
checks. Clean-Mac install/reboot/upgrade/rollback/uninstall evidence, dedicated
always-on account-service architecture, fleet scale and service objectives remain open.
