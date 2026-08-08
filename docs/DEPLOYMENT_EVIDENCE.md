# ControlForge 0.3 deployment evidence

Verified 2026-08-18 in the `Chanakya Chowdary` Cloudflare account.

## Runtime

- Worker: `controlforge-soc`
- Custom hostname: `https://soc.chanakyachowdary.in`
- Workers.dev fallback: `https://controlforge-soc.chanakya-chowdary.workers.dev`
- Deployed version: `3da8e811-3df0-42bc-9a71-697897258d2d`
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

## Verification gates

Python package:

- 72 tests passing;
- 87.83 percent coverage;
- Ruff lint and format passing;
- strict MyPy passing for 14 source files;
- Bandit zero findings;
- `controlforge-security` 0.3.0 wheel and source distribution built.

Cloudflare control plane:

- 40 tests passing in the Workers runtime;
- 87.81 percent line coverage;
- 82.90 percent statement coverage;
- 93.33 percent function coverage;
- 67.93 percent branch coverage;
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
