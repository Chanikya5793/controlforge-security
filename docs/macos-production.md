# macOS production deployment

The current `0.5.0` collector and local user application source targets Apple Silicon
(`arm64`) Macs running macOS 13 or later. A universal Intel/Apple Silicon package is not
yet built or validated. The package builder sets an explicit macOS 13 deployment target
for both Swift executables and validates the PyInstaller runtime separately. No `0.5.0`
package has been built or accepted yet; the latest downloadable signed pilot remains the
historical `0.4.0` artifact described below.

ControlForge uses the open-source North Pole Security Santa system extension as
its macOS endpoint telemetry source. Santa is installed from its official,
signed package; ControlForge does not rebuild or re-sign Santa.

## Safety posture

- Santa starts in **Monitor** mode (`ClientMode=1`) so unknown programs remain
  allowed while telemetry and false-positive behavior are validated.
- Santa's bad-signature protection remains disabled during the initial
  monitor-mode rollout, so the profile does not silently introduce a blocking
  exception before an allow policy and recovery path have been tested.
- The collector ingests only execution, file-access, Gatekeeper override,
  launch-item, TCC, and XProtect records.
- Process arguments, environment variables, file descriptors, entitlements,
  and Santa's raw machine identifier are excluded from cloud events.
- The collector launch daemon ships disabled. It is enabled only after Santa,
  System-keychain credentials, and a test delivery are verified.

### Control-plane outage behavior

The launch daemon still wakes every 60 seconds so local controls, Santa cursors and
containment reconciliation remain timely. Upload and action polling have separate durable
retry circuits in the existing SQLite spool. A failed operation starts at a 60-second delay,
doubles up to one hour and applies bounded deterministic per-device jitter. A delivery outage
does not prevent action polling, and an action-polling outage does not discard or stop local
collection. Provider response bodies and socket details do not enter the spool or redacted
status file.

Each wake drains a bounded number of batches. The library default remains 10 and the value is
hard-capped at 100; the packaged hosted profile currently selects 25 to recover a retained
backlog without an uncapped burst. At a 60-second schedule that permits at most 25 ingest
requests per minute. Return the profile to 10 after recovery when lower steady-state request
volume is preferred. Increasing this bound changes drain speed, not the number of retained
events that ultimately require ingestion.

All accepted Santa events remain durably queued until the server acknowledges them. To avoid
manufacturing an unbounded stream of identical health events during an outage, an unchanged
endpoint-control snapshot has at most one pending copy. A real control-state transition is
queued immediately, even while another snapshot is pending. After acknowledgement, an
unchanged snapshot becomes due again after one hour. The retry and snapshot tables are created
in place when an existing spool is opened; queued telemetry is not migrated or deleted.

The local status distinguishes an attempted upload failure from a retained backlog whose retry
circuit is waiting. It records `delivery` or `action_polling` as the failed stage while keeping
the bounded pending count and lower-bound flag. Control-plane availability failures are isolated
from the collection cycle, so operators should use the redacted status rather than a launchd
process exit alone to decide whether the endpoint checked in.

## Single-Mac installation order

1. Install the official Santa PKG.
2. Approve `com.northpolesec.santa.daemon` under **System Settings > General >
   Login Items & Extensions > Endpoint Security Extensions**.
3. Grant Santa Full Disk Access under **Privacy & Security > Full Disk Access**.
4. Install `deployment/macos/com.controlforge.santa.mobileconfig` and verify its
   settings before approving the profile.
5. Verify `santactl status`, `santactl doctor`, and one JSON record in
   `/var/db/santa/santa.log`.
6. Install the Developer ID-signed ControlForge PKG after notarization and ticket stapling
   for public distribution. The current release artifact is notarized and stapled; its
   enforcement-on installation should still be exercised on a separate clean Mac.
7. Run `deployment/macos/provision-system-keychain.sh`. It prompts for each
   collector and Cloudflare Access credential without placing values in files or
   shell history.
8. Run one collector cycle manually, inspect the cloud event/case/audit record,
   then enable and bootstrap `com.controlforge.agent` with `launchctl`.

For a standalone enrollment, use the packaged root-only `agent-enroll` command instead of
manually provisioning values. It claims a bound grant, installs the standalone definition,
stores the fixed Keychain pairs, proves one signed check-in, and only then activates launchd.
If activation fails after claim, rerun `agent-activate`; do not claim a second grant. Removal is
confirmation-gated through `agent-uninstall` and preserves spool/logs by default.

For out-of-band containment recovery, use a local root console. The status command exposes only
the redacted enum and bounded expiry. The release command disables the collector before releasing
only ControlForge-owned PF state so an approved action cannot immediately reapply while the
operator is offline:

```bash
sudo /Library/ControlForge/bin/controlforge agent-containment-status
sudo /Library/ControlForge/bin/controlforge agent-containment-release \
  --confirm RELEASE-CONTROLFORGE-CONTAINMENT
```

Resolve or allow the server action to expire before running `agent-activate` again. Do not replace
this command with a global PF flush.

The appliance `service-status` report exposes certificate identity, validity bounds, bounded
days until expiry, and `valid` or `renewal_due`. Health degrades during the final 30 days without
stopping service. Replace the certificate and matching `0600` private key atomically at their
configured paths, then restart and rerun `service-status`; browser/OS trust must still be verified
from an intended admin device.

## Building the ControlForge PKG

Install the packaging dependency and build:

```bash
python -m pip install -e '.[macos-dist]'
deployment/macos/build-pkg.sh
```

Without signing variables, the script intentionally produces an unsigned local
test package. Public distribution requires these existing Keychain identities:

```bash
export DEVELOPER_ID_APPLICATION='Developer ID Application: Organization (TEAMID)'
export DEVELOPER_ID_INSTALLER='Developer ID Installer: Organization (TEAMID)'
export NOTARY_PROFILE='controlforge-notary'
deployment/macos/build-pkg.sh
```

The builder uses `.venv/bin/python` by default. Set `CONTROLFORGE_PYTHON` only to
another explicit project interpreter containing both the application and
`macos-dist` dependencies; it never falls back to Apple's bare system Python.

Every build emits two different provenance records:

- `/Library/ControlForge/installer/release-build.json` inside the PKG records
  version, release channel, exact Git commit, dirty state, architecture, minimum
  macOS and the non-secret account destination.
- `ControlForge-VERSION.release.json` beside the PKG binds that same identity to
  the package filename, byte size and SHA-256 plus the observed signing and
  notarization state.

The native app reads only the root-owned, non-writable embedded record and
shows the app version, release channel and short source revision in **Help &
Diagnostics**. Invalid, oversized, symlinked or extended metadata is ignored.
This lets a user distinguish a development copy from staging or production
without exposing credentials or tenant data.

Verify the pair before physical acceptance:

```bash
python -m controlforge.release_manifest verify \
  --manifest /path/to/ControlForge-0.5.0.release.json \
  --package /path/to/ControlForge-0.5.0.pkg

python tools/verify_macos_physical_acceptance.py \
  --phase preinstall \
  --package /path/to/ControlForge-0.5.0.pkg \
  --release-manifest /path/to/ControlForge-0.5.0.release.json
```

Use `CONTROLFORGE_RELEASE_CHANNEL=staging` for account-enabled acceptance.
`production` is fail-closed: it requires a clean tree, exact `vVERSION` tag,
matching `CONTROLFORGE_ACCOUNT_SERVER_HOST` and
`CONTROLFORGE_PRODUCTION_ACCOUNT_SERVER_HOST`, both Developer ID identities and
the notary profile. This prevents a staging destination or uncommitted source
from being labeled as a production release.

### Native guidance and status v3 (current source, not release evidence)

The current collector writes `controlforge-agent-status-v3`. Its controls object
requires `evaluated`, `total`, `failed`, `degraded`, `missing`, and `not_running`.
Counts come from the actual structured control report, not parsed evidence text.
Failed plus degraded cannot exceed total; missing plus stopped cannot exceed
failed. No component names, paths, raw events or recommended commands enter the
user-readable snapshot. The current native app accepts v1/v2 as legacy summaries
without treating absent degraded details as zero.

Native guidance separates component health, activity collection, report delivery
and network restriction. Fresh successful delivery cannot hide a degraded check,
unattempted delivery cannot imply a check-in, stale cards are neutral/historical,
and a scheduled restriction release is not reported as completed without a newer
state. Account and Help buttons only navigate; Refresh rereads the saved report
and does not scan, upload, restart services or change protection settings.

Upgrade the collector and native application together in a newly built installer.
An old app safely rejects v3 until upgraded; the new app can read an older
collector's v1/v2 report with explicit limitations. The current-source physical
acceptance verifier requires v3. The earlier signed/notarized v2 package is
historical evidence, not proof of this update. A fresh signed artifact and real
clean-Mac acceptance remain required.

### Account-enabled installers

For the new standalone account workflow, build with the actual trusted HTTPS host
serving the account API. Do not infer this address from a person's username domain.
The following host is an example, not a live ControlForge service:

```bash
CONTROLFORGE_ACCOUNT_SERVER_HOST=accounts.example.com \
CONTROLFORGE_ACCOUNT_SERVER_PORT=443 \
CONTROLFORGE_RELEASE_CHANNEL=staging \
CONTROLFORGE_BUILD_LABEL=account-candidate \
deployment/macos/build-pkg.sh
```

`CONTROLFORGE_BUILD_LABEL` puts the output in its own subdirectory under
`dist/macos` so a test candidate does not replace an existing release artifact.
Use the same Developer ID and notarization variables above for a distributable
candidate; a successful unsigned build is not a release acceptance result.

The PKG carries a non-secret `account-server.default.json`. Post-installation calls
the fixed root helper to create `/Library/ControlForge/status/account-server.json`
only on a fresh unenrolled Mac, with a new device ID generated on that Mac. Users
then open ControlForge, sign in with the credentials from their network admin,
change the initial password and explicitly connect the device. They do not type a
server URL or run a configuration command. Santa installation/OS approvals and the
Mac administrator's enrollment authorization remain separate prerequisites.

An upgrade preserves the live profile and collector, even if the new package has a
different server default. Partially populated Keychain accounts are treated as
existing state, not a fresh Mac. An unreadable Keychain or orphaned membership fails
setup without creating another identity. The installer does not start the collector,
claim a grant, enable response or enroll Santa automatically.

Without the host variable, the builder produces a manual-setup package. It does not
create an account profile or inspect Keychain. The explicit
`agent-configure-account-server` command remains available to an administrator for
a fresh installation. Existing-device migration requires a separate workflow.

Installer scripts target the running startup volume only. They refuse symlinked,
non-root-owned or group/other-writable files inside an existing managed installation
before installing the payload. They do not silently repair or take ownership of an
unmanaged installation. The live collector configuration, profile and membership
receipt are never shipped in the package payload.

Current local evidence for this workflow, including the synthetic unsigned candidate,
is recorded in [the multi-network contract](MULTI_NETWORK_PRODUCT.md). The historical
signed artifact below does **not** contain these new account-installer changes.

### Signing and historical release evidence

The build signs the native Keychain wrapper and bundled runtime with the hardened runtime,
signs the installer,
submits it with `notarytool`, staples the accepted ticket, and verifies the final
package with Gatekeeper. Apple Development identities are suitable for local
development but do not replace the two Developer ID identities for public
distribution outside the Mac App Store.

The current 2026-08-24 release candidate is `dist/macos/ControlForge-0.3.0.pkg`, 14,526,455
bytes, SHA-256 `a80cd724a6202f773074a002e534f78bf9b17c0fb3374606421017d929eacd0a`.
Apple accepted notarization submission `2ff3b42c-d5a3-44a0-ba09-8c8be2187dfe`; stapling,
Gatekeeper assessment, strict code-sign checks, expanded-payload inspection, and the bundled
standalone launcher check passed. The payload includes the exact ten canonical detection rules
at `/Library/ControlForge/rules` with mode `0644`, so the installed launch daemon does not depend
on a PyInstaller extraction directory. The signed native app includes redacted status-contract v2
with enum-only containment posture and bounded expiry while accepting strict legacy v1 status.
It remains uninstalled pending the separate clean-Mac acceptance matrix; signing and notarization
do not prove System Keychain ACLs, launchd/reboot behavior, upgrade/rollback, or removal.

## Clean-Mac release exercise

Use the read-only physical verifier before installation and after every lifecycle boundary.
It emits redacted JSON and never reads Keychain secret values or telemetry rows:

```bash
source .venv/bin/activate
python tools/verify_macos_physical_acceptance.py \
  --phase preinstall \
  --package dist/macos/ControlForge-0.3.0.pkg \
  --package-sha256 a80cd724a6202f773074a002e534f78bf9b17c0fb3374606421017d929eacd0a \
  --output /tmp/controlforge-preinstall.json
```

Then retain `installed`, `running`, post-reboot `running`, and `uninstalled` reports using
the same tool. The `installed` report must be captured before enrollment because the package
intentionally ships launchd disabled. The normal standalone `agent-enroll` command performs
claim, first signed check-in, and activation as one workflow; use `agent-activate` only to
resume a post-claim local failure. The transitional `enrolled` verifier phase exists for that
recovery case.

Alongside those reports, retain the real trusted-TLS URL and hardware-passkey ceremony,
System Keychain ACL inspection, Santa signal identifiers, admin-workbench case evidence,
upgrade and rollback results, network-loss recovery, explicit endpoint and appliance-service
uninstall results, and the two-human PF isolate/explicit-release/automatic-release exercise.
The physical response exercise must additionally invoke the local containment status/release
commands from a console, prove that the collector remains disabled, then explicitly reactivate it
only after the pending action is resolved.
Re-run `running` after reboot and after upgrade; compare the stable hashed machine fingerprint
and confirm each report has a fresh timestamp and a completed collector cycle.

## Organization deployment

MDM can preapprove the system extension and TCC access. The included
`com.controlforge.santa-system-extension.mobileconfig` is an MDM template, not a
claim that this Mac is enrolled in MDM. Generate and verify a TCC profile from
Santa's current official documentation for the chosen MDM. The optional Santa
network extension is not used because it requires a paid Workshop subscription.

Do not switch to Lockdown mode until the monitor-mode execution inventory has
been reviewed, explicit allow rules are deployed, and recovery has been tested.

## 0.5.0 source candidate

The source release line now reports `0.5.0` across the Python package, cloud runtime
metadata, and macOS app template. It includes the collector outage behavior documented
above and the deployed cloud admission, capacity, direct-D1 recovery, selective-retention,
and atomic-audit controls recorded in `DEPLOYMENT_EVIDENCE.md`.

This is release metadata and verified source, not a distributable package. Before the
version can replace the public `0.4.0` pilot, build it from a reviewed clean commit with
the staging account host, run the complete gates, sign both executables and the installer,
obtain and staple a new Apple notarization ticket, verify the external manifest and digest,
download the published bytes again, and complete the clean-Mac lifecycle exercise. Do not
reuse any `0.4.0` digest, notarization submission, or physical-acceptance result for `0.5.0`.

## Signed 0.4.0 staging candidate

The multi-network/account release line is now `0.4.0`. The current staging
candidate is
`dist/macos/staging-20260830-0.4.0-rc3/ControlForge-0.4.0.pkg`, SHA-256
`c5d6c1ebcaca4401fe9e140abd59a26c648e7e34d130e44308f5a1149dd22813`.
Apple accepted notarization submission `0b780c68-9ef2-428c-8cb2-e4c39eae2908`;
stapling, ticket validation, Gatekeeper assessment, strict executable signatures
and both runtime help smokes passed. The embedded and external manifests match,
and the package pins `admin-staging.chanakyachowdary.in` as an account-enabled
**staging** destination.

The manifest deliberately records `source_dirty=true` at commit
`440f3cbfb91b51f19ae7598e4f746f6b6105460f`. This makes the candidate suitable
for controlled staging, not customer distribution. A preinstall verifier run on
this development Mac passed package digest/signing/notarization checks and failed
the clean-host boundary because an older collector receipt and payload are
already present. That is correct fail-closed behavior, not clean-Mac proof.

## Downloadable 0.4.0 public pilot

The public pilot replaces the dirty-source rc3 artifact for download purposes. It
was built from clean commit `fa34b23cb7b4bce34009bd6d73733548d1deb1b1` with
`source_dirty=false` and the fixed staging account host
`admin-staging.chanakyachowdary.in:443`:

- package: `dist/macos/public-pilot-20260830-fa34b23/ControlForge-0.4.0.pkg`;
- size: 14,774,363 bytes;
- SHA-256: `e96c42c7865ffe68e1010a1926560089a54342e1745137e23c0e5a7b89ad51be`;
- Developer ID Installer trusted timestamp: 2026-08-31 00:55:07 UTC;
- Apple notarization submission: `db9238ff-d8c5-453e-afa4-d67d97db9b8a`, accepted;
- stapler validation and Gatekeeper `Notarized Developer ID` assessment: passed;
- external manifest verification against the exact package: passed.

The package and evidence are published at
`https://controlforge.chanakyachowdary.in/download`. A fresh download was measured
at the same size and SHA-256 and independently passed `pkgutil`, `stapler`, and
`spctl` checks. This is public availability of a signed **staging pilot**, not a
general-availability production release. The development Mac is not a clean host;
its preinstall verifier correctly failed the existing-receipt and existing-payload
checks. Clean-Mac lifecycle acceptance and a dedicated production account service
remain release gates.
