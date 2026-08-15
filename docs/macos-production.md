# macOS production deployment

The current 0.3 collector and local user application package supports Apple Silicon
(`arm64`) Macs running macOS 13 or later. A universal Intel/Apple Silicon package is not
yet built or validated. The package builder sets an explicit macOS 13 deployment target
for both Swift executables and validates the PyInstaller runtime separately.

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
