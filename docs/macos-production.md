# macOS production deployment

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

## Organization deployment

MDM can preapprove the system extension and TCC access. The included
`com.controlforge.santa-system-extension.mobileconfig` is an MDM template, not a
claim that this Mac is enrolled in MDM. Generate and verify a TCC profile from
Santa's current official documentation for the chosen MDM. The optional Santa
network extension is not used because it requires a paid Workshop subscription.

Do not switch to Lockdown mode until the monitor-mode execution inventory has
been reviewed, explicit allow rules are deployed, and recovery has been tested.
