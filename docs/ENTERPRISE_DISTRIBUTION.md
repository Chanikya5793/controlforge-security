# Enterprise distribution and release channels

ControlForge uses a signed Developer ID installer package for managed macOS
distribution. The Mac App Store is not the primary enterprise channel because
the product includes a root launch daemon, System Keychain integration and Santa
deployment prerequisites that an organization normally manages through MDM.

## Release channels

| Channel | Purpose | Required identity | Distribution claim |
|---|---|---|---|
| `development` | Local compilation and contract testing | Exact commit and dirty state | No public distribution claim |
| `staging` | Trusted-TLS account and fleet acceptance | Fixed staging host, exact commit and dirty state | Signed pilot only when Apple checks pass |
| `production` | Customer or organization deployment | Clean exact `vVERSION` tag and explicit production host | Signed/notarized artifact eligible for acceptance |

The build refuses to label a package `production` unless all of these conditions
are true:

1. The Git worktree and index are clean, including untracked files.
2. `HEAD` has the exact tag `vVERSION`.
3. A fixed account-server host is supplied twice through the normal and explicit
   production variables, and the values match.
4. Developer ID Application and Installer identities are available.
5. A working Apple notary profile is supplied.

These are necessary release-integrity gates. They do not prove physical
installation, server availability or customer readiness.

## Enterprise artifact set

A release handoff consists of:

- `ControlForge-VERSION.pkg`, the immutable signed/notarized installer;
- `ControlForge-VERSION.release.json`, the public package digest and provenance;
- release notes describing security and migration behavior;
- redacted preinstall, installed, running, reboot, upgrade and uninstall
  acceptance reports from a clean supported Mac;
- the organization-specific Santa system-extension and TCC configuration
  profiles reviewed for the chosen MDM;
- a rollback package and the documented data-preservation contract.

The release manifest is not a replacement for the Developer ID signature. It
prevents a valid package from being accidentally associated with the wrong
version, source state, account destination or release channel. Administrators
must verify both the manifest digest and Apple's signature/notarization state.

## MDM deployment sequence

1. Publish the official Santa package and organization-reviewed profiles through
   Jamf, Kandji, Mosyle, Intune or another capable macOS MDM.
2. Preapprove the required Santa system extension and Full Disk Access policy.
3. Deploy the manifest-pinned ControlForge PKG to a pilot smart group.
4. Confirm the package receipt while the ControlForge launch daemon remains
   disabled and no credentials exist.
5. Provision endpoint accounts and use the OS-authorized ControlForge enrollment
   handoff on each Mac. Enrollment creates a unique device identity locally; the
   PKG never ships a shared credential.
6. Verify a signed check-in, deterministic case evidence and the redacted native
   status before expanding the smart group.
7. Exercise upgrade, rollback and uninstall against the same device identity and
   retain the acceptance reports.

Do not silently retarget an enrolled Mac by publishing a package with a different
account host. Package upgrades preserve the installed profile and credentials;
moving a device between networks is an explicit administrative workflow.

## Control-plane gate

An enterprise PKG is useful only when its control plane is independently ready.
The current `admin-staging.chanakyachowdary.in` appliance runs on a development
Mac through Cloudflare Tunnel. It proves the trusted-TLS and passkey integration,
but it is not an availability architecture.

Before customer distribution, deploy the exact tagged runtime to a dedicated
always-on environment with monitored health, certificate expiry, capacity,
encrypted backups, restore exercises and incident alerts. Decide explicitly
whether customers receive dedicated appliances or a hosted multi-tenant service.
The hosted option additionally needs tenant sharding, durable external audit
anchoring, SSO/SCIM, retention and data-residency policy, service objectives and
support operations. A Workers Paid subscription alone does not supply those
controls.

## Current boundary

The signed and notarized `0.4.0-rc3` staging candidate is suitable for controlled
acceptance. Production distribution remains blocked by exact-source commit/tag
provenance, the live multi-network ceremony, clean-Mac lifecycle evidence and a
dedicated production control plane. Those gates must remain separate in release
notes and customer claims.
