# Multi-network product contract

Status: implementation in progress. This is not a deployment or release claim.

## Product model

ControlForge has a platform owner, network administrators, and endpoint users.
The platform owner can create networks and work within any network. Network
administrators see and manage only their assigned network. Endpoint users see
their own Mac's status and account setup, never the investigation console.
Existing analyst and responder roles remain available inside a network.

The cloud-independent appliance is the first implementation target. The existing
hosted Worker is unchanged while we build and verify the new contract; it must
not silently expose an independent, incompatible account system. Cloud parity,
DNS/TLS provisioning, and signed native enrollment are separate acceptance gates.

## Identity and authorization

- Fresh console/passkey bootstrap designates one platform owner. Upgraded
  appliances do not promote existing admins automatically. An explicit local
  owner designation is required for those installations.
- Owner authority is recorded separately from the existing `admin` role. It is
  never inferred from an email address, a request header, or a tenant name.
- Network selection is only a request to the server. The authenticated owner
  may select any active network; everyone else must remain in their own network.
- Owner membership projections preserve the same human ID across networks for
  audit attribution and independent-response approval checks. They contain no
  passkeys or recovery credentials and are not additional login identities.
- Administrators use passkeys. Account passwords are for endpoint users, whose
  sessions cannot authenticate to any administrative API.
- Network login namespaces are exact, immutable, unique domains under an
  operator-configured base domain. `alex@acme.example.com` is an internal username;
  no mailbox, MX record, or email provider is required. DNS routing is a separate
  operation and must not be shown as active just because a namespace was saved.

## Management and upgrade contract

- Existing appliances designate a single existing active passkey administrator as
  owner through an explicit **offline local CLI** ceremony. It requires database
  ownership, the runtime operation lock, exact tenant/user IDs and confirmation.
  It is not a public HTTP bootstrap route, owner transfer, or automatic promotion.
  Conflicting existing identities fail atomically; no passkeys are copied into
  owner projections. The newly designated owner signs in again.
- The owner can adopt a missing immutable login namespace on an existing network,
  rename its display label, or pause/resume it. Login slugs and existing namespaces
  are not renamed. Changes use an expected revision to reject stale dashboard edits.
  The owner's home network cannot be paused, preventing administrative lockout.
- Pausing revokes that network's human/endpoint sessions, outstanding invitations,
  enrollment grants and undelivered response approvals. Existing data and collector
  credentials are preserved. Delivery and sign-in stop; local collectors may spool,
  and already-stored activity may still be processed. Resume does not resurrect old
  sessions or grants. Already-dispatched restrictions are not undone by a pause.
  A request authenticated before the pause may finish; pausing is not a distributed
  stop-the-world barrier and does not recall an already-delivered command.
- Network admins manage only their own endpoint accounts and human team memberships.
  Disabling/demoting a human revokes sessions, their outstanding invitations/grants,
  and undelivered response approvals involving them. Owner identities/projections
  and self-disable/self-demotion are protected. Changing a network role never grants
  platform ownership. Re-enabling requires a fresh sign-in.
- Disabling an endpoint account revokes its sessions/grants and closes pending reset
  requests, but does not silently revoke its collector. The UI must state this
  distinction before confirmation. Historical account and audit records are retained.
- Management authorization is rechecked inside the write transaction. Actor/target,
  prior/new state, and bounded revocation counts are audit-recorded without tokens.
  Response proposals, approvals, and rejections also recheck the session, active
  network, role and owner projection inside the write transaction. A captured old
  principal cannot create new response authority after demotion or suspension.

## Password and enrollment lifecycle

- Admins create endpoint accounts. The initial random password is displayed once,
  expires after seven days, and must be changed before enrollment.
- Passwords use salted, purpose-peppered scrypt (N=32768, r=8, p=3). Password input
  is bounded; hashing concurrency and public login/reset rates are bounded.
- First-login sessions can only view their account, change the initial password,
  or sign out. A domain match alone cannot mint a collector credential.
- Changed passwords must be 15–128 characters; no arbitrary composition rules or
  periodic forced changes. Never log password bodies, hashes, or bearer tokens.
- Reset requests are deduplicated and always return the same public response,
  whether or not the username exists. Requests never deliver a password to an
  unauthenticated requester.
- An admin verifies the person's identity separately, then issues a new random
  password, shown once to that admin. They deliver it directly to the person.
  No email server is needed. Previously completed first-login setup stays complete;
  an account that has never completed first login must still do so.
- Password changes and resets revoke all account sessions and unclaimed account
  enrollment grants atomically. They do not silently disable already-enrolled
  security collectors. Device revocation is a separate audited admin operation.
- Enrollment grants must be bound to the authenticated account, its network,
  password revision, and exact device ID, and use the existing privileged
  Keychain/configuration installation boundary. No endpoint-supplied tenant ID.

## Experience acceptance

### Native account and privileged handoff contract

The Mac app reads a small root-owned `account-server.json` beside the redacted
status snapshot. The operator configures its fixed HTTPS host/port; the app never
derives a destination URL from an entered username. It uses an ephemeral HTTP
session, default certificate verification, no redirects, bounded responses, and
holds the short-lived endpoint session only in memory. Sign-out clears that
session, not the device's separate collector credential.

Connecting a fresh Mac creates a five-minute account/device-bound grant. The app
writes a mode-0600, single-link request in `/private/var/tmp`, then requests macOS
administrator authorization to run one fixed installed helper command. Only the
numeric caller UID and SHA-256 of the request appear in command arguments; the
password, session bearer, and grant do not. The root helper validates file ownership,
type, mode, size, age and digest with no symlink traversal, reads the root-owned
server profile, and refuses to overwrite an existing collector credential.

The helper uses the existing encrypted device-credential enrollment, System
Keychain, configuration and activation boundaries. A version-opted-in enrollment
response supplies the account/network identity from server records, not the local
request. A root-owned non-secret membership receipt distinguishes credential
installation from verified first check-in. If activation fails after credential
storage, a separate fixed `agent-finish-account-enrollment` operation checks the
local user, profile and collector binding before finishing setup without
claiming another credential. Existing managed Macs are never silently migrated.

This is an enrollment-only privilege elevation, not a new remote command or
containment interface. OS authorization and actual clean-Mac activation remain
physical acceptance gates; an in-process runner does not prove them.

### Installer provisioning contract

An account-enabled PKG carries a versioned server host/port default in its payload.
These account defaults never contain a device ID, user account, enrollment grant
or credential; the existing manual collector configuration template is separate.
After installation the fixed root helper validates these defaults and either creates
a fresh locally generated device ID and public account profile, or preserves the
existing profile/collector. A changed installer server never silently retargets a Mac.
An existing membership without its profile requires explicit operator repair.

The credential-presence check uses the signed wrapper's metadata-only Keychain
lookup. It returns only `empty` or `present`, includes partial credentials and old
Access credentials, and fails closed on lookup errors. It never reads secret bytes.
Profile creation repeats the empty-credential check inside the account-enrollment
lock; neither provisioning nor package installation starts the collector or claims
an account. Users still sign in, change the initial password and explicitly connect.

Manual packages have no account destination and do not probe Keychain or create a
profile. Installation scripts require the running startup volume and reject
pre-existing redirected/unmanaged installation roots before payload installation.
The generated live profile is not in the payload, so an upgrade cannot overwrite it.

1. Owner: create a network, see its setup state, appoint its admin, open it.
2. Admin: see a plain-language overview, invite people, connect devices, handle
   reset requests, and investigate actual issues with evidence one level deeper.
3. Endpoint: sign in, set initial password, connect this Mac, see reporting state,
   permission/setup problems and the next useful action; request account help.
4. Empty, stale, offline, failed, and loading states must be explicit. "Reporting"
   does not mean "no threats" or "fully protected". Santa Monitor mode is not blocking.
5. Network isolation tests cover list/detail/mutations, spoofed headers/domains,
   revoked authority, reset replay, first-login bypass, and enrollment reuse.
6. Local tests, browser interaction, signed package, live DNS/deployment, and
   clean-Mac acceptance are independently recorded. No fake deployment indicators.

## Capacity decision (27 August 2026)

The read-only live D1 check returned 268,419 events, 219 unprocessed records,
zero stored processing errors, and 477,241,344 bytes of database storage. This is
near the Free per-database limit, not evidence of ample capacity. Recommend Workers
Paid for continued hosted ingestion, with retention and billing monitoring; do
not purchase automatically. Standalone does not require this subscription.

Sources: [Workers pricing](https://developers.cloudflare.com/workers/platform/pricing/),
[D1 limits](https://developers.cloudflare.com/d1/platform/limits/),
[Queues pricing](https://developers.cloudflare.com/queues/platform/pricing/),
[password storage guidance](https://cheatsheetseries.owasp.org/cheatsheets/Password_Storage_Cheat_Sheet.html).

## First milestone evidence

- Standalone migration 9 adds explicit ownership, account namespaces, endpoint-only
  password sessions, reset requests, and account-linked enrollment grants.
- `/console` is a task-oriented network/people/device view. `/admin?investigate=1`
  keeps the detailed investigation tools. New bootstrap/login flows route to the
  console; network selection is checked by the server on every scoped API request.
- Added 18 regression cases (including parameterized inputs): owner/admin isolation,
  endpoint-to-admin denial, first-login gating, one-use resets, session/grant
  revocation, password expiration, malformed input redaction, rate limits, exact
  device binding, streamed request-size limits, and migration non-promotion.
  Full gate: 315 tests, 88.09% coverage,
  strict MyPy, Ruff, Bandit zero issues, wheel and source distribution builds.
- Browser QA used `tests/preview_network_console.py` with a synthetic owner in a
  temporary SQLite database. Network switching, account creation, one-time credential
  handoff, and absence of that account in a different network were exercised.
  The preview uses real in-process account APIs but deliberately injects a test
  owner session. It is NOT browser-passkey, TLS, real-user, or deployment proof.
- The native status wording no longer equates a healthy check-in with being protected.
  The subsequent native account milestone is recorded below.

## Native account milestone (28 August 2026)

The Mac app now contains a real API-connected Account section: network sign-in,
mandatory first-password change, in-app reset requests, explicit device connection,
and recovery after an interrupted first check-in. A configured but unenrolled Mac
opens the Account section first. Successful setup points to Protection for current
health; its historical setup receipt never masquerades as a live status check.

The account transport is HTTPS-only to the operator profile, uses ephemeral sessions,
rejects redirects and wrong status/content contracts, and stops at 16 KB. Account
bearers expire after 15 minutes and stay in process memory. Passwords are cleared
from form state when submitted or when leaving the screen. No additional password
change is offered after completed setup; the person asks their admin for a reset.

`agent-enroll-app` reads only a fixed-directory UID/digest-bound grant file and uses
the existing root Keychain and activation helpers. It takes a nonblocking exclusive
enrollment lock, rejects existing credentials or membership, verifies authoritative
account/network/device identity, and writes a public credential-free receipt. The
uninstaller validates and removes only the specific owned account profile, receipt
and lock, preserving unrelated operator files.

### Operator setup for a fresh Mac

After installing a build that includes this milestone, a Mac administrator configures
the account server once with the installed helper, for example:

```bash
sudo /Library/ControlForge/bin/controlforge agent-configure-account-server \
  --api-host accounts.example.com --api-port 443
```

Use the real operator-controlled HTTPS host, not an endpoint username domain unless
that host actually serves the account API. This command is **not** a migration: it
requires an empty collector Keychain and refuses to replace a different existing
profile. A unique device ID is generated on the Mac, not embedded in an installer.
Do not run it on a currently enrolled production Mac to move networks. This manual
step is unnecessary when a fresh Mac uses an account-enabled installer (see below).

`account-server.json` is root-owned mode 0644 under `/Library/ControlForge/status`;
it contains only schema, host, port and device ID. Installer provisioning is now
implemented as recorded below; explicit migration of existing managed Macs remains
separate work.

### Validation boundaries

- Full local gate: 344 tests, 88.38% Python coverage, strict MyPy across 56 source
  files, Ruff, Bandit with zero findings, and wheel/source-distribution builds.
  Native Swift compile/run contracts are included in this gate. Both temporary
  preview applications were closed after inspection.
- Native Swift compile/run contracts target macOS 13 and cover first-login gating,
  mismatched confirmations, session/account scope drift, expiry, grant/device binding,
  redirect/status/size rejection, file ownership/mode/link checks, argument injection,
  interrupted activation and missing-receipt failures.
- The Python privileged helper is exercised against the real in-process account and
  enrollment HTTP API with a temporary database. Keychain and activation are injected
  test doubles, not an actual privileged installation or server check-in.
- Temporary native builds were visually inspected for unconfigured, sign-in,
  first-password, connect, reset, interrupted and completed states. The stage preview
  (`tests/preview_mac_account.swift`) is explicitly synthetic and excluded from the
  source distribution and shipped app build. No credentials were entered through UI.
- The native app was compiled and ad-hoc signed for local inspection only. No new
  Developer ID-signed/notarized installer or clean-device activation has been verified.
- The production collector, Keychain, profiles, Cloudflare deployment, DNS and billing
  were not changed. No commit or push was made.

## Owner and management milestone (28 August 2026)

Migration 10 adds monotonic network and account-management revisions. Existing
appliances can explicitly designate an owner using the offline operator CLI;
there is no public owner-upgrade endpoint. The console now supports account-name
setup on existing networks, display-name changes, pause/resume, human team roles,
endpoint sign-in state, and cancellation of pending administrator invitations.
Plain-language confirmations explain the retained data, revoked authority, and
the distinction between an account and an already-enrolled collector.

### Existing-appliance owner designation

Use the actual private database and existing secrets directory, owned by the
appliance operator. These example paths are placeholders. Back up and verify the
appliance, apply the normal schema upgrade, then stop the runtime before designation.

```bash
controlforge standalone owner status \
  --database /absolute/path/controlforge.db \
  --secrets-directory /absolute/path/secrets

controlforge standalone owner designate \
  --database /absolute/path/controlforge.db \
  --secrets-directory /absolute/path/secrets \
  --tenant-id EXISTING_HOME_TENANT_ID --user-id EXISTING_PASSKEY_ADMIN_ID \
  --confirm DESIGNATE-PLATFORM-OWNER
```

Use the exact candidate IDs from `status`. The command refuses an unsafe path,
hard-linked database, missing existing secrets, incompatible schema, failed audit
verification, running-runtime lock, conflicting network identity, or a different
already-designated owner. It never creates credentials or transfers ownership.
Restart the runtime and sign in again with the designated administrator's existing
passkey. Configure the missing account namespace through that network's console card.

### Validation evidence

- Full local gate: **358 tests, 88.56% coverage**, strict MyPy across 58 source files,
  Ruff, Bandit with zero findings, and wheel/source-distribution builds.
- Fourteen lifecycle tests cover owner adoption, identity collision rollback,
  trusted paths, audit-key mismatch, stale revisions, scope/CSRF/confirmation checks,
  session and enrollment revocation, interrupted invitations, and audit-failure
  rollback. Signed synthetic collector authentication is denied during a pause and
  works with the same preserved credential after resume.
- Response tests prove that proposed/approved actions expire on a relevant authority
  change while dispatched actions remain recorded as dispatched. Old principals
  cannot propose, approve or reject after revocation. No real endpoint action ran.
- Browser QA against temporary SQLite and the real in-process APIs exercised namespace
  adoption, pause/resume and owner fallback, role changes, account creation/disable,
  one-time credential handoff, and immediate invitation listing/cancellation. The
  390-pixel layout had no horizontal overflow. This is not a full accessibility audit.
- The preview deliberately supplies a synthetic owner session. These checks do not
  prove browser passkeys, real users, hosted deployment, public DNS or OS authorization.
  No production identity, collector, Keychain, DNS, subscription or deployment changed.

## Account-installer milestone (28 August 2026)

- The builder accepts a fixed account server host/port and creates a non-secret,
  schema-validated default in the package. The live per-Mac profile is generated only
  after installation, under the existing root-owned account-enrollment lock.
- `agent-provision-account-server` reports only a bounded outcome: fresh sign-in
  ready, existing profile preserved, existing collector preserved, or manual setup
  required. A different package host never silently retargets an enrolled Mac.
- The signed-wrapper source adds a root-only `keychain-enrollment-state` operation
  using metadata-only lookups. It returns no credential values. Errors are not
  interpreted as an empty Keychain. The existing initial-pair guard is rechecked
  before profile creation.
- Full local gate: **381 tests, 88.61% coverage**, strict MyPy across 59 source files,
  Ruff, Bandit with zero findings, and wheel/source-distribution builds. The separate
  in-process enrollment test now starts with installer defaults before claiming an
  account-bound grant. Keychain writes and activation remain injected test doubles.
- A real unsigned Apple Silicon PKG was built at
  `dist/macos/account-installer-20260828/ControlForge-0.3.0-unsigned.pkg`:
  14,685,120 bytes, SHA-256
  `bf6f8e2cd05bc836ca0dac2f179b5dc9d5081b75a089267536c6af514e2c160b`.
  It intentionally uses the synthetic `accounts.example.com` host. **Do not
  distribute or install it as a production account package.**
- Expanded-package inspection verified the exact pre/post-install scripts, root-owned
  mode-0644 defaults, absence of a live profile/membership, and intact ad-hoc signatures
  on the app and wrapper. The bundled runtime exposes the new command. The packaged
  metadata helper exits 77 with no output when invoked without root authority.
- The build emitted `write: Permission denied` warnings; the subsequent expanded-payload
  and code-signature checks passed. A clean-machine installer run remains necessary.
  The existing Developer ID release artifact was not overwritten. No installation,
  notarization submission, credential change, deployment, commit or push occurred.

## Device guidance milestone (28 August 2026)

The network console now includes active, enrolling and revoked device records, with
a labelled, device-specific Connection details dialog. It fetches fresh scoped
evidence when opened, includes the server observation time, and clears prior details
before a load. Failed requests show an explicit unavailable state and have a
20-second timeout. The 200-record list limit is disclosed; the active-device metric
uses the separate aggregate rather than silently counting only the displayed rows.

Guidance is deterministic, not LLM-generated. It distinguishes a recent check-in,
no first check-in, an overdue check-in, interrupted enrollment, absent usable
credentials, revoked access, and an inconsistent future timestamp. A recent check-in
with no usable credential is still an attention state. The suggested steps preserve
retained activity and existing credentials and direct users to the Mac's actual
Protection/Account views. The server does not infer local permissions, Santa blocking,
absence of malware, or physical containment from a connection timestamp.

The read-only `/v1/dashboard/devices/{device_id}` route uses the same passkey-session,
capability and network-selection checks as other admin projections. It queries the
selected network, returns a uniform missing-device response, and exposes no credential
IDs, secrets, raw events or account passwords. Tests include colliding device IDs in
different networks, owner network switching, admin cross-network denial, rejection of
endpoint password sessions, bounded identifiers and the 15-minute freshness boundary.

Final local gate: **397 tests passed, 88.71% Python coverage**, strict MyPy across
60 source files, Ruff, Bandit with zero findings, and wheel/source-distribution
builds. The rendered console script also passed Node's syntax check. Python coverage
does not measure browser JavaScript execution; UI interaction evidence is separate.

Browser inspection used temporary SQLite and the real in-process APIs with a synthetic
owner. The seven listed states, stale and fresh detail dialogs, a forced HTTP 503
unavailable state, and empty-network switch were exercised at a 1280-pixel viewport
with no horizontal overflow. The failed request left no previous device facts in
the dialog. This is not
physical-device telemetry, browser-passkey or deployment evidence. Full narrow-screen,
keyboard and assistive-technology acceptance remain open.

The unsigned installer above predates this server/dashboard-only milestone; it was
not rebuilt as a release. No installed collector, Keychain, production account, DNS,
subscription or Cloudflare deployment was changed. No commit or push was made.

## Multi-network recovery and installed configuration milestone

The single-organization lifecycle restriction is removed for appliances with up
to 200 networks. Startup preflight, automatic pre-upgrade backup, explicit offline
restore and failure rollback now support the whole multi-network database. This
is local implementation and regression evidence, not a production recovery drill.

- Single-network backups retain the version-1 manifest without a new inventory
  field. Multi-network backups use a version-2 manifest with a sorted, unique,
  authenticated `tenant_ids` inventory. The outer encrypted container and key
  derivation are unchanged; older version-1-only readers reject version 2.
- `tenant_id` remains the backup-history anchor, normally the owner's home
  network (or the first network in a legacy appliance). It does not mean only
  that network was backed up. CLI inventory returns the full network set.
  Backup-history rows are not duplicated into every network's dashboard.
- Backups are operator-only whole-appliance artifacts. Explicit tenant selection
  on a multi-network appliance is rejected rather than exporting other networks
  under a misleading tenant-scoped label.
- Inventory comes from the consistent SQLite snapshot. A concurrent network
  creation is included if it is in that snapshot. Integrity, foreign keys,
  supported migration ledger, inventory and backup-history identity are checked
  before restoration replaces the database. Backup holds the shared operation
  lock before writing its history; restore still requires the exclusive offline
  lock.
- In-place restore requires the exact same network set. A backup from before a
  new network was created cannot silently delete that network. Intentional older
  recovery uses a separate empty database with the original appliance key bundle.
  Database backup does not include TLS files, installed service configuration or
  the key bundle: keep separately protected recovery copies. Historical sessions
  and credential state are restored too; review revocations before reopening
  service. This is not selective tenant restore or a merge operation.
- The launcher accepts `--network-base-domain`. Interactive commands can capture
  `CONTROLFORGE_NETWORK_BASE_DOMAIN`; service installation pins its normalized
  value in launchd arguments. Managed restarts use those arguments, including an
  intentionally absent domain, regardless of later shell/launchd environment
  changes. Invalid domain syntax fails before service actions. Use the same
  configuration options for install, status and uninstall. No existing namespace
  is renamed, and this option does not provision DNS or TLS.

Regression coverage includes account/password-reset/device-enrollment/audit
restoration across three networks, empty-root recovery, mismatched live network
sets, malformed and contradictory authenticated manifests, concurrent network
creation, operation-lock failure cleanup, legacy format compatibility,
three-network schema upgrades and automatic rollback, and installed-domain
restart persistence. Launchd is exercised with an injected command runner in
temporary directories; the real installed daemon and collector are untouched.

Fresh validation on 2026-08-28: `source .venv/bin/activate && make verify` passed
**429 tests at 88.89% coverage**, Ruff lint/format checks (118 files), strict MyPy
(60 source files), Bandit with zero findings, and wheel/source-distribution builds.
The new recovery tests are in `tests/test_network_backup.py`; upgrade/restart
regressions extend `tests/test_standalone_appliance.py` and
`tests/test_standalone_launchd.py`. This gate did not rebuild or notarize a Mac
installer, operate real launchd, provision DNS, or exercise the hosted Worker.

## Canonical-host network routing milestone

Migration 11 adds owner-controlled network entry routes, disabled by default.
Upgrading does not rename namespaces, enable routes, duplicate identities, or
change accounts. The existing Python appliance remains the authoritative account
store; the hosted TypeScript Worker and its identity store are unchanged.

- The owner opens **Web address** on a network card, reviews its exact address,
  and explicitly enables or disables application entry routing. This uses the
  same optimistic network revision as other settings. Origin/CSRF, live session,
  owner authority and audit writes are enforced transactionally. Ordinary network
  admins cannot configure routes, including for their own network.
- The application accepts authenticated APIs only on its exact configured HTTPS
  authority (host and port). Other hosts, duplicate/malformed Host headers, plain
  HTTP, and forwarded-host/protocol spoofing are rejected before account body
  parsing or authentication. Packaged and CLI standalone launchers explicitly
  disable implicit proxy-header trust.
- Only GET/HEAD `/` on an enabled, active network's exact namespace can redirect
  to the fixed canonical `/console?network=...` destination. Paths and incoming
  query strings are not carried over. Aliases never serve account/admin APIs or
  issue cookies; unknown, paused and disabled entries fail closed. A database
  lookup failure returns a bounded 503 without redirecting or reflecting details.
- The network hint survives the canonical passkey sign-in page, but is selected
  only from the authenticated membership list. It is not an authorization grant.
  An unavailable hint hides the workspace and gives a clear return-to-own-network
  action. Every data API still independently enforces network scope.
- Disabling an entry link does not disable an account or collector using the
  canonical host. Pausing a network suppresses its enabled link; resuming restores
  that link if it was still enabled. Changing the configured base domain does not
  migrate old namespaces; mismatched entry routes become unavailable.
- The web card distinguishes `namespace_only`, `entry_enabled`, `paused`, and
  `unavailable`. It explicitly says DNS/HTTPS is **not verified**. There is no
  claim that toggling the application route publishes DNS or provisions TLS.
- Multi-window browser validation uncovered CSRF rotation on every console load.
  New sessions now use a purpose-separated, keyed, session-bound CSRF token that
  stays stable across tabs. Only its hash is stored. Tokens remain isolated by
  session, expire with the session, and are rejected after logout. Legacy random
  tokens converge once on the first read after upgrade; an already-open legacy
  tab may need a reload. Origin and stale-revision checks remain required.

Browser checks used the loopback synthetic preview with the real in-process
account APIs, not production identities or browser passkeys. Enabling an entry
updated the card; a competing stale dialog displayed a revision-conflict error
without invalidating authentication. An unavailable hint showed no workspace and
Refresh returned to the owner's own network. At 390 × 844, document width stayed
390 pixels and the dialog was 352 pixels wide with bounded vertical scrolling.
Cancel closed the dialog and returned focus to a button. This is not a full
accessibility audit, public subdomain navigation, browser-trusted TLS, or physical
passkey evidence.

### Hosted ingress contract (not deployed)

The standalone service needs a real running appliance/server; adding its domains
to the existing Worker does not deploy Python/SQLite there. A separate staging
hostname should be verified first. Keep the current SOC Worker and collector
destination intact until an explicit migration/cutover is authorized.

For Cloudflare Tunnel, use HTTPS to the origin with certificate validation and
the canonical `originServerName`. Preserve the incoming HTTP Host so the
application can distinguish exact network entries; do not replace it with the
canonical host through `httpHostHeader`, and do not disable TLS verification.
Use exact approved ingress hostnames and a final rejection rule. DNS records,
edge certificates, origin certificate trust, service persistence, authenticated
end-to-end enrollment and rate-limit behavior behind the connector all require
independent staging evidence. These are requirements, not configured resources.
See Cloudflare's [origin parameters](https://developers.cloudflare.com/tunnel/advanced/origin-parameters/)
and [ingress configuration](https://developers.cloudflare.com/tunnel/advanced/local-management/configuration-file/).

No real launchd, installed collector, Keychain, production identity, DNS record,
subscription, or hosted deployment changed in this milestone. No commit or push
was made. The earlier unsigned/native package was not rebuilt or notarized here.

Final local gate on 2026-08-28: `source .venv/bin/activate && make verify`
passed **469 tests at 88.97% coverage**, Ruff lint/format (120 files), strict
MyPy (61 source files), Bandit with zero findings, and wheel/source builds.
`tests/test_network_routing.py` contains 40 routing/session regressions;
`tests/test_network_backup.py` also verifies that restored routing state retains
its authenticated audit history. Both temporary browser tabs and the loopback
preview server were closed after validation.

### Staging ingress runbook

Local implementation on 2026-08-28 adds `tunnel-config` to the hardened module
launcher and an opt-in `--ingress-mode cloudflare-tunnel` to both serve commands.
The default remains `direct`. Managed-service arguments pin the mode across
restarts; no environment variable silently enables forwarded-header trust.

This is a same-host connector design, not a Worker replacement. Choose a
separate staging hostname and a durable appliance host before creating external
resources. Do not repoint `soc.chanakyachowdary.in` or re-enroll existing collectors
as part of this setup. Keep the configured passkey origin/RP ID stable.

1. Start the standalone appliance with its real certificate/private key, a
   canonical HTTPS origin on port 443, the matching RP ID and network base domain,
   plus `--host 127.0.0.1 --port 8443 --ingress-mode cloudflare-tunnel`.
   The internal port may differ from public 443. A different bind address in
   Tunnel mode fails before runtime creation. Retain Uvicorn `proxy_headers=False`.
   For a managed installation, use these same options for service install/status.
2. Bootstrap the owner through an already verified secure route, or bootstrap
   locally with the same canonical origin before switching ingress mode. Create
   the desired network namespaces and enable their **Web address** entries.
   Generation requires an existing current-schema database with 1–200 networks;
   it never bootstraps or migrates the appliance.
3. After creating a locally managed Tunnel through the operator's authorized
   Cloudflare account, keep its credential JSON private on the appliance. Generate
   a candidate configuration using that Tunnel's actual UUID. Example placeholders:

   ```bash
   python -m controlforge.standalone tunnel-config \
     --database /Library/ControlForge/appliance/data/controlforge.db \
     --admin-origin https://admin.staging.example.com \
     --network-base-domain staging.example.com \
     --port 8443 \
     --tunnel-id 11111111-2222-4333-8444-555555555555 \
     --credentials-file /Library/ControlForge/tunnel/credentials.json \
     --ca-pool /Library/ControlForge/tls/origin-ca.pem
   ```

   Use the actual database path from the installed appliance. Output goes to
   stdout; save and review a candidate before replacing a working connector
   configuration. The credentials/CA arguments are references only: their
   contents and existence are not checked by this command. Omit `--ca-pool` only
   if the connector already trusts the origin certificate issuer. Never substitute
   disabling certificate verification as a remedy.
4. Validate the saved candidate with
   `cloudflared tunnel --config /absolute/path/config.yml ingress validate`.
   Confirm each intended hostname matches its exact ingress rule and an unknown
   hostname matches the final 404. Preserve `originServerName`,
   `noTLSVerify: false`, `matchSNItoHost: false`, and the original HTTP Host.
   Do not add `httpHostHeader`, wildcard ingress, or a header-rewriting Worker.
   See Cloudflare's [configuration reference](https://developers.cloudflare.com/tunnel/advanced/local-management/configuration-file/)
   and [origin TLS settings](https://developers.cloudflare.com/tunnel/advanced/origin-parameters/).
   Before registering a root daemon, copy the already verified connector into a
   root-owned, non-writable appliance binary directory and record its SHA-256.
   Never point a root launch daemon at Homebrew's user-writable prefix or a
   symlink. Install the exact service through the bundled lifecycle command:

   ```bash
   /Library/ControlForge/standalone/bin/controlforge-runtime \
     standalone-appliance connector-service-install \
     --binary /Library/ControlForge/standalone/bin/cloudflared \
     --binary-sha256 <verified-64-character-sha256> \
     --config /Library/ControlForge/tunnel/config.yml
   ```

   The command independently checks root ownership, private config mode,
   executable mode, the pinned digest, the connector's own ingress validator,
   exact launchd arguments, and post-activation loaded state. Partial activation
   removes only the exact plist it created; uninstall preserves Tunnel config and
   credentials. `connector-service-status` and `connector-service-uninstall` take
   the same binary, digest and config arguments.
5. Publish only the approved staging DNS records and verify their edge
   certificates. Enforce HTTP-to-HTTPS redirection at the edge before forwarding
   requests. Origin TLS alone does not prove that a browser used HTTPS to the
   edge. Ensure `CF-Connecting-IP` is retained. Do not enable a transform that
   removes it; same-zone Workers can alter its meaning, so this deployment does
   not place one before the connector. See Cloudflare's
   [client-header behavior](https://developers.cloudflare.com/fundamentals/reference/http-headers/).
6. Exercise real passkey sign-in, scoped admin access, initial endpoint-password
   change, enrollment, check-in, and password-reset handling through staging.
   Verify that separate clients do not share one IP budget and account/global
   limits still apply. If Cloudflare Access is also applied, explicitly test
   native client/API coexistence; this implementation neither adds an Access
   service token to endpoint accounts nor bypasses an existing Access policy.
7. Prove connector/appliance restart persistence and an encrypted recovery drill
   before a production cutover. Disabling or pausing an entry is enforced by the
   application immediately; enabling a new entry also requires regenerating,
   validating and installing the connector snapshot and publishing its DNS/TLS.
   These external changes are not performed by the dashboard toggle.

Tunnel mode requires exactly one valid client IP field on every request, including
`/health`; missing/malformed metadata and non-loopback peers receive a bounded 403
before body parsing. Test public health through the connector. A deliberately
local diagnostic must preserve the canonical Host, validate TLS using its canonical
SNI and supply an explicit synthetic client address. That diagnostic is not proof
of Cloudflare connectivity. The mode never treats client IP as an authenticated
person or network; other processes on the appliance are inside this trust boundary.

Local evidence for this ingress increment:

- A real Uvicorn loopback TLS socket accepted a certificate trusted explicitly by
  the test client and rejected both an untrusted issuer and the wrong SNI hostname.
  With canonical certificate SNI and an enabled alias Host, the real HTTP response
  was the fixed canonical redirect. Alias APIs and unknown Host values failed.
- Request tests cover absent/duplicate/malformed/oversized client metadata,
  untrusted peers, forged forwarded Host, direct-mode spoofing, equivalent IPv6/IP
  forms, independent client budgets and endpoint account/global limits.
- Snapshot tests verify current-schema/private-file checks, inactive and
  out-of-domain exclusions, exact hosts plus final 404, non-disclosure of a
  synthetic credential file's content, CLI parity and unchanged logical database
  contents. Managed restart tests verify the installed mode survives an unrelated
  shell environment.

These tests do not establish a live Tunnel, edge TLS, browser-trusted origin
certificate, physical passkey, or native endpoint enrollment. `cloudflared` was
not installed or run on this host during this increment; its deployed parser and
connector behavior remain staging gates. No external resources or installed
services were changed.

Final gate for this increment: `source .venv/bin/activate && make verify` passed
**508 tests at 89.11% coverage**, Ruff lint/format (123 files), strict MyPy
(63 source files), Bandit with zero findings, and wheel/source builds.
The 37 new ingress tests include the actual local TLS listener; the existing
managed-restart test now also runs in both ingress modes. The built wheel contains
the new ingress and Tunnel snapshot modules. `git diff --check` passed. No signed
Mac package was rebuilt, and no commit, push, deployment or purchase was made.

### Native guidance and status contract milestone (local)

Current-source collector status v3 now includes required bounded aggregate counts
for failed, degraded, missing and stopped security components. Previously a
degraded result contributed to neither the failure count nor the Mac's warning,
allowing a misleading all-passed presentation. The counts now come directly from
structured control results without exposing component names, paths or evidence.
The native decoder requires the v3 fields and their count invariants. Older v1/v2
summaries remain readable but do not prove degraded health is absent.

The Mac's deterministic guidance now distinguishes component problems, collection
failures, credential-renewal failures, upload interruption, waiting report batches,
unattempted upload, stale/future reports, and network restrictions. A successful
upload does not override a degraded check or active/unreconciled restriction.
Passed release times require a newer report rather than implying that access was
restored. Outdated component cards are explicitly historical and neutral, not green.
Zero rejected Santa input does not prove collection ran or blocking mode is enabled.

The Protection screen shows the trusted local network setup record only when its
device matches the report (or no report exists), and provides working Account and
contextual Help navigation. Help carries the current explanation and next step,
with a redacted support summary containing report age/state and aggregate counts.
Device identifiers and versions are bounded before display/copy. The Account
screen explains that a configured device can keep reporting while the user is not
signed in for account tools. No new scan, forced upload, permissions change,
service restart, reset, or containment action is performed by the status buttons.

Local validation includes a real collector run with synthetic structured control
results and a fixture HTTPS transport, plus native Swift decoding/presentation
contracts for 18 report scenarios, empty states, stale restrictions, missing or
inconsistent fields, secret-extension rejection and failed-read recovery. These
are software contract tests, not physical endpoint or provider evidence.

Computer-use inspection of the native synthetic preview confirmed normal,
degraded, stale and restricted presentations, direct Help/Account navigation,
and a 760-point-wide minimum layout with wrapped text and vertical scrolling.
The preview uses injected synthetic models, not installed state, real accounts,
Keychain, or privileged commands. It is excluded from source distributions.
The release-path native source also compiles without the test flag.

This increment is not a signed/notarized installer or installed-agent update.
Deploy the collector and native app together: the old app rejects v3, while the
new app reads v1/v2 conservatively. The current physical-acceptance verifier now
requires v3; the older signed v2 release is not evidence for this change.

Final local gate on 2026-08-28: `source .venv/bin/activate && make verify`
passed **516 tests at 89.14% coverage**, Ruff lint/format (123 files), strict
MyPy (63 source files), Bandit with zero findings, and wheel/source builds.
An earlier full run reported a native test failure during ongoing edits; its
isolated rerun and the final full gate passed. The final native source was also
rebuilt without `CONTROLFORGE_CONTRACT_TEST`. The synthetic preview was closed
after inspection. No installed agent, Keychain item, permission, production
account, DNS record or subscription changed; no commit, push or deployment occurred.

## Administrator finding guidance milestone — 2026-08-28

The standalone case workbench now starts with what was recorded, why that kind
of activity needs review, its reported actor and event/receipt times, and a
linked device when the stored event has one. An expandable checklist suggests
read-only review; technical rule provenance remains available separately.
The saved rule description is explicitly attributed to the historical rule.
Guidance is static event-category context, not an AI verdict or a second
detector: it does not reinterpret a rule, change severity, assert an attack,
or claim that an XProtect remediation succeeded. Unknown event types receive
generic review guidance. Viewer-only roles are directed to an analyst for notes
and dispositions rather than being offered new write capabilities.

Network device rows and their connection dialogs now link directly to the case
queue with explicit network and device parameters. Case evidence links back to
the same device-filtered view, with an expandable current connection snapshot.
Only the case queue is filtered; the interface labels other panels as
network-wide. Filtering uses an exact, tenant-scoped join to the event's device
ID, never an actor-name guess or wildcard match. Recurrences retain their existing
aggregation and exact linked-alert counts. A case can include other evidence;
the filter does not silently remove that evidence from its detail view.

The investigation page validates its network against current authenticated
membership and pins subsequent API requests to that network. Invalid, ambiguous
or inaccessible links do not silently fall back to another network. There is a
visible route back to the network console on a rejected link. Device parameters
are bounded, encoded as data, and cannot grant authority. All new labels and
historical descriptions render as text, not HTML. The existing same-origin CSP,
passkey sessions, CSRF, tenant scope and independent response approvals remain.

Case-selection generations discard late responses after another selection or
filter change. A failed detail request clears the old case and its actions.
Refresh reloads the selected case's evidence; requests have a 20-second timeout
covering response-body loading. Device links focus and scroll to the case queue
after the asynchronous workspace has loaded.

Local evidence:

- Real deterministic-worker fixtures produce five alerts in four cases; an exact
  device filter returns two cases, including two launch alerts grouped as one
  case. An unbound event with the same actor name does not enter that filter.
- API tests cover same-ID devices in different networks, network-admin scope,
  endpoint-account rejection, wildcard/injection-shaped identifiers, bounded
  inputs, no raw payload projection, and generic unknown-category guidance.
- Executable JavaScript contracts cover network selection, ambiguous links,
  pinned request headers despite changed browser selection storage, encoded link
  parameters, out-of-order case responses, failure clearing and invalidated reads.
  Python coverage does not measure browser JavaScript statement coverage.
- Browser inspection uses the loopback-only synthetic preview with real services
  and a test-authenticated owner, not browser passkeys or production accounts.
  Alpha's device opens its two cases; “Show all network cases” returns four.
  The same device ID in Beta shows Beta's name and evidence, not Alpha's. The
  XProtect checklist distinguishes detection from remediation. Expandable
  connection details, direct-link heading focus and the desktop layout were
  inspected. This is not a complete keyboard, screen-reader or narrow-screen audit.
  An empty priority filter clears the prior case and reports no matching cases,
  not an all-clear. An unavailable network shows no network data and offers the
  network-console recovery link. Its signed-in error state hides invitation
  forms and clears the busy announcement; the latter is also contract-tested.

Final local gate: `source .venv/bin/activate && make verify` passed **533 tests
at 89.15% coverage**, Ruff lint/format (126 files), strict MyPy (65 source files),
Bandit with zero findings, and wheel/source builds. `git diff --check` passed.
The source archive includes the new guidance, UI helper and test contracts;
developer preview entry points remain excluded. No production deployment,
subscription, installed collector, Keychain item, DNS record, commit or push
was changed by this milestone.

## Release prerequisite audit — 2026-08-28

A fresh read-only Cloudflare query reported **280,961 events, zero pending rows,
zero stored processing errors, and 499,843,072 bytes** for the existing hosted
database. The query wrote zero rows. This is approximately 500 MB, near the Free
per-database limit; it is not evidence that new ingestion has spare capacity.
Zero server-side pending rows also does not prove the endpoint spool is empty.
The documented local status snapshot was absent, so collector backlog drainage
was not verified by this audit. An unauthenticated request to the custom-domain
health URL returned HTTP 302, not a Worker health/version result; no authentication
policy was bypassed.

Workers Paid remains recommended for continued use of the existing hosted
pipeline, with retention and usage monitoring. The subscription starts at $5 per
month, not a fixed all-inclusive cap. The published Queue allowance is one million
operations per month plus usage charges, versus 10,000 daily on Free; D1's
per-database ceiling is 10 GB on Paid versus 500 MB on Free. This subscription does
not deploy the new standalone application or supply its persistent appliance host.
Sources verified during this audit:
[Workers pricing](https://developers.cloudflare.com/workers/platform/pricing/),
[D1 limits](https://developers.cloudflare.com/d1/platform/limits/), and
[Tunnel origin hosting](https://developers.cloudflare.com/tunnel/advanced/local-management/create-local-tunnel/).
No plan purchase or upgrade was performed or inferred from usage statistics.

Both Developer ID Application and Installer identities appeared in the local
Keychain metadata. Their private keys were not used and no new signing or
notarization operation was started. The historical package still has size
14,526,455 bytes and SHA-256
`a80cd724a6202f773074a002e534f78bf9b17c0fb3374606421017d929eacd0a`.
It predates the new account workflow and status v3. The acceptance document now
labels that evidence as historical rather than current-source release proof.

No `cloudflared` command was available on PATH, and the documented appliance/TLS
directories were absent. These checks do not inventory unrelated machines or
prove that no other deployment exists. A staging host and canonical HTTPS address
still need to be selected and authorized before installing a service, publishing
DNS or building an account-enabled public installer for that destination. The
existing `soc.chanakyachowdary.in` Worker must remain unchanged until an explicit
cutover decision. A temporary development-Mac staging setup would not establish
production uptime or substitute for clean-endpoint acceptance.

Pending user decision: authorize a separate temporary staging instance on this
Mac at `admin-staging.chanakyachowdary.in`, or supply a different staging host.
This would require new service/Tunnel/DNS setup, not merely local source testing.
No such setup has been performed. The proposal preserves the existing SOC and
collector; it does not authorize a paid-plan upgrade or a production cutover.

The current-source acceptance harness was rerun in temporary state at
2026-08-28T12:51:43Z: **16 checks passed, two optional checks were not run, and five
physical/deployment boundaries remained unverified**. It returned
`current_scope_passed=true`, `release_ready=false`. The omitted checks were
cross-runtime contract execution and signed-package inspection; the old artifact
was deliberately not supplied as proof of the new release. This harness still
tests the core standalone loop; it is not by itself proof of the complete new
multi-network/browser/native experience, covered by the separate tests above.

The acceptance-document regression now checks the historical-artifact limitation
and real-server requirement explicitly, tolerating layout/capitalization changes.
After correcting its obsolete wording expectation, the final `make verify` passed
**533 tests at 89.14% coverage**, Ruff, strict MyPy, Bandit (zero findings), and
wheel/source builds. `git diff --check` passed. No runtime behavior was changed
during this release audit; the documentation and its regression were updated.

## Still required by this goal

1. Clean-Mac validation of installer provisioning, the native UI and OS-authorized
   Keychain/configuration handoff; explicit
   migration and repair paths for existing managed Macs.
2. Shared hosted implementation and migration strategy, DNS/TLS provisioning under
   the owner's domain, and Cloudflare Access coexistence without bypassing security.
3. Broader administrator failure-state and accessibility/responsive acceptance,
   and native guidance verification on the actual managed device.
4. Signed/notarized new installer, clean-Mac and real-passkey acceptance, staging
   rollout, a recovery drill on the actual deployment, and explicit production
   deployment authorization.

No production account, DNS record, subscription, installed collector, or cloud
deployment was changed by this milestone. No commit or push was made.

## Live staging and polished release candidate — 2026-08-30

The previously proposed isolated staging boundary now exists at
`https://admin-staging.chanakyachowdary.in`. It is separate from the existing
`soc.chanakyachowdary.in` Worker and does not replace that production collector
path. Cloudflare Tunnel terminates public TLS and forwards only to the private
`127.0.0.1:8443` appliance listener. The latest live check returned HTTP 200,
validated the public TLS chain, and reported standalone version `0.3.0`, a
running worker, and no worker error.

Both local services run as root launch daemons. The connector no longer executes
the user-owned Homebrew path: it uses the root-owned regular file
`/Library/ControlForge/standalone/bin/cloudflared`, whose pinned SHA-256 is
`b6bc98e794894b4ccee49c027c7cae050bbf74a92212e2c4bef348f5b33fa846`.
The currently deployed signed appliance runtime has SHA-256
`b5e36bb3603fc19a943ce1b3b3b875bb82f8de0f566e2b03c71be155931d5802`.
The migration preserved the installed endpoint collector, runtime and launchd
plist byte-for-byte; this is staging evidence, not a dedicated-host uptime claim.

The first polished release candidate was
`dist/macos/staging-20260830-polished/ControlForge-0.3.0.pkg`, SHA-256
`8e74253faab7f90b9897ea2ed3327d6253f9522523905e229750403ddb5600b1`.
Apple notarization submission `5369c4cd-2499-49cb-92f8-2fd64032a18a` was
accepted, the ticket was stapled and validated, `pkgutil` reported a trusted
Developer ID Installer signature, and Gatekeeper accepted the installer. The
contained frozen runtime has SHA-256
`abc0570122539bd3527b6a7844a4b6f453610ef5bfa31b10dbdf22fa9d4dd305`;
both top-level and standalone help commands ran successfully. A fresh wheel also
installed in an empty virtual environment, both help commands ran, and
`pip check` found no broken requirements.

That candidate's source gate passed **544 tests at 88.84% coverage**, Ruff lint and
format checks, strict MyPy across 66 source files, Bandit with zero findings, and
source/wheel builds. A design review simplified first-run labels to “One-time
setup code”, “Network ID” and “Network name”, explains the human approval
boundary in plain language, and keeps the team-invitation choice hidden until the
first administrator exists. These changes were deployed to the live staging
runtime before the later accessibility additions were built.

The following evidence was still deliberately missing when the polished
candidate was recorded; the first and third items are superseded by the
post-bootstrap evidence below:

1. A real owner passkey registration and recovery-code ceremony on the staging
   origin.
2. Live owner creation of a second network, scoped network-admin invitation,
   endpoint-user first-login password change, reset request and administrator
   reset, plus device enrollment into the selected network.
3. An encrypted backup/restore drill and post-restore browser acceptance after
   the first owner creates the initial network. The runtime deployment and
   staging restart are complete.
4. Installation and migration/repair acceptance on a separate clean supported
   Mac. Testing on this development Mac cannot prove clean-endpoint behavior.
5. A dedicated always-on appliance host, monitoring/alerting and explicit
   production cutover authorization. The current development-Mac tunnel is a
   staging deployment only.

Workers Paid remains justified for the separate hosted D1/Queues pipeline because
the last measured D1 size was already near the Free 500 MB per-database ceiling
and Free Queue operations had previously been exhausted. It does not improve the
standalone dashboard, macOS application, passkey workflow or appliance uptime.
No subscription purchase or upgrade was performed.

### Accessibility and responsive acceptance update

A WCAG 2.1 AA review of the task-focused network console found and fixed missing
accessible names on the create-network, add-person, invite-admin, password-reset
and one-time-secret dialogs. Every dialog now has an explicit
`aria-labelledby` relationship. Subtle text links and the focused skip link now
have at least a 44 CSS-pixel target, while the existing visible focus outline,
landmarks, form labels, status live regions and native dialog focus trapping are
preserved.

Measured foreground/background contrast ratios were 13.14:1 for body text,
5.65:1 for muted text, 6.34:1 for accent links, 6.88:1 for primary button text,
13.14:1 for sidebar text, 8.51:1 for sidebar secondary text, 8.38:1 for errors
and 7.99:1 for status pills. A browser run against the synthetic, loopback-only
owner preview at 390 by 844 CSS pixels reported no horizontal overflow and no
visible interactive target below 44 by 44. A 640 CSS-pixel reflow run (the
effective width of a 1280-pixel viewport at 200 percent zoom) also reported no
horizontal overflow. Keyboard activation opened the create-network dialog,
focused its first field, exposed its accessible name and closed it with Escape.
These measurements cover the rendered web console with synthetic data. They do
not replace a manual VoiceOver session or real-passkey staging acceptance.

The accessibility-inclusive release candidate, now superseded by the final
first-run candidate, is
`dist/macos/staging-20260830-accessible/ControlForge-0.3.0.pkg`, SHA-256
`d1dd16a2b5b4b2fd2f9e97a847684517adb51c0ef6cf1903c004a5bd9532e880`.
Apple notarization submission `c3485801-6453-4ae8-a46c-c48b37b2ec9b` was
accepted and its ticket was stapled and validated. Gatekeeper accepted the
installer, and expanding the final product archive proved that the native app,
collector wrapper, frozen runtime, LaunchDaemon, pre/postinstall scripts, rules
and account-server configuration are present. All three packaged executables
passed strict code-signature verification. The packaged account configuration
contains only the expected staging host, port 443, account mode and schema
version. The contained frozen runtime SHA-256 is
`1ca76097bfd4b8bc0431768fb6012de054c8058beb3dab240cff8f4a6b6f0528` and both
top-level and standalone help smoke tests passed. The full source gate for this
candidate passed **545 tests at 88.83% coverage**, Ruff lint and format, strict
MyPy, Bandit with zero findings, and source/wheel builds.

### Final first-run candidate and live parity

The current release candidate is
`dist/macos/staging-20260830-final/ControlForge-0.3.0.pkg`, SHA-256
`1077d4623e23dcacb11fd25db759ce849e27c294f847869c560998065f238a31`.
Apple notarization submission `3178a947-17f7-4282-be93-1ef3b461ef25` was
accepted, its ticket was stapled and validated, `pkgutil` reported a trusted
Developer ID Installer signature, and Gatekeeper accepted the installer. All
three packaged executables passed strict code-signature verification. The
package contains the native application, collector wrapper, frozen runtime,
LaunchDaemon, pre/postinstall scripts, rules and the expected staging-only
account configuration. Its frozen runtime has SHA-256
`b5e36bb3603fc19a943ce1b3b3b875bb82f8de0f566e2b03c71be155931d5802`.

That exact runtime hash is deployed at
`https://admin-staging.chanakyachowdary.in`. A fresh public check on 2026-08-30
returned HTTP 200 with a valid TLS chain, version `0.3.0`, a running worker and
no worker error. Both the standalone service and its pinned Cloudflare Tunnel
connector were running as root launch daemons. The bootstrap-status endpoint
returned `configured=false`, so this proves live binary parity and service
health but not owner/passkey or post-bootstrap workflow acceptance.

The final source gate passed **545 tests at 88.84% coverage**, Ruff lint and
format, strict MyPy across 66 source files, Bandit with zero findings, and
source/wheel builds. `git diff --check` passed. The final candidate also changes
the first-run administrator email field to standards-based email autocomplete;
the real owner still must perform the origin-bound passkey ceremony with Touch
ID. No passkey was synthesized or bypassed.

### Live owner and recovery acceptance

The real owner completed the origin-bound passkey ceremony with Touch ID on
2026-08-30. The public bootstrap-status endpoint then returned
`configured=true`, and the authenticated console identified the principal as
`Platform owner` with one network available. No credential, setup code,
recovery code or session token was captured in this evidence.

An encrypted appliance backup and isolated clone-restore drill then passed. The
accepted artifact has backup ID `adc8a31d-2a40-4d39-a89f-6aaaa05e57a8`, SHA-256
`a65a05d1c96fe18035a905b40e7443d7c68e6fd7654280961ced669de6d45e78`,
and size 537,208 bytes. Authentication, SQLite integrity, foreign keys, the
single-network inventory and schema versions 1 through 11 all verified in the
temporary clone. The clone's post-restore database hash differs from the
encrypted snapshot hash by design because recovery records the backup history
row as `restored` after replacement. The temporary clone was removed; the live
database was never replaced.

Remaining live acceptance is the second-network/scoped-admin/endpoint-user
workflow, including first-password change, reset request and device enrollment.
Separate clean-Mac installation and migration proof, manual VoiceOver
acceptance, dedicated-host uptime and an explicitly authorized production
cutover also remain outside the current evidence.

### Versioned enterprise staging release

The multi-network/account work now advances on version `0.4.0` instead of
producing more indistinguishable `0.3.0` app bundles. The builder records an
embedded build identity and emits a matching public release manifest. Production
mode rejects a dirty tree, a missing exact `vVERSION` tag, a missing or mismatched
explicit production account host, missing Developer ID identities, or missing
notarization configuration.

The signed staging candidate is
`dist/macos/staging-20260830-0.4.0-rc3/ControlForge-0.4.0.pkg`, SHA-256
`c5d6c1ebcaca4401fe9e140abd59a26c648e7e34d130e44308f5a1149dd22813`.
Its frozen runtime SHA-256 is
`c776fcb105b9a924200cdfa072233ef3335ad08fc1e8d3491549b85f185d52ce`.
Apple notarization submission `0b780c68-9ef2-428c-8cb2-e4c39eae2908` was
accepted; stapling, ticket validation, Gatekeeper, strict signatures, archive
expansion and runtime help smokes passed. The embedded identity matches
`ControlForge-0.4.0.release.json` and pins the expected staging host.

This candidate also exposes its validated app version, channel and short source
revision in the native **Help & Diagnostics** view, resolving the otherwise
indistinguishable staging/development app experience without displaying the
account host or secrets.

The manifest explicitly records `channel=staging` and `source_dirty=true` at
commit `440f3cbfb91b51f19ae7598e4f746f6b6105460f`. This is deliberate evidence
that the artifact is not a customer production release. The manifest-aware
physical verifier passed its artifact checks on this Mac and rejected the
`preinstall` phase because an older ControlForge receipt and payload already
exist. Clean-Mac acceptance therefore remains open.
