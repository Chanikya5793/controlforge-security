# Threat model

## Assets

- endpoint control status;
- normalized security events;
- detection rules and alert decisions;
- analyst investigation history;
- future vendor API credentials.
- HIBP subscription credentials and verified-domain exposure intelligence;
- hashed application session identifiers and edge authentication telemetry.

## Trust boundaries

- local operating-system process and filesystem observations;
- inbound API event batches;
- YAML rule and agent configuration;
- SQLite persistence;
- CLI/API output consumed by operators or automation.

## Primary threats and controls

| Threat | Current control |
|---|---|
| Shell injection through control configuration | Fixed subprocess argument list; `shell=False`; paths are treated as data |
| SQL injection through event fields | Parameterized SQL only |
| Unbounded event ingestion | API batches capped at 10,000 events; alert queries capped at 1,000 |
| Duplicate alert flooding | Deterministic alert IDs and database uniqueness constraints |
| Ambiguous detector decisions | Every alert records matched fields and reasons |
| Malformed telemetry | Pydantic validation at CLI/API boundaries |
| Secret disclosure | Repository contains fixtures only; no vendor credentials are required |
| Unsafe active response | Active actions require a different approving principal; the exact-device macOS PF adapter is disabled by default, uses fixed arguments and owned state, preserves configured management access, expires within 15 minutes, and rolls back on partial failure |
| Exposure API key disclosure | Key is read from an environment variable, never accepted as a CLI argument, logged, or persisted |
| Plaintext breached identity retention | Aliases are SHA-256 hashed immediately; only the digest enters events and alerts |
| Arbitrary outbound requests | Exposure transport is pinned to the HIBP HTTPS host and validates DNS names before path construction |
| Edge-memory exhaustion | Correlation uses time-bounded per-source or per-session state and API batches remain capped |
| Prompt injection through telemetry | Alert reasons are delimited as untrusted data; structured output is post-validated against supplied evidence indexes |
| Hallucinated AI evidence | References outside the deterministic alert are rejected and all triage output requires human review |
| Model credential disclosure | Keys are Worker secrets, are sent only to the adapter's fixed Meta or Google API host, and are never persisted |
| Collector credential theft | Collector secrets are encrypted with a Worker-held AES-GCM key and returned only once |
| Access service-token theft | Collector traffic requires both the Access service token and a separate request-bound HMAC credential; both are stored outside the repository and rotate independently |
| Collector request replay | HMAC covers method, path, body, timestamp, and nonce; nonces are persisted and expire |
| Cross-tenant data access | Every cloud query is tenant-scoped and Access principals require tenant membership |
| Queue redelivery | Stable tenant-scoped identifiers and unique constraints make event and alert writes idempotent |
| Audit record tampering | Records carry an HMAC and database triggers reject updates and deletes |
| Autonomous unsafe action | Active and high-impact actions require a different approving principal; unsupported endpoint adapters fail closed |
| Unsupported response execution | The endpoint collector returns a bounded failure result without changing the host when the separately enabled adapter does not support the exact action or cannot validate its owned state |
| Recurring-alert case flooding | Active cases have a tenant-scoped semantic key derived from rule and device or normalized actor; a partial unique index and transactional link/update aggregate recurrences while closed history remains immutable |
| Unbounded case detail | Case and evidence projections return exact totals plus bounded newest records and explicit truncation indicators |

## Production requirements not claimed by this project

### Multi-network account expansion

The approved owner/network/endpoint-account design and release gates are in
`MULTI_NETWORK_PRODUCT.md`. Its new boundaries must prevent suffix-based authority,
cross-network scope switching, endpoint-to-admin escalation, first-login bypass,
reset enumeration, stale-password session reuse, and unsafe credential handoff.
Creating a login namespace does not provision DNS or prove domain ownership.
Owner-controlled entry routing uses exact Host/port matching before authentication
and body parsing, with no implicit forwarded-header trust. Aliases only redirect
root GET/HEAD requests to a fixed canonical origin, discard incoming query data,
and never issue cookies or serve APIs. Unknown, paused, disabled, mismatched and
failed-lookup aliases do not fall through. Network hints are membership-checked,
not authority. Owner changes use live capability, CSRF and revision checks with
atomic target/home audit writes. New routes default disabled on migration.
Investigation links pin network scope after checking current membership. Device
filters join the exact stored event device ID within that tenant; actor strings
never establish device identity. Guidance is static category context, not a second
detector or an AI verdict; historical rule descriptions and evidence remain
untrusted text rendered without HTML interpretation. Late case responses cannot
replace a newer selection, and failed reads clear old case actions. None of these admin
projections are exposed to endpoint password-account sessions or the native user app.
Session CSRF tokens are keyed and purpose-separated from authentication secrets,
stable within one session for multi-tab use, and stored only as hashes. Session
expiry/revocation and same-origin checks still apply. Legacy random tokens
converge once after upgrade; old open tabs may need reloading.
Installed-service arguments pin the validated base domain; daemon restarts do not
adopt an ambient domain environment variable. Existing namespaces are not renamed.
The optional Cloudflare Tunnel ingress mode accepts only HTTPS requests from the
fixed IPv4 loopback connector address, with exactly one syntactically valid
`CF-Connecting-IP`. It uses that address only for rate-limit partitioning, never
authentication, tenant selection, Host or scheme. Direct mode ignores proxy
headers. Missing/malformed connector metadata fails closed before body parsing.
The host operating system and same-zone Cloudflare configuration are trusted:
another local process or same-zone Worker can forge this metadata. This is not
connector authentication; endpoint global/account budgets and all passkey,
password, HMAC, scope and CSRF checks remain independent. Do not expose the
origin listener or put a header-rewriting Worker in front of these routes.
Generated Tunnel configuration is a read-only snapshot of exact enabled network
entries, with canonical origin TLS verification and a final 404. It neither
publishes DNS nor reads connector credentials. Operators must verify origin
certificate trust, deployed configuration, edge HTTPS redirects and client-header
behavior in staging; application entry toggles alone do not update the connector.
The managed connector lifecycle additionally refuses a user-writable or symlinked
binary, a digest mismatch, a non-private configuration, an unexpected plist, or
connector ingress validation failure before launchd activation. This prevents a
desktop user from replacing a package-manager binary that a root daemon executes.
Encrypted backups are operator-only whole-appliance recovery artifacts, not
network-admin exports. Multi-network manifests authenticate a sorted, unique
inventory of at most 200 networks. Verification checks that inventory, schema,
integrity, foreign keys and backup-history anchor before database replacement.
Offline in-place restore rejects a different network set; this avoids silently
discarding networks created after a snapshot. Snapshot scope comes from the
consistent SQLite copy, not a live query racing with network creation. The public
authenticated manifest exposes network IDs, not account names or credentials.
The appliance key bundle and service/TLS configuration require separate protected
recovery copies. Restoring a database also restores its historical credential and
session state; an operator must consider credential revocation and expiry before
returning a recovered appliance to service.
Owner authority is explicit; existing admins must never be bulk-promoted on upgrade.
The offline owner designation requires trusted operator-owned paths, existing
secrets, audit verification and an exclusive runtime lock. Identity collisions
fail without merging passkeys. Management writes and response decisions recheck
mutable session and role authority inside their transaction. Pausing a network or
disabling a human cancels relevant undelivered response approvals but never claims
to undo an already-dispatched action. Audit failure rolls back the access change.
Account-enabled installers carry a fixed non-secret host/port, never a shared
device identity or credential. A root-only helper validates the package defaults,
uses metadata-only Keychain presence checks and preserves existing enrollment.
Unknown Keychain state, unsafe files, and orphaned membership fail closed. Package
upgrades cannot silently replace the live account-server profile or change networks.
The local status v3 contract adds bounded aggregate counts for degraded, missing
and stopped security components, never their names, paths, evidence or commands.
Native guidance is deterministic: outdated observations cannot produce current
green component states, an active/unreconciled restriction outranks a successful
upload, and unattempted delivery is not a confirmed check-in. Older status formats
remain readable but cannot prove the new component details. End-user buttons only
navigate, reread status or copy the existing redacted support summary; they do not
restart agents, change permissions or release restrictions.

### Remaining requirements

- multi-node standalone high availability, PostgreSQL failover, or enterprise tenant sharding;
- an off-appliance audit-chain anchor, audit-key rotation ceremony, or immutable external archive;
- production-scale D1/Queue chaos and long-duration soak evidence for every migration/runtime;
- field-validated operating-system containment, account resets, or edge blocking. The macOS
  adapter remains disabled until its privileged install and live rollback exercise are verified.
- autonomous AI severity changes, alert closure, or containment.
