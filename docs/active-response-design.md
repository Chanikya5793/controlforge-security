# Active response design

## Scope

ControlForge documents a proposed active-response adapter for reversible network containment
on a managed macOS endpoint. The adapter is not implemented or installed in the current
release. CrowdStrike is not enabled because this deployment has no licensed Falcon tenant,
API client, or installed sensor. The platform must not claim either containment path without
those independently verified prerequisites.

The deterministic detector and human approval boundary remain unchanged. AI may recommend
an investigation step, but cannot propose, approve, dispatch, or execute containment.

## Authorization and dispatch

1. An analyst proposes `isolate_endpoint` or `release_endpoint` for an exact device ID.
2. A different authenticated responder or administrator approves the action before expiry.
3. The signed collector for that same device retrieves the approved action.
4. The collector validates the action type, risk level, target type, target ID, and expiry.
5. A future, separately installed macOS PF adapter could apply or release containment and
   return bounded evidence to the control plane. The current collector instead fails closed.

The proposer cannot approve their own active action. An operator, browser automation, or AI
agent controlled by the proposer is not an independent second responder.

## Proposed macOS PF boundary

A future adapter must:

- runs only on Darwin and requires effective UID 0;
- is disabled unless explicitly enabled in the collector configuration;
- uses fixed `/sbin/pfctl` argument arrays and never invokes a shell;
- loads rules only into the existing `com.apple/controlforge` wildcard anchor;
- never edits or replaces `/etc/pf.conf`;
- permits loopback, DNS, and HTTPS to the configured ControlForge API host;
- resolves only the configured fixed API hostname before containment;
- caps containment at 15 minutes, even when the control-plane action lives longer;
- records only its PF reference token, expiry, and management IPs in a root-owned state file;
- treats repeated isolate and release requests as idempotent;
- flushes only its own anchor and releases only its own PF enable token;
- attempts rollback immediately if rule loading or state persistence fails.

Such an adapter would reconcile expired state at the start of every run and emit a
containment-state event when it performs an automatic release. Its installed schedule would
need to run at least once per minute so the automatic-release bound is meaningful.

## Failure behavior

- Missing adapter, non-root execution, malformed state, DNS failure, PF command failure,
  expired action, or target mismatch results in no new containment.
- Provider command output is not returned to the SOC or written to telemetry.
- A partial isolate attempts to flush the dedicated anchor and release its PF reference.
- A failed release keeps the state file so a later reconciliation can retry.
- Reboot clears the runtime-only anchor; the adapter does not install persistent firewall rules.

## Deployment gates

No PF adapter code or fixture implementation is included in this release. Enabling this
design requires:

1. implementation plus focused parser, authorization, rollback, and command-boundary tests;
2. a second independent Cloudflare Access responder;
3. a root-owned state directory and a one-minute launchd schedule;
4. a console or other out-of-band recovery path;
5. a staged live exercise that proves ControlForge remains reachable during isolation;
6. an observed automatic or explicit release and restored normal connectivity.

Until those gates pass, the adapter remains disabled and production continues to fail closed
for active actions.
