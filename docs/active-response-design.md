# Active response design

## Scope

ControlForge implements a code-level active-response service and a disabled-by-default adapter
for reversible network containment on a managed macOS endpoint. The adapter is not enabled or
physically exercised on an installed endpoint in this milestone. CrowdStrike is not enabled
because this deployment has no licensed Falcon tenant, API client, or installed sensor. The
platform must not claim either physical containment path without independently verified
prerequisites and a live exercise.

The deterministic detector and human approval boundary remain unchanged. AI may recommend
an investigation step, but cannot propose, approve, dispatch, or execute containment.

## Authorization and dispatch

1. An authenticated responder or administrator proposes `isolate_endpoint` or
   `release_endpoint` for an exact device ID.
2. A different authenticated responder or administrator approves the action before expiry.
3. The signed collector for that same device retrieves the approved action.
4. The collector validates the action type, risk level, target type, target ID, and expiry.
5. The collector may invoke the macOS PF adapter only when that adapter is explicitly enabled;
   otherwise isolation fails closed. Release and expiry reconciliation remain available for
   ControlForge-owned state so disabling the adapter cannot strand known containment.
6. The device returns only a bounded status, summary, and evidence list. Identical result
   retries are idempotent and conflicting results fail closed.

The proposer cannot approve their own active action. An operator, browser automation, or AI
agent controlled by the proposer is not an independent second responder.

## Implemented macOS PF code boundary

The adapter:

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

Because the adapter deliberately does not flush global PF state, a connection established
before containment may continue until that state expires or the owning process closes it.
The current code-level adapter therefore must not be described as complete network isolation;
the physical acceptance exercise must measure both new and pre-existing flows.

The adapter reconciles expired state before regular collector probes and emits a
containment-state event when it performs an automatic release. Its installed schedule would
need to run at least once per minute so the automatic-release bound is meaningful.

The acceptance harness supplies a recording runner and documentation-only management IPs. It
therefore proves command construction and state transitions without invoking `/sbin/pfctl`,
changing the host firewall, or performing DNS. Focused tests cover command failures, partial
rollback, retained recovery state, deletion failures, and disabled-configuration recovery.

## Failure behavior

- Missing adapter, non-root execution, malformed state, DNS failure, PF command failure,
  expired action, or target mismatch results in no new containment.
- Provider command output is not returned to the SOC or written to telemetry.
- A partial isolate attempts to flush the dedicated anchor and release its PF reference.
- A failed release keeps the state file so a later reconciliation can retry.
- Reboot clears the runtime-only anchor; the adapter does not install persistent firewall rules.
- A root console can run `agent-containment-status` without exposing PF ownership material and
  can invoke confirmation-gated `agent-containment-release`. The recovery command first disables
  collector polling, proves the daemon is stopped, releases only the owned anchor/token, and keeps
  the collector disabled until an operator explicitly reactivates it after resolving the action.
- Malformed or untrusted ownership state is never guessed or deleted by the recovery command.

## Deployment gates

The code-level parser, authorization, expiry/race, rollback, fixed-command, state, and
reconciliation tests pass. Enabling this design for a release still requires:

1. two independent real human responders with hardware-backed passkeys;
2. installed evidence for the root-owned state directory and at-least-once-per-minute
   supervision;
3. physical proof of the implemented local-console recovery path, including the intentionally
   disabled collector state and explicit reactivation after the action is resolved;
4. a staged live exercise that proves ControlForge remains reachable during isolation and
   records expected packet and existing-connection behavior;
5. observed explicit and automatic release with restored normal connectivity;
6. clean-install, upgrade, disabled-adapter recovery, and uninstall acceptance on a supported
   Mac.

Until those physical gates pass, the adapter remains disabled by default, release readiness
remains false, and ControlForge must describe active response as code-level governance and
adapter evidence rather than an operational containment capability.
