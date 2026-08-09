# Alert fingerprint contract v1

Status: specified and cross-runtime conformance-tested. Cloud activates v1 only after migration
`0007_alert_replay_and_fingerprint.sql` installs semantic uniqueness on
`(tenant_id, rule_id, event_id)`; Standalone remains on its legacy identifier.

The canonical alert occurrence key is the ordered JSON array:

```json
["controlforge-alert", 1, "<tenant_id>", "<rule_id>", "<event_id>"]
```

Serialize it as UTF-8 JSON with no insignificant whitespace and hash the exact bytes with
SHA-256. The v1 `alert_id` is the first 32 lowercase hexadecimal characters of that digest.
Array framing is mandatory: joining values with a delimiter is ambiguous because rule and
event identifiers may contain colons.

The tenant identifier must be the stable tenant UUID created during bootstrap and preserved
by backup and restore. A standalone installation is still a tenant and must not substitute a
display name or hostname.

`rule_version`, rule content digest, title, severity, reasons, and detector build version are
not inputs. They are immutable decision provenance recorded alongside the alert. Re-evaluating
an event against another rule version creates a replay/evaluation record; it does not silently
change the alert occurrence identity.

## Legacy compatibility

- Python currently truncates SHA-256 to 20 hex characters and uses runtime-specific input
  strings.
- Cloud currently truncates SHA-256 to 32 hex characters over
  `tenant_id:rule_id:event_id`; case identifiers derive from that legacy alert identifier.

An adoption migration must preserve every existing alert and case identifier. Before emitting
v1 identifiers, persistence must enforce semantic uniqueness on tenant, rule, and event and
resolve a previously stored legacy occurrence instead of inserting a second alert. Existing
rows are never renamed in place.

Both runtimes expose a pure v1 fingerprint helper and validate it against shared vectors. Cloud
resolves the semantic occurrence after every insert, so an existing legacy alert ID and its case
links win over the new candidate. Migration fails closed rather than rewriting rows if historical
semantic duplicates are present. Standalone activation still requires an equivalent uniqueness
and legacy-resolution migration.
