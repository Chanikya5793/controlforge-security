import { sha256Hex } from "./security";
import type { DetectionAlert, Severity, StoredEvent } from "./types";

type Attributes = Record<string, unknown>;

interface CountRow {
  event_count: number;
  total_bytes: number;
  distinct_accounts?: number;
}

interface PreviousLoginRow {
  occurred_at: string;
  attributes_json: string;
}

interface PreviousSessionRow {
  source_ip: string | null;
}

function attributes(event: StoredEvent): Attributes {
  const parsed: unknown = JSON.parse(event.attributes_json);
  return typeof parsed === "object" && parsed !== null && !Array.isArray(parsed)
    ? parsed as Attributes
    : {};
}

function text(value: unknown): string {
  return typeof value === "string" ? value : "";
}

function endsWithOne(value: unknown, suffixes: string[]): boolean {
  const normalized = text(value).toLowerCase();
  return suffixes.some((suffix) => normalized.endsWith(suffix));
}

function includesOne(value: unknown, needles: string[]): boolean {
  const normalized = text(value).toLowerCase();
  return needles.some((needle) => normalized.includes(needle));
}

async function createAlert(
  event: StoredEvent,
  ruleId: string,
  title: string,
  severity: Severity,
  reasons: string[],
  tags: string[],
): Promise<DetectionAlert> {
  return {
    alertId: (await sha256Hex(`${event.tenant_id}:${ruleId}:${event.event_id}`)).slice(0, 32),
    ruleId,
    title,
    severity,
    eventId: event.event_id,
    actor: event.actor,
    reasons,
    tags,
    createdAt: event.occurred_at,
  };
}

export async function detectStatelessEvent(event: StoredEvent): Promise<DetectionAlert[]> {
  const attrs = attributes(event);
  const alerts: DetectionAlert[] = [];

  if (
    event.event_type === "endpoint_control_status" &&
    ["failed", "degraded"].includes(text(attrs.status).toLowerCase())
  ) {
    const failed = text(attrs.status).toLowerCase() === "failed";
    alerts.push(await createAlert(
      event,
      "CF-CONTROL-001",
      failed ? "Required endpoint security control failed" : "Endpoint security control degraded",
      failed ? "high" : "medium",
      [
        `endpoint control ${event.target ?? "unknown"} reported ${text(attrs.status).toLowerCase()}`,
        `installed=${String(attrs.installed)} running=${String(attrs.running)}`,
      ],
      ["control-assurance", "endpoint-security", "defense-evasion"],
    ));
  }

  if (
    event.event_type === "santa_execution" &&
    text(attrs.decision).toUpperCase() === "DECISION_DENY"
  ) {
    alerts.push(await createAlert(
      event,
      "CF-MACOS-001",
      "Santa denied executable launch",
      "high",
      [
        `Santa denied ${text(attrs.process_path) || event.target || "unknown executable"}`,
        `reason=${text(attrs.reason) || "unknown"} mode=${text(attrs.mode) || "unknown"}`,
      ],
      ["attack.execution", "endpoint-security", "north-pole-security-santa"],
    ));
  }

  if (event.event_type === "santa_gatekeeper_override") {
    alerts.push(await createAlert(
      event,
      "CF-MACOS-002",
      "macOS Gatekeeper policy override",
      "high",
      [`Gatekeeper policy was overridden for ${text(attrs.target_path) || event.target || "a file"}`],
      ["attack.defense-evasion", "attack.t1553.001", "endpoint-security", "north-pole-security-santa"],
    ));
  }

  if (event.event_type === "santa_xprotect") {
    alerts.push(await createAlert(
      event,
      "CF-MACOS-003",
      "XProtect malware event observed by Santa",
      "critical",
      [
        `XProtect ${text(attrs.xprotect_event) || "event"}: ${text(attrs.malware_identifier) || "unidentified malware"}`,
        `target=${text(attrs.target_path) || event.target || "unknown"}`,
      ],
      ["malware", "endpoint-security", "north-pole-security-santa"],
    ));
  }

  if (
    event.event_type === "process_start" &&
    endsWithOne(attrs.process_name, ["powershell.exe", "pwsh.exe"]) &&
    includesOne(attrs.command_line, [" -enc ", " -encodedcommand "])
  ) {
    alerts.push(await createAlert(event, "CF-ENDPOINT-001", "Encoded PowerShell execution", "high", [
      "PowerShell-compatible process name matched",
      "command line contains an encoded-command flag",
    ], ["attack.execution", "attack.t1059.001", "endpoint-security"]));
  }

  if (
    event.event_type === "process_start" &&
    endsWithOne(attrs.parent_process_name, ["winword.exe", "excel.exe", "powerpnt.exe", "outlook.exe"]) &&
    endsWithOne(attrs.process_name, [
      "powershell.exe", "pwsh.exe", "cmd.exe", "mshta.exe", "rundll32.exe", "wscript.exe", "cscript.exe",
    ])
  ) {
    alerts.push(await createAlert(
      event,
      "CF-ENDPOINT-002",
      "Office application spawned a script or living-off-the-land binary",
      "high",
      ["Office-family parent process matched", "script or proxy-execution child process matched"],
      ["attack.execution", "attack.t1204.002", "endpoint-security"],
    ));
  }

  if (
    event.event_type === "process_start" &&
    endsWithOne(attrs.process_name, ["procdump.exe", "procdump64.exe", "rundll32.exe"]) &&
    includesOne(attrs.command_line, ["lsass"]) &&
    includesOne(attrs.command_line, ["minidump", " -ma "])
  ) {
    alerts.push(await createAlert(event, "CF-ENDPOINT-003", "Suspected LSASS credential dumping", "critical", [
      "credential-dumping process pattern matched",
      "command line references LSASS and a memory-dump operation",
    ], ["attack.credential-access", "attack.t1003.001", "endpoint-security"]));
  }

  if (
    event.event_type === "registry_value_set" &&
    includesOne(attrs.registry_path, [
      "\\software\\microsoft\\windows\\currentversion\\run\\",
      "\\software\\microsoft\\windows\\currentversion\\runonce\\",
    ])
  ) {
    alerts.push(await createAlert(event, "CF-ENDPOINT-004", "User-level Run key persistence", "medium", [
      "registry write targets a Run or RunOnce persistence location",
    ], ["attack.persistence", "attack.t1060", "endpoint-security"]));
  }

  if (
    event.event_type === "edge_http_request" &&
    includesOne(attrs.request_path, ["/.env", "/.git/config", "/server-status", "/actuator/env", "/wp-admin"])
  ) {
    alerts.push(await createAlert(event, "CF-EDGE-001", "Sensitive path discovery at the application edge", "medium", [
      "request path targets a commonly exposed secret, metadata, or administrative location",
    ], ["edge-security", "attack.discovery", "attack.t1083"]));
  }

  if (
    event.event_type === "email_received" &&
    text(attrs.dmarc).toLowerCase() === "fail" &&
    (
      includesOne(attrs.url_path, ["login", "verify", "password"]) ||
      /(?:xn--|(?:\d{1,3}\.){3}\d{1,3})/iu.test(text(attrs.sender_domain))
    )
  ) {
    alerts.push(await createAlert(event, "CF-EMAIL-001", "High-confidence phishing email indicators", "high", [
      "DMARC authentication failed",
      "credential-themed link or lookalike sender domain matched",
    ], ["phishing", "email-security", "social-engineering"]));
  }

  if (
    event.event_type === "privileged_role_grant" &&
    ["administrator", "security-admin", "database-owner"].includes(text(attrs.role).toLowerCase()) &&
    !text(attrs.change_ticket).toUpperCase().startsWith("CHG-")
  ) {
    alerts.push(await createAlert(
      event,
      "CF-IDENTITY-002",
      "Privileged role granted outside approved workflow",
      "critical",
      ["high-impact role matched", "approved CHG- workflow reference is absent"],
      ["identity", "privilege-escalation", "insider-risk"],
    ));
  }
  return alerts;
}

function haversineKm(lat1: number, lon1: number, lat2: number, lon2: number): number {
  const toRadians = (value: number): number => value * Math.PI / 180;
  const deltaLatitude = toRadians(lat2 - lat1);
  const deltaLongitude = toRadians(lon2 - lon1);
  const first = toRadians(lat1);
  const second = toRadians(lat2);
  const value = Math.sin(deltaLatitude / 2) ** 2 +
    Math.cos(first) * Math.cos(second) * Math.sin(deltaLongitude / 2) ** 2;
  return 6_371 * 2 * Math.atan2(Math.sqrt(value), Math.sqrt(1 - value));
}

async function statefulDetections(event: StoredEvent, db: D1Database): Promise<DetectionAlert[]> {
  const attrs = attributes(event);
  const alerts: DetectionAlert[] = [];

  if (event.event_type === "sensitive_data_access" && typeof attrs.bytes === "number") {
    const aggregate = await db.prepare(
      `SELECT COUNT(*) AS event_count,
              COALESCE(SUM(CAST(json_extract(attributes_json, '$.bytes') AS INTEGER)), 0) AS total_bytes
         FROM events
        WHERE tenant_id = ? AND actor = ? AND event_type = 'sensitive_data_access'
          AND julianday(occurred_at) BETWEEN julianday(?) - (15.0 / 1440.0) AND julianday(?)`,
    ).bind(event.tenant_id, event.actor, event.occurred_at, event.occurred_at).first<CountRow>();
    if (aggregate && (aggregate.event_count >= 10 || aggregate.total_bytes >= 50_000_000)) {
      alerts.push(await createAlert(event, "CF-INSIDER-001", "Unusual sensitive-data access volume", "high", [
        `${String(aggregate.event_count)} access events within 15m`,
        `${String(aggregate.total_bytes)} bytes accessed`,
      ], ["insider-risk", "financial-data", "behavioral-analytics"]));
    }
  }

  if (
    event.event_type === "authentication_success" &&
    typeof attrs.latitude === "number" && typeof attrs.longitude === "number"
  ) {
    const previous = await db.prepare(
      `SELECT occurred_at, attributes_json FROM events
        WHERE tenant_id = ? AND actor = ? AND event_type = 'authentication_success'
          AND julianday(occurred_at) < julianday(?)
        ORDER BY julianday(occurred_at) DESC LIMIT 1`,
    ).bind(event.tenant_id, event.actor, event.occurred_at).first<PreviousLoginRow>();
    if (previous) {
      const previousAttrs: unknown = JSON.parse(previous.attributes_json);
      if (
        typeof previousAttrs === "object" && previousAttrs !== null &&
        "latitude" in previousAttrs && "longitude" in previousAttrs &&
        typeof previousAttrs.latitude === "number" && typeof previousAttrs.longitude === "number"
      ) {
        const hours = (Date.parse(event.occurred_at) - Date.parse(previous.occurred_at)) / 3_600_000;
        const distance = haversineKm(
          previousAttrs.latitude,
          previousAttrs.longitude,
          attrs.latitude,
          attrs.longitude,
        );
        const speed = distance / hours;
        if (hours > 0 && speed > 900) {
          alerts.push(await createAlert(event, "CF-IDENTITY-001", "Impossible-travel authentication", "high", [
            `calculated travel velocity ${speed.toFixed(0)} km/h`,
            `distance ${distance.toFixed(0)} km over ${hours.toFixed(2)}h`,
          ], ["identity", "account-takeover", "behavioral-analytics"]));
        }
      }
    }
  }

  if (event.event_type === "edge_auth_failure" && event.source_ip) {
    const aggregate = await db.prepare(
      `SELECT COUNT(*) AS event_count, COUNT(DISTINCT lower(actor)) AS distinct_accounts,
              0 AS total_bytes
         FROM events
        WHERE tenant_id = ? AND source_ip = ? AND event_type = 'edge_auth_failure'
          AND julianday(occurred_at) BETWEEN julianday(?) - (5.0 / 1440.0) AND julianday(?)`,
    ).bind(event.tenant_id, event.source_ip, event.occurred_at, event.occurred_at).first<CountRow>();
    if (aggregate && aggregate.event_count >= 20 && (aggregate.distinct_accounts ?? 0) >= 10) {
      alerts.push(await createAlert(
        event,
        "CF-EDGE-002",
        "Credential-stuffing pattern at the authentication edge",
        "high",
        [
          `${String(aggregate.event_count)} failed authentications from ${event.source_ip}`,
          `${String(aggregate.distinct_accounts ?? 0)} distinct accounts within 5m`,
        ],
        ["edge-security", "credential-access", "account-takeover", "attack.t1110"],
      ));
    }
  }

  const sessionHash = text(attrs.session_id_hash);
  if (event.event_type === "edge_session_use" && event.source_ip && sessionHash.length >= 12) {
    const previous = await db.prepare(
      `SELECT source_ip FROM events
        WHERE tenant_id = ? AND event_type = 'edge_session_use'
          AND json_extract(attributes_json, '$.session_id_hash') = ?
          AND julianday(occurred_at) < julianday(?)
          AND julianday(occurred_at) >= julianday(?) - (10.0 / 1440.0)
        ORDER BY julianday(occurred_at) DESC LIMIT 1`,
    ).bind(event.tenant_id, sessionHash, event.occurred_at, event.occurred_at)
      .first<PreviousSessionRow>();
    if (previous?.source_ip && previous.source_ip !== event.source_ip) {
      alerts.push(await createAlert(event, "CF-EDGE-003", "Possible session replay across source addresses", "high", [
        `session hash reused from ${previous.source_ip} and ${event.source_ip}`,
        "reuse occurred within 10m",
      ], ["edge-security", "session-hijacking", "account-takeover"]));
    }
  }
  return alerts;
}

export async function detectEvent(event: StoredEvent, db: D1Database): Promise<DetectionAlert[]> {
  return [
    ...await detectStatelessEvent(event),
    ...await statefulDetections(event, db),
  ];
}
