import { hmacHex, sha256Hex } from "./security";
import type {
  AlertRow,
  AuthenticatedPrincipal,
  DetectionAlert,
  Env,
  StoredEvent,
} from "./types";
import type { SecurityEventInput } from "./schemas";

function canonicalize(value: unknown): string {
  if (value === null || typeof value !== "object") return JSON.stringify(value);
  if (Array.isArray(value)) return `[${value.map(canonicalize).join(",")}]`;
  const record = value as Record<string, unknown>;
  return `{${Object.keys(record).sort().map((key) => `${JSON.stringify(key)}:${canonicalize(record[key])}`).join(",")}}`;
}

export async function appendAudit(
  env: Env,
  tenantId: string,
  action: string,
  principal: AuthenticatedPrincipal,
  resourceType: string,
  resourceId: string,
  payload: Record<string, unknown>,
): Promise<void> {
  const auditId = crypto.randomUUID();
  const createdAt = new Date().toISOString();
  const payloadJson = canonicalize(payload);
  const integrityHmac = await hmacHex(
    env.AUDIT_HMAC_SECRET,
    [auditId, tenantId, action, principal.type, principal.id, resourceType, resourceId, payloadJson, createdAt].join("\n"),
  );
  await env.DB.prepare(
    `INSERT INTO audit_log(
       audit_id, tenant_id, action, actor_type, actor_id, resource_type,
       resource_id, payload_json, integrity_hmac, created_at
     ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
  ).bind(
    auditId, tenantId, action, principal.type, principal.id, resourceType,
    resourceId, payloadJson, integrityHmac, createdAt,
  ).run();
}

export async function persistEvents(
  env: Env,
  tenantId: string,
  events: SecurityEventInput[],
): Promise<{ accepted: string[]; duplicates: string[] }> {
  const accepted: string[] = [];
  const duplicates: string[] = [];
  const receivedAt = new Date().toISOString();
  const normalizedEvents = await Promise.all(events.map(async (event) => {
    const canonicalPayload = canonicalize(event);
    if (new TextEncoder().encode(canonicalPayload).byteLength > 64_000) {
      throw new Error(`event ${event.event_id} exceeds the 64 KB normalized limit`);
    }
    return {
      event,
      canonicalPayload,
      payloadSha256: await sha256Hex(canonicalPayload),
    };
  }));

  for (let offset = 0; offset < normalizedEvents.length; offset += 100) {
    const chunk = normalizedEvents.slice(offset, offset + 100);
    const results = await env.DB.batch(chunk.map(({ event, payloadSha256 }) => (
      env.DB.prepare(
      `INSERT OR IGNORE INTO events(
         tenant_id, event_id, event_type, occurred_at, received_at, actor,
         source_ip, target, device_id, attributes_json, payload_sha256
       ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
      ).bind(
        tenantId,
        event.event_id,
        event.event_type,
        event.timestamp,
        receivedAt,
        event.actor,
        event.source_ip ?? null,
        event.target ?? null,
        event.device_id ?? null,
        canonicalize(event.attributes),
        payloadSha256,
      )
    )));
    results.forEach((result, index) => {
      const normalized = chunk[index];
      if (!normalized) throw new Error("D1 batch result count does not match event count");
      const eventId = normalized.event.event_id;
      if (result.meta.changes === 1) accepted.push(eventId);
      else duplicates.push(eventId);
    });
  }

  const pendingDuplicates: string[] = [];
  // D1 limits bound SQL parameters; leave room for tenant_id alongside event IDs.
  for (let offset = 0; offset < duplicates.length; offset += 90) {
    const chunk = duplicates.slice(offset, offset + 90);
    const placeholders = chunk.map(() => "?").join(", ");
    const pending = await env.DB.prepare(
      `SELECT event_id FROM events
       WHERE tenant_id = ? AND processed_at IS NULL AND event_id IN (${placeholders})`,
    ).bind(tenantId, ...chunk).all<{ event_id: string }>();
    pendingDuplicates.push(...pending.results.map(({ event_id: eventId }) => eventId));
  }

  const queueEventIds = [...accepted, ...pendingDuplicates];
  for (let offset = 0; offset < queueEventIds.length; offset += 100) {
    await env.EVENT_QUEUE.sendBatch(queueEventIds.slice(offset, offset + 100).map((eventId) => ({
      body: { tenantId, eventId, attemptId: crypto.randomUUID() },
      contentType: "json",
    })));
  }
  return { accepted, duplicates };
}

export async function loadEvent(
  db: D1Database,
  tenantId: string,
  eventId: string,
): Promise<StoredEvent | null> {
  return db.prepare(
    "SELECT * FROM events WHERE tenant_id = ? AND event_id = ?",
  ).bind(tenantId, eventId).first<StoredEvent>();
}

function casePriority(severity: DetectionAlert["severity"]): "low" | "medium" | "high" | "critical" {
  if (severity === "critical") return "critical";
  if (severity === "high") return "high";
  if (severity === "medium") return "medium";
  return "low";
}

export async function persistAlertAndCase(
  env: Env,
  tenantId: string,
  alert: DetectionAlert,
): Promise<void> {
  const caseId = (await sha256Hex(`${tenantId}:case:${alert.alertId}`)).slice(0, 32);
  const inserted = await env.DB.prepare(
    `INSERT OR IGNORE INTO alerts(
       tenant_id, alert_id, event_id, rule_id, title, severity, actor,
       reasons_json, tags_json, created_at
     ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
  ).bind(
    tenantId, alert.alertId, alert.eventId, alert.ruleId, alert.title, alert.severity,
    alert.actor, JSON.stringify(alert.reasons), JSON.stringify(alert.tags), alert.createdAt,
  ).run();
  if (inserted.meta.changes !== 1) return;

  const now = new Date().toISOString();
  await env.DB.batch([
    env.DB.prepare(
      `INSERT OR IGNORE INTO cases(
         tenant_id, case_id, title, priority, status, opened_at, updated_at
       ) VALUES (?, ?, ?, ?, 'open', ?, ?)`,
    ).bind(tenantId, caseId, alert.title, casePriority(alert.severity), now, now),
    env.DB.prepare(
      "INSERT OR IGNORE INTO case_alerts(tenant_id, case_id, alert_id, linked_at) VALUES (?, ?, ?, ?)",
    ).bind(tenantId, caseId, alert.alertId, now),
  ]);
  await appendAudit(
    env,
    tenantId,
    "alert.created",
    { id: "detector", type: "collector", tenantId },
    "alert",
    alert.alertId,
    { rule_id: alert.ruleId, severity: alert.severity, case_id: caseId },
  );
}

export async function markEventProcessed(
  db: D1Database,
  tenantId: string,
  eventId: string,
  error?: string,
): Promise<void> {
  await db.prepare(
    "UPDATE events SET processed_at = ?, processing_error = ? WHERE tenant_id = ? AND event_id = ?",
  ).bind(error ? null : new Date().toISOString(), error ?? null, tenantId, eventId).run();
}

export function mapAlert(row: AlertRow): Record<string, unknown> {
  return {
    alert_id: row.alert_id,
    event_id: row.event_id,
    rule_id: row.rule_id,
    title: row.title,
    severity: row.severity,
    actor: row.actor,
    reasons: JSON.parse(row.reasons_json) as unknown,
    tags: JSON.parse(row.tags_json) as unknown,
    created_at: row.created_at,
  };
}
