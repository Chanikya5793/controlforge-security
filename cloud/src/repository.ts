import { hmacHex, sha256Hex } from "./security";
import type {
  AlertRow,
  AuthenticatedPrincipal,
  DetectionAlert,
  Env,
  StoredEvent,
} from "./types";
import type { SecurityEventInput } from "./schemas";

const EVENT_IDS_PER_QUEUE_MESSAGE = 50;
const QUEUE_MESSAGES_PER_SEND = 25;

function canonicalize(value: unknown): string {
  if (value === null || typeof value !== "object") return JSON.stringify(value);
  if (Array.isArray(value)) return `[${value.map(canonicalize).join(",")}]`;
  const record = value as Record<string, unknown>;
  return `{${Object.keys(record).sort().map((key) => `${JSON.stringify(key)}:${canonicalize(record[key])}`).join(",")}}`;
}

export class EventIdentityConflictError extends Error {
  constructor() {
    super("event identity conflicts with a previously accepted payload");
  }
}

export async function prepareAuditStatement(
  env: Env,
  tenantId: string,
  action: string,
  principal: AuthenticatedPrincipal,
  resourceType: string,
  resourceId: string,
  payload: Record<string, unknown>,
  requirePreviousChange = false,
): Promise<D1PreparedStatement> {
  const auditId = crypto.randomUUID();
  const createdAt = new Date().toISOString();
  const payloadJson = canonicalize(payload);
  const integrityHmac = await hmacHex(
    env.AUDIT_HMAC_SECRET,
    [auditId, tenantId, action, principal.type, principal.id, resourceType, resourceId, payloadJson, createdAt].join("\n"),
  );
  return env.DB.prepare(
    `INSERT INTO audit_log(
       audit_id, tenant_id, action, actor_type, actor_id, resource_type,
       resource_id, payload_json, integrity_hmac, created_at
     ) SELECT ?, ?, ?, ?, ?, ?, ?, ?, ?, ?
       ${requirePreviousChange ? "WHERE changes() = 1" : ""}`,
  ).bind(
    auditId, tenantId, action, principal.type, principal.id, resourceType,
    resourceId, payloadJson, integrityHmac, createdAt,
  );
}

interface NormalizedEvent {
  canonicalPayload: string;
  event: SecurityEventInput;
  occurrences: number;
  payloadSha256: string;
}

async function existingEventHashes(
  env: Env,
  tenantId: string,
  eventIds: string[],
): Promise<Map<string, string>> {
  const hashes = new Map<string, string>();
  for (let offset = 0; offset < eventIds.length; offset += 90) {
    const chunk = eventIds.slice(offset, offset + 90);
    if (chunk.length === 0) continue;
    const placeholders = chunk.map(() => "?").join(", ");
    const existing = await env.DB.prepare(
      `SELECT event_id, payload_sha256 FROM events
        WHERE tenant_id = ? AND event_id IN (${placeholders})`,
    ).bind(tenantId, ...chunk).all<{ event_id: string; payload_sha256: string }>();
    existing.results.forEach((row) => hashes.set(row.event_id, row.payload_sha256));
  }
  return hashes;
}

export async function persistEvents(
  env: Env,
  tenantId: string,
  events: SecurityEventInput[],
): Promise<{ accepted: string[]; duplicates: string[] }> {
  const accepted: string[] = [];
  const duplicates: string[] = [];
  const receivedAt = new Date().toISOString();
  const normalizedInput = await Promise.all(events.map(async (event) => {
    const canonicalPayload = canonicalize(event);
    if (new TextEncoder().encode(canonicalPayload).byteLength > 64_000) {
      throw new Error(`event ${event.event_id} exceeds the 64 KB normalized limit`);
    }
    return {
      event,
      canonicalPayload,
      occurrences: 1,
      payloadSha256: await sha256Hex(canonicalPayload),
    };
  }));

  const uniqueById = new Map<string, NormalizedEvent>();
  for (const normalized of normalizedInput) {
    const prior = uniqueById.get(normalized.event.event_id);
    if (!prior) {
      uniqueById.set(normalized.event.event_id, normalized);
      continue;
    }
    if (prior.payloadSha256 !== normalized.payloadSha256) {
      throw new EventIdentityConflictError();
    }
    prior.occurrences += 1;
  }
  const normalizedEvents = [...uniqueById.values()];
  const existingHashes = await existingEventHashes(
    env,
    tenantId,
    normalizedEvents.map(({ event }) => event.event_id),
  );
  const candidates: NormalizedEvent[] = [];
  for (const normalized of normalizedEvents) {
    const existingHash = existingHashes.get(normalized.event.event_id);
    if (existingHash === undefined) {
      candidates.push(normalized);
      continue;
    }
    if (existingHash !== normalized.payloadSha256) throw new EventIdentityConflictError();
    duplicates.push(...Array<string>(normalized.occurrences).fill(normalized.event.event_id));
  }

  const raced: NormalizedEvent[] = [];
  for (let offset = 0; offset < candidates.length; offset += 100) {
    const chunk = candidates.slice(offset, offset + 100);
    let results: D1Result[];
    try {
      results = await env.DB.batch(chunk.map(({ event, payloadSha256 }) => (
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
    } catch (error) {
      if (error instanceof Error && error.message.includes("conflicting event payload")) {
        throw new EventIdentityConflictError();
      }
      throw error;
    }
    results.forEach((result, index) => {
      const normalized = chunk[index];
      if (!normalized) throw new Error("D1 batch result count does not match event count");
      const eventId = normalized.event.event_id;
      if (result.meta.changes === 1) {
        accepted.push(eventId);
        duplicates.push(...Array<string>(normalized.occurrences - 1).fill(eventId));
      } else {
        raced.push(normalized);
      }
    });
  }

  if (raced.length > 0) {
    const racedHashes = await existingEventHashes(
      env,
      tenantId,
      raced.map(({ event }) => event.event_id),
    );
    for (const normalized of raced) {
      if (racedHashes.get(normalized.event.event_id) !== normalized.payloadSha256) {
        throw new EventIdentityConflictError();
      }
      duplicates.push(...Array<string>(normalized.occurrences).fill(normalized.event.event_id));
    }
  }

  const pendingDuplicates: string[] = [];
  const uniqueDuplicates = [...new Set(duplicates)];
  // D1 limits bound SQL parameters; leave room for tenant_id alongside event IDs.
  for (let offset = 0; offset < uniqueDuplicates.length; offset += 90) {
    const chunk = uniqueDuplicates.slice(offset, offset + 90);
    const placeholders = chunk.map(() => "?").join(", ");
    const pending = await env.DB.prepare(
      `SELECT event_id FROM events
       WHERE tenant_id = ? AND processed_at IS NULL AND event_id IN (${placeholders})`,
    ).bind(tenantId, ...chunk).all<{ event_id: string }>();
    pendingDuplicates.push(...pending.results.map(({ event_id: eventId }) => eventId));
  }

  await enqueueEventIds(env, tenantId, [...accepted, ...pendingDuplicates]);
  return { accepted, duplicates };
}

export async function enqueueEventIds(
  env: Env,
  tenantId: string,
  eventIds: string[],
): Promise<void> {
  const messages = [];
  for (let offset = 0; offset < eventIds.length; offset += EVENT_IDS_PER_QUEUE_MESSAGE) {
    messages.push({
      body: {
        tenantId,
        eventIds: eventIds.slice(offset, offset + EVENT_IDS_PER_QUEUE_MESSAGE),
        attemptId: crypto.randomUUID(),
      },
      contentType: "json",
    } as const);
  }
  for (let offset = 0; offset < messages.length; offset += QUEUE_MESSAGES_PER_SEND) {
    await env.EVENT_QUEUE.sendBatch(messages.slice(offset, offset + QUEUE_MESSAGES_PER_SEND));
  }
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
  event: StoredEvent,
): Promise<void> {
  const entity = event.device_id ? `device:${event.device_id}` : `actor:${alert.actor}`;
  const semanticKey = await sha256Hex(
    `${tenantId}:case-semantic:v1:${alert.ruleId}:${entity}`,
  );
  const alertInsert = env.DB.prepare(
    `INSERT OR IGNORE INTO alerts(
       tenant_id, alert_id, event_id, rule_id, title, severity, actor,
       reasons_json, tags_json, rule_version, rule_digest, rule_snapshot_json,
       fingerprint_version, detector_version, evidence_json, created_at
     ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
  ).bind(
    tenantId, alert.alertId, alert.eventId, alert.ruleId, alert.title, alert.severity,
    alert.actor,
    JSON.stringify(alert.reasons),
    JSON.stringify(alert.tags),
    alert.ruleVersion,
    alert.ruleDigest,
    JSON.stringify(alert.ruleSnapshot),
    alert.fingerprintVersion,
    alert.detectorVersion,
    JSON.stringify(alert.evidence),
    alert.createdAt,
  );
  const alertAudit = await prepareAuditStatement(
    env,
    tenantId,
    "alert.created",
    { id: "detector", type: "collector", tenantId },
    "alert",
    alert.alertId,
    {
      rule_id: alert.ruleId,
      rule_version: alert.ruleVersion,
      rule_digest: alert.ruleDigest,
      fingerprint_version: alert.fingerprintVersion,
      severity: alert.severity,
    },
    true,
  );
  const [inserted] = await env.DB.batch([alertInsert, alertAudit]);
  if (!inserted) throw new Error("alert persistence returned no result");
  const occurrence = await env.DB.prepare(
    `SELECT alert_id FROM alerts
      WHERE tenant_id = ? AND rule_id = ? AND event_id = ?`,
  ).bind(tenantId, alert.ruleId, alert.eventId).first<{ alert_id: string }>();
  if (!occurrence) {
    throw new Error("semantic alert occurrence was not persisted");
  }
  const resolvedAlertId = occurrence.alert_id;
  if (inserted.meta.changes !== 1 || resolvedAlertId !== alert.alertId) {
    const existingLink = await env.DB.prepare(
      "SELECT case_id FROM case_alerts WHERE tenant_id = ? AND alert_id = ? LIMIT 1",
    ).bind(tenantId, resolvedAlertId).first<{ case_id: string }>();
    if (existingLink) return;
  }

  const now = new Date().toISOString();
  await env.DB.prepare(
    `INSERT OR IGNORE INTO cases(
       tenant_id, case_id, semantic_key, title, priority, status, opened_at, updated_at
     ) VALUES (?, ?, ?, ?, ?, 'open', ?, ?)`,
  ).bind(
    tenantId,
    crypto.randomUUID(),
    semanticKey,
    alert.title,
    casePriority(alert.severity),
    now,
    now,
  ).run();
  const activeCase = await env.DB.prepare(
    `SELECT case_id FROM cases
      WHERE tenant_id = ? AND semantic_key = ? AND status != 'closed'`,
  ).bind(tenantId, semanticKey).first<{ case_id: string }>();
  if (!activeCase) throw new Error("active semantic case was not persisted");
  const caseId = activeCase.case_id;
  await env.DB.batch([
    env.DB.prepare(
      `INSERT OR IGNORE INTO case_alerts(tenant_id, case_id, alert_id, linked_at)
       VALUES (?, ?, ?, ?)`,
    ).bind(tenantId, caseId, resolvedAlertId, now),
    env.DB.prepare(
      `UPDATE cases
          SET updated_at = ?,
              priority = CASE
                WHEN priority = 'critical' OR ? = 'critical' THEN 'critical'
                WHEN priority = 'high' OR ? = 'high' THEN 'high'
                WHEN priority = 'medium' OR ? = 'medium' THEN 'medium'
                ELSE 'low'
              END
        WHERE tenant_id = ? AND case_id = ?`,
    ).bind(
      now,
      casePriority(alert.severity),
      casePriority(alert.severity),
      casePriority(alert.severity),
      tenantId,
      caseId,
    ),
  ]);
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

export async function markEventsProcessed(
  db: D1Database,
  events: Array<{ tenant_id: string; event_id: string }>,
): Promise<void> {
  const processedAt = new Date().toISOString();
  for (let offset = 0; offset < events.length; offset += 100) {
    await db.batch(events.slice(offset, offset + 100).map((event) => db.prepare(
      "UPDATE events SET processed_at = ?, processing_error = NULL WHERE tenant_id = ? AND event_id = ?",
    ).bind(processedAt, event.tenant_id, event.event_id)));
  }
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
    rule_version: row.rule_version,
    rule_digest: row.rule_digest,
    rule_snapshot: row.rule_snapshot_json === null
      ? null
      : JSON.parse(row.rule_snapshot_json) as unknown,
    fingerprint_version: row.fingerprint_version,
    detector_version: row.detector_version,
    evidence: JSON.parse(row.evidence_json) as unknown,
    created_at: row.created_at,
  };
}
