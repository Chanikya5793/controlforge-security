import { mapAlert } from "./repository";
import type { AlertRow } from "./types";

const SEVERITY_RANK: Readonly<Record<string, number>> = {
  informational: 0,
  low: 1,
  medium: 2,
  high: 3,
  critical: 4,
};

function parseStoredJson(value: string | null): unknown {
  if (value === null) return null;
  try {
    return JSON.parse(value) as unknown;
  } catch {
    return null;
  }
}

function count(result: D1Result | undefined): number {
  if (!result) return 0;
  const row = result.results[0] as { count?: number } | undefined;
  return row?.count ?? 0;
}

export async function loadDashboardSummary(
  db: D1Database,
  tenantId: string,
  now: string,
): Promise<Record<string, number | string | null>> {
  const [events, alerts, critical, cases, pending, errors, devices, stale, latest, approvals]
    = await db.batch([
      db.prepare(
        "SELECT COUNT(*) AS count FROM events WHERE tenant_id = ? AND julianday(received_at) >= julianday('now') - 1",
      ).bind(tenantId),
      db.prepare(
        "SELECT COUNT(*) AS count FROM alerts WHERE tenant_id = ? AND julianday(created_at) >= julianday('now') - 1",
      ).bind(tenantId),
      db.prepare(
        "SELECT COUNT(*) AS count FROM cases WHERE tenant_id = ? AND priority = 'critical' AND status != 'closed'",
      ).bind(tenantId),
      db.prepare(
        "SELECT COUNT(*) AS count FROM cases WHERE tenant_id = ? AND status != 'closed'",
      ).bind(tenantId),
      db.prepare(
        `SELECT COUNT(*) AS count FROM events
          WHERE tenant_id = ? AND processed_at IS NULL AND processing_error IS NULL`,
      ).bind(tenantId),
      db.prepare(
        "SELECT COUNT(*) AS count FROM events WHERE tenant_id = ? AND processing_error IS NOT NULL",
      ).bind(tenantId),
      db.prepare(
        "SELECT COUNT(*) AS count FROM devices WHERE tenant_id = ? AND revoked_at IS NULL",
      ).bind(tenantId),
      db.prepare(
        `SELECT COUNT(*) AS count FROM devices
          WHERE tenant_id = ? AND revoked_at IS NULL
            AND (last_seen_at IS NULL
              OR julianday(last_seen_at) < julianday('now') - (15.0 / 1440.0))`,
      ).bind(tenantId),
      db.prepare("SELECT MAX(received_at) AS timestamp FROM events WHERE tenant_id = ?")
        .bind(tenantId),
      db.prepare(
        `SELECT COUNT(*) AS count FROM response_actions
          WHERE tenant_id = ? AND status = 'proposed' AND expires_at > ?`,
      ).bind(tenantId, now),
    ]);
  const latestRow = latest?.results[0] as { timestamp?: string | null } | undefined;
  return {
    events_24h: count(events),
    alerts_24h: count(alerts),
    critical_open: count(critical),
    open_cases: count(cases),
    pending_events: count(pending),
    processing_errors: count(errors),
    active_devices: count(devices),
    stale_devices: count(stale),
    last_event_at: latestRow?.timestamp ?? null,
    pending_approvals: count(approvals),
  };
}

interface CaseQueueRow {
  case_id: string;
  semantic_key: string | null;
  title: string;
  priority: "low" | "medium" | "high" | "critical";
  status: string;
  opened_at: string;
  updated_at: string;
  alert_id: string;
  rule_id: string;
  actor: string;
  tags_json: string;
  alert_created_at: string;
  event_type: string;
  device_id: string | null;
  assignee_principal_id: string | null;
}

interface MutableQueueGroup {
  case_id: string;
  case_ids: Set<string>;
  title: string;
  priority: "low" | "medium" | "high" | "critical";
  status: string;
  opened_at: string;
  updated_at: string;
  latest_alert_at: string;
  alert_ids: Set<string>;
  rule_ids: Set<string>;
  sources: Set<string>;
  tags: Set<string>;
  actor: string;
  device_id: string | null;
  grouping: "semantic" | "legacy_grouped";
  assignee_principal_id: string | null;
}

export async function loadCaseQueue(
  db: D1Database,
  tenantId: string,
  limit: number,
): Promise<Record<string, unknown>> {
  const scanLimit = 10_000;
  const rows = await db.prepare(
    `SELECT c.case_id, c.semantic_key, c.title, c.priority, c.status,
            c.assignee_principal_id,
            c.opened_at, c.updated_at, a.alert_id, a.rule_id, a.actor,
            a.tags_json, a.created_at AS alert_created_at,
            e.event_type, e.device_id
       FROM cases c
       JOIN case_alerts ca
         ON ca.tenant_id = c.tenant_id AND ca.case_id = c.case_id
       JOIN alerts a
         ON a.tenant_id = ca.tenant_id AND a.alert_id = ca.alert_id
       JOIN events e
         ON e.tenant_id = a.tenant_id AND e.event_id = a.event_id
      WHERE c.tenant_id = ? AND c.status != 'closed'
      ORDER BY c.updated_at DESC, a.created_at DESC
      LIMIT ?`,
  ).bind(tenantId, scanLimit).all<CaseQueueRow>();
  const grouped = new Map<string, MutableQueueGroup>();
  for (const row of rows.results) {
    const entity = row.device_id ? `device:${row.device_id}` : `actor:${row.actor}`;
    const key = `${row.rule_id}:${entity}`;
    let group = grouped.get(key);
    if (!group) {
      group = {
        case_id: row.case_id,
        case_ids: new Set<string>(),
        title: row.title,
        priority: row.priority,
        status: row.status,
        opened_at: row.opened_at,
        updated_at: row.updated_at,
        latest_alert_at: row.alert_created_at,
        alert_ids: new Set<string>(),
        rule_ids: new Set<string>(),
        sources: new Set<string>(),
        tags: new Set<string>(),
        actor: row.actor,
        device_id: row.device_id,
        grouping: row.semantic_key ? "semantic" : "legacy_grouped",
        assignee_principal_id: row.assignee_principal_id,
      };
      grouped.set(key, group);
    }
    group.case_ids.add(row.case_id);
    group.alert_ids.add(row.alert_id);
    group.rule_ids.add(row.rule_id);
    group.sources.add(row.event_type);
    const tags = parseStoredJson(row.tags_json);
    if (Array.isArray(tags)) {
      for (const tag of tags) if (typeof tag === "string") group.tags.add(tag);
    }
    if ((SEVERITY_RANK[row.priority] ?? 0) > (SEVERITY_RANK[group.priority] ?? 0)) {
      group.priority = row.priority;
    }
    if (row.updated_at > group.updated_at) {
      group.case_id = row.case_id;
      group.title = row.title;
      group.status = row.status;
      group.updated_at = row.updated_at;
      group.actor = row.actor;
      group.device_id = row.device_id;
      group.assignee_principal_id = row.assignee_principal_id;
    }
    if (row.opened_at < group.opened_at) group.opened_at = row.opened_at;
    if (row.alert_created_at > group.latest_alert_at) {
      group.latest_alert_at = row.alert_created_at;
    }
    if (row.semantic_key) group.grouping = "semantic";
  }
  const groups = [...grouped.values()]
    .sort((left, right) => {
      const priority = (SEVERITY_RANK[right.priority] ?? 0)
        - (SEVERITY_RANK[left.priority] ?? 0);
      return priority || right.updated_at.localeCompare(left.updated_at);
    })
    .slice(0, limit)
    .map((group) => ({
      case_id: group.case_id,
      case_count: group.case_ids.size,
      title: group.title,
      priority: group.priority,
      status: group.status,
      opened_at: group.opened_at,
      updated_at: group.updated_at,
      latest_alert_at: group.latest_alert_at,
      recurrence_count: group.alert_ids.size,
      rule_ids: [...group.rule_ids].sort(),
      sources: [...group.sources].sort(),
      tags: [...group.tags].sort(),
      actor: group.actor,
      device_id: group.device_id,
      grouping: group.grouping,
      assignee_principal_id: group.assignee_principal_id,
    }));
  return {
    groups,
    source_rows_scanned: rows.results.length,
    scan_truncated: rows.results.length === scanLimit,
  };
}

interface AlertEvidenceRow extends AlertRow {
  event_type: string;
  occurred_at: string;
  received_at: string;
  device_id: string | null;
  source_ip: string | null;
  target: string | null;
  attributes_json: string;
  payload_sha256: string;
}

interface JsonRow extends Record<string, string | null> {
  result_json: string | null;
}

export async function loadResponseActions(
  db: D1Database,
  tenantId: string,
  limit: number,
): Promise<Array<Record<string, unknown>>> {
  const actions = await db.prepare(
    `SELECT action_id, case_id, action_type, target_type, target_id, rationale,
            risk_level, status, proposed_by, proposed_at, approved_by, approved_at,
            expires_at, result_json, completed_at
       FROM response_actions WHERE tenant_id = ?
       ORDER BY proposed_at DESC LIMIT ?`,
  ).bind(tenantId, limit).all<JsonRow>();
  return actions.results.map((row) => {
    const { result_json: resultJson, ...action } = row;
    return { ...action, result: parseStoredJson(resultJson) };
  });
}

export async function loadCaseDetail(
  db: D1Database,
  tenantId: string,
  caseId: string,
): Promise<Record<string, unknown> | null> {
  const selectedCase = await db.prepare(
    `SELECT case_id, semantic_key, title, priority, status, opened_at, updated_at, closed_at,
            assignee_principal_id,
            disposition_required_after
       FROM cases WHERE tenant_id = ? AND case_id = ?`,
  ).bind(tenantId, caseId).first();
  if (!selectedCase) return null;
  const [alerts, assessments, notes, dispositions, audit] = await Promise.all([
    db.prepare(
      `SELECT a.alert_id, a.event_id, a.rule_id, a.title, a.severity, a.actor,
              a.reasons_json, a.tags_json, a.rule_version, a.rule_digest,
              a.rule_snapshot_json, a.fingerprint_version, a.detector_version,
              a.evidence_json, a.created_at,
              e.event_type, e.occurred_at, e.received_at, e.device_id,
              e.source_ip, e.target, e.attributes_json, e.payload_sha256
         FROM case_alerts ca
         JOIN alerts a
           ON a.tenant_id = ca.tenant_id AND a.alert_id = ca.alert_id
         JOIN events e
           ON e.tenant_id = a.tenant_id AND e.event_id = a.event_id
        WHERE ca.tenant_id = ? AND ca.case_id = ?
        ORDER BY a.created_at DESC LIMIT 500`,
    ).bind(tenantId, caseId).all<AlertEvidenceRow>(),
    db.prepare(
      `SELECT t.assessment_id, t.alert_id, t.model, t.assessment_json,
              t.created_by, t.created_at
         FROM triage_assessments t
         JOIN case_alerts ca
           ON ca.tenant_id = t.tenant_id AND ca.alert_id = t.alert_id
        WHERE t.tenant_id = ? AND ca.case_id = ?
        ORDER BY t.created_at DESC LIMIT 100`,
    ).bind(tenantId, caseId).all<{
      assessment_id: string;
      alert_id: string;
      model: string;
      assessment_json: string;
      created_by: string;
      created_at: string;
    }>(),
    db.prepare(
      `SELECT note_id, body, created_by, created_at
         FROM case_notes WHERE tenant_id = ? AND case_id = ?
        ORDER BY created_at DESC LIMIT 500`,
    ).bind(tenantId, caseId).all<{
      note_id: string;
      body: string;
      created_by: string;
      created_at: string;
    }>(),
    db.prepare(
      `SELECT disposition_id, disposition, rationale, false_positive_reason,
              created_by, created_at
         FROM case_dispositions WHERE tenant_id = ? AND case_id = ?
        ORDER BY created_at DESC LIMIT 100`,
    ).bind(tenantId, caseId).all<{
      disposition_id: string;
      disposition: string;
      rationale: string;
      false_positive_reason: string | null;
      created_by: string;
      created_at: string;
    }>(),
    db.prepare(
      `SELECT audit_id, action, actor_type, actor_id, resource_type, resource_id,
              payload_json, created_at
         FROM audit_log
        WHERE tenant_id = ? AND (
          (resource_type = 'case' AND resource_id = ?)
          OR resource_id IN (
            SELECT alert_id FROM case_alerts WHERE tenant_id = ? AND case_id = ?
          )
          OR resource_id IN (
            SELECT action_id FROM response_actions WHERE tenant_id = ? AND case_id = ?
          )
        )
        ORDER BY sequence DESC LIMIT 200`,
    ).bind(tenantId, caseId, tenantId, caseId, tenantId, caseId).all<{
      audit_id: string;
      action: string;
      actor_type: string;
      actor_id: string;
      resource_type: string;
      resource_id: string;
      payload_json: string;
      created_at: string;
    }>(),
  ]);
  const responseActions = await loadResponseActionsForCase(db, tenantId, caseId);
  return {
    case: selectedCase,
    alerts: alerts.results.map((row) => ({
      ...mapAlert(row),
      event: {
        event_type: row.event_type,
        occurred_at: row.occurred_at,
        received_at: row.received_at,
        device_id: row.device_id,
        source_ip: row.source_ip,
        target: row.target,
        attributes: parseStoredJson(row.attributes_json),
        payload_sha256: row.payload_sha256,
      },
      rule_provenance: {
        rule_id: row.rule_id,
        rule_version: row.rule_version,
        rule_digest: row.rule_digest,
        fingerprint_version: row.fingerprint_version,
        detector: row.detector_version,
        immutable_snapshot_stored: row.rule_snapshot_json !== null,
        original_replay_available: row.rule_version !== null
          && row.rule_digest !== null
          && row.rule_snapshot_json !== null,
      },
    })),
    triage_assessments: assessments.results.map((row) => ({
      assessment_id: row.assessment_id,
      alert_id: row.alert_id,
      model: row.model,
      created_by: row.created_by,
      created_at: row.created_at,
      assessment: parseStoredJson(row.assessment_json),
    })),
    notes: notes.results,
    dispositions: dispositions.results.map((row) => ({
      ...row,
      disposition: row.disposition === "benign_positive" ? "benign" : row.disposition,
    })),
    response_actions: responseActions,
    audit: audit.results.map((row) => ({
      audit_id: row.audit_id,
      action: row.action,
      actor_type: row.actor_type,
      actor_id: row.actor_id,
      resource_type: row.resource_type,
      resource_id: row.resource_id,
      created_at: row.created_at,
      payload: parseStoredJson(row.payload_json),
    })),
  };
}

async function loadResponseActionsForCase(
  db: D1Database,
  tenantId: string,
  caseId: string,
): Promise<Array<Record<string, unknown>>> {
  const actions = await db.prepare(
    `SELECT action_id, case_id, action_type, target_type, target_id, rationale,
            risk_level, status, proposed_by, proposed_at, approved_by, approved_at,
            expires_at, result_json, completed_at
       FROM response_actions WHERE tenant_id = ? AND case_id = ?
       ORDER BY proposed_at DESC LIMIT 100`,
  ).bind(tenantId, caseId).all<JsonRow>();
  return actions.results.map((row) => {
    const { result_json: resultJson, ...action } = row;
    return { ...action, result: parseStoredJson(resultJson) };
  });
}
