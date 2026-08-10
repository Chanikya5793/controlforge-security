import {
  alertFingerprintV1,
  compiledCorrelations,
  compiledDetectionProvenance,
  detectCanonicalStatelessEvent,
  evaluateCanonicalBuiltin,
  evaluateCanonicalRule,
  parseDetectionSnapshot,
  type CanonicalEvent,
  type CompiledCorrelation,
  type CompiledDetectionProvenance,
  type DetectionSnapshot,
} from "./sigma";
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

function correlation(eventType: string): CompiledCorrelation {
  const found = compiledCorrelations.find((item) => item.event_type === eventType);
  if (!found) throw new Error(`missing compiled correlation for ${eventType}`);
  return found;
}

function requiredNumber(value: number | null, name: string): number {
  if (value === null) throw new Error(`compiled correlation is missing ${name}`);
  return value;
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

async function createAlert(
  event: StoredEvent,
  ruleId: string,
  title: string,
  severity: Severity,
  reasons: string[],
  tags: string[],
  provenanceOverride?: CompiledDetectionProvenance,
): Promise<DetectionAlert> {
  const provenance = provenanceOverride ?? compiledDetectionProvenance(ruleId);
  return {
    alertId: await alertFingerprintV1(event.tenant_id, ruleId, event.event_id),
    ruleId,
    title,
    severity,
    eventId: event.event_id,
    actor: event.actor,
    reasons,
    tags,
    ruleVersion: provenance.ruleVersion,
    ruleDigest: provenance.ruleDigest,
    ruleSnapshot: provenance.ruleSnapshot,
    fingerprintVersion: "alert-fingerprint-v1",
    detectorVersion: "controlforge-cloud-canonical-v1",
    evidence: {
      source_event_id: event.event_id,
      source_event_sha256: event.payload_sha256,
      matched_evidence: reasons,
    },
    createdAt: event.occurred_at,
  };
}

function canonicalEvent(event: StoredEvent): CanonicalEvent {
  const attrs = attributes(event);
  return {
    event_id: event.event_id,
    event_type: event.event_type,
    timestamp: event.occurred_at,
    actor: event.actor,
    ...(event.source_ip === null ? {} : { source_ip: event.source_ip }),
    ...(event.target === null ? {} : { target: event.target }),
    ...(event.device_id === null ? {} : { device_id: event.device_id }),
    attributes: attrs,
  };
}

export async function detectStatelessEvent(event: StoredEvent): Promise<DetectionAlert[]> {
  const canonical = await Promise.all(detectCanonicalStatelessEvent(canonicalEvent(event)).map((decision) => (
    createAlert(
      event,
      decision.rule_id,
      decision.title,
      decision.severity,
      decision.reasons,
      decision.tags,
    )
  )));
  return canonical;
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

async function statefulDetections(
  event: StoredEvent,
  db: D1Database,
  replaySnapshot?: Extract<DetectionSnapshot, { kind: "correlation" }>,
): Promise<DetectionAlert[]> {
  const attrs = attributes(event);
  const alerts: DetectionAlert[] = [];
  if (replaySnapshot && replaySnapshot.rule.event_type !== event.event_type) return alerts;
  const replayProvenance = replaySnapshot
    ? {
        ruleVersion: replaySnapshot.rule.rule_version,
        ruleDigest: replaySnapshot.rule.rule_digest,
        ruleSnapshot: Object.fromEntries(
          Object.entries(replaySnapshot.rule).filter(([key]) => key !== "rule_digest"),
        ),
      }
    : undefined;

  if (event.event_type === "sensitive_data_access" && typeof attrs.bytes === "number") {
    const spec = replaySnapshot?.rule ?? correlation(event.event_type);
    const windowMinutes = requiredNumber(spec.window_minutes, "window_minutes");
    const eventThreshold = requiredNumber(spec.event_threshold, "event_threshold");
    const byteThreshold = requiredNumber(spec.byte_threshold, "byte_threshold");
    const aggregate = await db.prepare(
      `SELECT COUNT(*) AS event_count,
              COALESCE(SUM(CAST(json_extract(attributes_json, '$.bytes') AS INTEGER)), 0) AS total_bytes
         FROM events
        WHERE tenant_id = ? AND actor = ? AND event_type = 'sensitive_data_access'
          AND json_type(attributes_json, '$.bytes') IN ('integer', 'real')
          AND julianday(occurred_at) BETWEEN julianday(?) - (? / 1440.0) AND julianday(?)`,
    ).bind(event.tenant_id, event.actor, event.occurred_at, windowMinutes, event.occurred_at)
      .first<CountRow>();
    if (aggregate && (aggregate.event_count >= eventThreshold || aggregate.total_bytes >= byteThreshold)) {
      alerts.push(await createAlert(event, spec.rule_id, spec.title, spec.severity, [
        `${String(aggregate.event_count)} access events within ${String(windowMinutes)}m`,
        `${String(aggregate.total_bytes)} bytes accessed`,
      ], spec.tags, replayProvenance));
    }
  }

  if (
    event.event_type === "authentication_success" &&
    typeof attrs.latitude === "number" && typeof attrs.longitude === "number"
  ) {
    const spec = replaySnapshot?.rule ?? correlation(event.event_type);
    const maximumSpeed = requiredNumber(spec.maximum_speed_kph, "maximum_speed_kph");
    const previous = await db.prepare(
      `SELECT occurred_at, attributes_json FROM events
        WHERE tenant_id = ? AND actor = ? AND event_type = 'authentication_success'
          AND julianday(occurred_at) < julianday(?)
        ORDER BY julianday(occurred_at) DESC, event_id DESC LIMIT 1`,
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
        if (hours > 0 && speed > maximumSpeed) {
          alerts.push(await createAlert(event, spec.rule_id, spec.title, spec.severity, [
            `calculated travel velocity ${speed.toFixed(0)} km/h`,
            `distance ${distance.toFixed(0)} km over ${hours.toFixed(2)}h`,
          ], spec.tags, replayProvenance));
        }
      }
    }
  }

  if (event.event_type === "edge_auth_failure" && event.source_ip) {
    const spec = replaySnapshot?.rule ?? correlation(event.event_type);
    const windowMinutes = requiredNumber(spec.window_minutes, "window_minutes");
    const eventThreshold = requiredNumber(spec.event_threshold, "event_threshold");
    const distinctThreshold = requiredNumber(spec.distinct_threshold, "distinct_threshold");
    const aggregate = await db.prepare(
      `SELECT COUNT(*) AS event_count, COUNT(DISTINCT lower(actor)) AS distinct_accounts,
              0 AS total_bytes
         FROM events
        WHERE tenant_id = ? AND source_ip = ? AND event_type = 'edge_auth_failure'
          AND julianday(occurred_at) BETWEEN julianday(?) - (? / 1440.0) AND julianday(?)`,
    ).bind(event.tenant_id, event.source_ip, event.occurred_at, windowMinutes, event.occurred_at)
      .first<CountRow>();
    if (
      aggregate && aggregate.event_count >= eventThreshold &&
      (aggregate.distinct_accounts ?? 0) >= distinctThreshold
    ) {
      alerts.push(await createAlert(
        event,
        spec.rule_id,
        spec.title,
        spec.severity,
        [
          `${String(aggregate.event_count)} failed authentications from ${event.source_ip}`,
          `${String(aggregate.distinct_accounts ?? 0)} distinct accounts within ${String(windowMinutes)}m`,
        ],
        spec.tags,
        replayProvenance,
      ));
    }
  }

  const sessionHash = text(attrs.session_id_hash);
  if (event.event_type === "edge_session_use" && event.source_ip && sessionHash.length >= 12) {
    const spec = replaySnapshot?.rule ?? correlation(event.event_type);
    const windowMinutes = requiredNumber(spec.window_minutes, "window_minutes");
    const previous = await db.prepare(
      `SELECT source_ip FROM events
        WHERE tenant_id = ? AND event_type = 'edge_session_use'
          AND json_extract(attributes_json, '$.session_id_hash') = ?
          AND julianday(occurred_at) < julianday(?)
          AND julianday(occurred_at) >= julianday(?) - (? / 1440.0)
        ORDER BY julianday(occurred_at) DESC, event_id DESC LIMIT 1`,
    ).bind(event.tenant_id, sessionHash, event.occurred_at, event.occurred_at, windowMinutes)
      .first<PreviousSessionRow>();
    if (previous?.source_ip && previous.source_ip !== event.source_ip) {
      alerts.push(await createAlert(event, spec.rule_id, spec.title, spec.severity, [
        `session hash reused from ${previous.source_ip} and ${event.source_ip}`,
        `reuse occurred within ${String(windowMinutes)}m`,
      ], spec.tags, replayProvenance));
    }
  }
  return alerts;
}

export interface StoredSnapshotReplay {
  alert: DetectionAlert | null;
  snapshotKind: DetectionSnapshot["kind"];
  evidenceBasis: "source_event" | "current_retained_history";
}

export async function replayStoredSnapshot(
  event: StoredEvent,
  rawSnapshot: unknown,
  expectedDigest: string,
  db: D1Database,
): Promise<StoredSnapshotReplay> {
  const snapshot = await parseDetectionSnapshot(rawSnapshot, expectedDigest);
  const provenance: CompiledDetectionProvenance = {
    ruleVersion: snapshot.rule.rule_version,
    ruleDigest: snapshot.rule.rule_digest,
    ruleSnapshot: rawSnapshot as Record<string, unknown>,
  };
  if (snapshot.kind === "correlation") {
    const alerts = await statefulDetections(event, db, snapshot);
    return {
      alert: alerts.find((item) => item.ruleId === snapshot.rule.rule_id) ?? null,
      snapshotKind: snapshot.kind,
      evidenceBasis: "current_retained_history",
    };
  }
  const decision = snapshot.kind === "sigma"
    ? evaluateCanonicalRule(snapshot.rule, canonicalEvent(event))
    : evaluateCanonicalBuiltin(snapshot.rule, canonicalEvent(event));
  return {
    alert: decision
      ? await createAlert(
          event,
          decision.rule_id,
          decision.title,
          decision.severity,
          decision.reasons,
          decision.tags,
          provenance,
        )
      : null,
    snapshotKind: snapshot.kind,
    evidenceBasis: "source_event",
  };
}

export async function detectEvent(event: StoredEvent, db: D1Database): Promise<DetectionAlert[]> {
  return [
    ...await detectStatelessEvent(event),
    ...await statefulDetections(event, db),
  ];
}
