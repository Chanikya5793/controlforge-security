import { env } from "cloudflare:workers";
import { describe, expect, it } from "vitest";

import { appendCaseNote } from "../src/case-workflow";
import {
  enforceIngestionLimits,
  loadOperationalHealth,
  operationalConfig,
  requireIngestionCapacity,
  runTelemetryRetention,
  TenantIngestionLimitError,
} from "../src/operational-safety";
import {
  EventIdentityConflictError,
  loadEvent,
  persistAlertAndCase,
  persistEvents,
} from "../src/repository";
import type { SecurityEventInput } from "../src/schemas";
import type { DetectionAlert, Env } from "../src/types";

function derivedEnv(overrides: Partial<Env>): Env {
  return Object.assign(Object.create(env as unknown as object), overrides) as Env;
}

async function createTenant(): Promise<string> {
  const tenantId = crypto.randomUUID();
  await env.DB.prepare(
    `INSERT INTO tenants(tenant_id, slug, display_name, status, created_at)
     VALUES (?, ?, ?, 'active', ?)`,
  ).bind(
    tenantId,
    `safety-${tenantId.slice(0, 12)}`,
    "Operational safety test",
    "2026-01-01T00:00:00.000Z",
  ).run();
  return tenantId;
}

async function insertEvent(
  tenantId: string,
  eventId: string,
  receivedAt: string,
  processedAt: string | null,
  processingError: string | null = null,
): Promise<void> {
  await env.DB.prepare(
    `INSERT INTO events(
       tenant_id, event_id, event_type, occurred_at, received_at, actor,
       source_ip, target, device_id, attributes_json, payload_sha256,
       processed_at, processing_error
     ) VALUES (?, ?, 'santa_execution', ?, ?, 'device:test', NULL, NULL, 'device-test',
       '{"decision":"DECISION_ALLOW"}', ?, ?, ?)`,
  ).bind(
    tenantId,
    eventId,
    receivedAt,
    receivedAt,
    "a".repeat(64),
    processedAt,
    processingError,
  ).run();
}

function result(rows: Array<Record<string, unknown>>, sizeAfter?: number): D1Result {
  return {
    results: rows,
    success: true,
    meta: sizeAfter === undefined ? {} : { size_after: sizeAfter },
  } as unknown as D1Result;
}

describe("operational safety", () => {
  it("uses bounded defaults when optional production settings are invalid", () => {
    const config = operationalConfig({
      EVENT_RETENTION_DAYS: "0",
      RETENTION_BATCH_SIZE: "9999",
      RETENTION_MAX_BATCHES_PER_RUN: "not-a-number",
      TENANT_INGEST_EVENTS_PER_MINUTE: "99",
      DEVICE_INGEST_EVENTS_PER_MINUTE: "100001",
      D1_MAX_DATABASE_BYTES: "499999999",
      D1_CAPACITY_WRITE_STOP_PERCENT: "100",
    } as unknown as Env);

    expect(config).toEqual({
      retentionDays: 7,
      retentionBatchSize: 200,
      retentionMaxBatches: 5,
      ingestEventsPerMinute: 5_000,
      deviceIngestEventsPerMinute: 2_000,
      databaseMaxBytes: 10_000_000_000,
      capacityWriteStopPercent: 90,
    });
  });

  it("rolls tenant and device quota counters back together and resets the next minute", async () => {
    const tenantId = await createTenant();
    const limited = derivedEnv({
      TENANT_INGEST_EVENTS_PER_MINUTE: "150",
      DEVICE_INGEST_EVENTS_PER_MINUTE: "100",
    });
    const firstWindow = new Date("2026-01-01T12:00:30.000Z");

    await enforceIngestionLimits(limited, tenantId, "device-a", 80, firstWindow);
    await expect(
      enforceIngestionLimits(limited, tenantId, "device-a", 30, firstWindow),
    ).rejects.toMatchObject({ retryAfterSeconds: 30 });

    const afterDeviceRejection = await env.DB.prepare(
      `SELECT scope_type, scope_id, event_count FROM tenant_ingestion_windows
       WHERE tenant_id = ? ORDER BY scope_type, scope_id`,
    ).bind(tenantId).all<{ scope_type: string; scope_id: string; event_count: number }>();
    expect(afterDeviceRejection.results.map((row) => row.event_count)).toEqual([80, 80]);

    await enforceIngestionLimits(limited, tenantId, "device-b", 70, firstWindow);
    await expect(
      enforceIngestionLimits(limited, tenantId, "device-b", 1, firstWindow),
    ).rejects.toBeInstanceOf(TenantIngestionLimitError);
    const deviceB = await env.DB.prepare(
      `SELECT event_count FROM tenant_ingestion_windows
       WHERE tenant_id = ? AND scope_type = 'device' AND scope_id = 'device-b'`,
    ).bind(tenantId).first<{ event_count: number }>();
    expect(deviceB?.event_count).toBe(70);

    await enforceIngestionLimits(
      limited,
      tenantId,
      "device-a",
      100,
      new Date("2026-01-01T12:01:00.000Z"),
    );
    const reset = await env.DB.prepare(
      `SELECT event_count, window_started_at FROM tenant_ingestion_windows
       WHERE tenant_id = ? AND scope_type = 'device' AND scope_id = 'device-a'`,
    ).bind(tenantId).first<{ event_count: number; window_started_at: string }>();
    expect(reset).toEqual({
      event_count: 100,
      window_started_at: "2026-01-01T12:01:00.000Z",
    });

    await expect(
      enforceIngestionLimits(limited, tenantId, "device-c", 151, firstWindow),
    ).rejects.toBeInstanceOf(TenantIngestionLimitError);
  });

  it("stops writes at the configured storage high-water mark", async () => {
    const capacityEnv = (sizeAfter: number | undefined): Env => ({
      DB: {
        prepare: () => ({
          run: () => Promise.resolve(result([], sizeAfter)),
        }),
      } as unknown as D1Database,
      D1_MAX_DATABASE_BYTES: "500000000",
      D1_CAPACITY_WRITE_STOP_PERCENT: "90",
    } as unknown as Env);

    await expect(requireIngestionCapacity(capacityEnv(449_999_999))).resolves.toBeUndefined();
    await expect(requireIngestionCapacity(capacityEnv(undefined))).resolves.toBeUndefined();
    await expect(requireIngestionCapacity(capacityEnv(450_000_000))).rejects.toMatchObject({
      retryAfterSeconds: 300,
    });
  });

  it("deletes only terminal unreferenced telemetry and exposes bounded health", async () => {
    const tenantId = await createTenant();
    const now = new Date("2026-01-15T12:00:00.000Z");
    await env.DB.prepare(
      `UPDATE retention_state SET last_started_at = NULL, last_completed_at = NULL,
       next_run_at = NULL, cutoff_at = NULL, deleted_events = 0,
       last_error = NULL, database_size_bytes = NULL, updated_at = ?
       WHERE singleton = 1`,
    ).bind(now.toISOString()).run();

    await insertEvent(tenantId, "old-safe", "2026-01-01T00:00:00.000Z", "2026-01-01T00:01:00.000Z");
    await insertEvent(
      tenantId,
      "old-error",
      "2026-01-01T00:00:01.000Z",
      "2026-01-01T00:01:01.000Z",
      "detector failed",
    );
    await insertEvent(tenantId, "old-pending", "2026-01-01T00:00:02.000Z", null);
    await insertEvent(tenantId, "old-alerted", "2026-01-01T00:00:03.000Z", "2026-01-01T00:01:03.000Z");
    await insertEvent(tenantId, "recent-safe", "2026-01-10T00:00:00.000Z", "2026-01-10T00:01:00.000Z");
    await env.DB.prepare(
      `INSERT INTO alerts(
         tenant_id, alert_id, event_id, rule_id, title, severity, actor,
         reasons_json, tags_json, created_at
       ) VALUES (?, 'retained-alert', 'old-alerted', 'CF-TEST', 'Retained evidence',
         'low', 'device:test', '[]', '[]', ?)`,
    ).bind(tenantId, "2026-01-01T00:02:00.000Z").run();

    await expect(runTelemetryRetention(env as unknown as Env, now)).resolves.toEqual({
      deletedEvents: 1,
      skipped: false,
    });
    const rows = await env.DB.prepare(
      "SELECT event_id FROM events WHERE tenant_id = ? ORDER BY event_id",
    ).bind(tenantId).all<{ event_id: string }>();
    expect(rows.results.map((row) => row.event_id)).toEqual([
      "old-alerted",
      "old-error",
      "old-pending",
      "recent-safe",
    ]);
    await expect(runTelemetryRetention(env as unknown as Env, now)).resolves.toEqual({
      deletedEvents: 0,
      skipped: true,
    });

    const health = await loadOperationalHealth(env as unknown as Env, tenantId, now);
    expect(health).toMatchObject({
      status: "attention",
      tenant: {
        pending_events: 1,
        pending_events_capped: false,
        processing_errors: 1,
        processing_errors_capped: false,
        retention_eligible_events: 0,
        retention_eligible_events_capped: false,
      },
      retention: {
        status: "attention",
        days: 7,
        last_deleted_events: 1,
        last_error: null,
      },
      capacity: { status: "normal" },
    });
  });

  it("caps operational counts and redacts stored retention errors", async () => {
    const statement = {
      bind: () => statement,
    };
    const fake = {
      DB: {
        prepare: () => statement,
        batch: () => Promise.resolve([
          result([{ pending_events: 1_001 }]),
          result([{ processing_errors: 0 }]),
          result([{ eligible_events: 1_001 }]),
          result([{
            last_completed_at: null,
            next_run_at: null,
            cutoff_at: null,
            deleted_events: 0,
            last_error: "private provider response",
            database_size_bytes: null,
          }], 8_500_000_000),
        ]),
      } as unknown as D1Database,
      D1_MAX_DATABASE_BYTES: "10000000000",
      D1_CAPACITY_WRITE_STOP_PERCENT: "90",
    } as unknown as Env;

    await expect(loadOperationalHealth(fake, crypto.randomUUID())).resolves.toMatchObject({
      status: "critical",
      tenant: {
        pending_events: 1_000,
        pending_events_capped: true,
        retention_eligible_events: 1_000,
        retention_eligible_events_capped: true,
      },
      retention: {
        status: "degraded",
        last_error: "retention maintenance failed",
      },
      capacity: {
        status: "critical",
        database_size_bytes: 8_500_000_000,
        utilization_percent: 85,
      },
    });
  });

  it("rejects conflicting event identities without changing accepted evidence", async () => {
    const tenantId = await createTenant();
    const event: SecurityEventInput = {
      event_id: `identity-${crypto.randomUUID()}`,
      event_type: "process_start",
      timestamp: "2026-01-01T00:00:00.000Z",
      actor: "device:original",
      device_id: "device-test",
      attributes: { process_name: "safe" },
    };

    const first = await persistEvents(env as unknown as Env, tenantId, [event, event]);
    expect(first).toEqual({ accepted: [event.event_id], duplicates: [event.event_id] });
    await expect(persistEvents(env as unknown as Env, tenantId, [event])).resolves.toEqual({
      accepted: [],
      duplicates: [event.event_id],
    });
    await expect(persistEvents(env as unknown as Env, tenantId, [{
      ...event,
      actor: "device:conflicting",
    }])).rejects.toBeInstanceOf(EventIdentityConflictError);

    const stored = await env.DB.prepare(
      "SELECT actor FROM events WHERE tenant_id = ? AND event_id = ?",
    ).bind(tenantId, event.event_id).first<{ actor: string }>();
    expect(stored?.actor).toBe("device:original");
  });

  it("rolls a case mutation back when its required audit record cannot commit", async () => {
    const tenantId = await createTenant();
    const caseId = `case-${crypto.randomUUID()}`;
    const triggerName = `audit_fail_${crypto.randomUUID().replaceAll("-", "")}`;
    await env.DB.prepare(
      `INSERT INTO cases(
         tenant_id, case_id, title, priority, status, opened_at, updated_at, closed_at
       ) VALUES (?, ?, 'Atomic audit test', 'low', 'open', ?, ?, NULL)`,
    ).bind(
      tenantId,
      caseId,
      "2026-01-01T00:00:00.000Z",
      "2026-01-01T00:00:00.000Z",
    ).run();
    await env.DB.prepare(
      `CREATE TRIGGER ${triggerName}
       BEFORE INSERT ON audit_log
       WHEN NEW.action = 'case.note_added' AND NEW.resource_id = '${caseId}'
       BEGIN
         SELECT RAISE(ABORT, 'forced audit failure');
       END`,
    ).run();

    try {
      await expect(appendCaseNote(
        env as unknown as Env,
        tenantId,
        caseId,
        "This note must roll back with its audit record.",
        { id: "test-admin", type: "admin_token", tenantId },
      )).rejects.toThrow("forced audit failure");
      const noteCount = await env.DB.prepare(
        "SELECT count(*) AS count FROM case_notes WHERE tenant_id = ? AND case_id = ?",
      ).bind(tenantId, caseId).first<{ count: number }>();
      const auditCount = await env.DB.prepare(
        `SELECT count(*) AS count FROM audit_log
         WHERE tenant_id = ? AND resource_id = ? AND action = 'case.note_added'`,
      ).bind(tenantId, caseId).first<{ count: number }>();
      expect(noteCount?.count).toBe(0);
      expect(auditCount?.count).toBe(0);
    } finally {
      await env.DB.prepare(`DROP TRIGGER ${triggerName}`).run();
    }
  });

  it("rolls alert evidence back when its integrity audit cannot commit", async () => {
    const tenantId = await createTenant();
    const eventId = `alert-source-${crypto.randomUUID()}`;
    const alertId = `alert-${crypto.randomUUID()}`;
    const triggerName = `alert_audit_fail_${crypto.randomUUID().replaceAll("-", "")}`;
    await insertEvent(tenantId, eventId, "2026-01-01T00:00:00.000Z", null);
    const event = await loadEvent(env.DB, tenantId, eventId);
    if (!event) throw new Error("test source event was not persisted");
    const alert: DetectionAlert = {
      alertId,
      eventId,
      ruleId: "CF-ATOMIC-001",
      title: "Atomic alert test",
      severity: "high",
      actor: "device:test",
      reasons: ["test evidence"],
      tags: ["test"],
      ruleVersion: 1,
      ruleDigest: `sha256:${"b".repeat(64)}`,
      ruleSnapshot: { id: "CF-ATOMIC-001", rule_version: 1 },
      fingerprintVersion: "alert-fingerprint-v1",
      detectorVersion: "controlforge-cloud-canonical-v1",
      evidence: {
        source_event_id: eventId,
        source_event_sha256: "a".repeat(64),
        matched_evidence: ["test evidence"],
      },
      createdAt: "2026-01-01T00:01:00.000Z",
    };
    await env.DB.prepare(
      `CREATE TRIGGER ${triggerName}
       BEFORE INSERT ON audit_log
       WHEN NEW.action = 'alert.created' AND NEW.resource_id = '${alertId}'
       BEGIN
         SELECT RAISE(ABORT, 'forced alert audit failure');
       END`,
    ).run();

    try {
      await expect(persistAlertAndCase(
        env as unknown as Env,
        tenantId,
        alert,
        event,
      )).rejects.toThrow("forced alert audit failure");
      const alertCount = await env.DB.prepare(
        "SELECT count(*) AS count FROM alerts WHERE tenant_id = ? AND alert_id = ?",
      ).bind(tenantId, alertId).first<{ count: number }>();
      const auditCount = await env.DB.prepare(
        `SELECT count(*) AS count FROM audit_log
         WHERE tenant_id = ? AND resource_id = ? AND action = 'alert.created'`,
      ).bind(tenantId, alertId).first<{ count: number }>();
      expect(alertCount?.count).toBe(0);
      expect(auditCount?.count).toBe(0);
    } finally {
      await env.DB.prepare(`DROP TRIGGER ${triggerName}`).run();
    }
  });
});
