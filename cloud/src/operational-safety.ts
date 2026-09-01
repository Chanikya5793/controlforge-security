import type { Env } from "./types";

const DEFAULT_RETENTION_DAYS = 7;
const DEFAULT_RETENTION_BATCH_SIZE = 200;
const DEFAULT_RETENTION_MAX_BATCHES = 5;
const DEFAULT_INGEST_EVENTS_PER_MINUTE = 5_000;
const DEFAULT_DEVICE_INGEST_EVENTS_PER_MINUTE = 2_000;
const DEFAULT_D1_MAX_DATABASE_BYTES = 10_000_000_000;
const DEFAULT_CAPACITY_WRITE_STOP_PERCENT = 90;
const RETENTION_IDLE_INTERVAL_MS = 24 * 60 * 60 * 1_000;
const HEALTH_COUNT_CAP = 1_001;

interface RetentionStateRow {
  last_completed_at: string | null;
  next_run_at: string | null;
  cutoff_at: string | null;
  deleted_events: number;
  last_error: string | null;
  database_size_bytes: number | null;
}

export interface OperationalConfig {
  databaseMaxBytes: number;
  capacityWriteStopPercent: number;
  deviceIngestEventsPerMinute: number;
  ingestEventsPerMinute: number;
  retentionBatchSize: number;
  retentionDays: number;
  retentionMaxBatches: number;
}

export class TenantIngestionLimitError extends Error {
  readonly retryAfterSeconds: number;

  constructor(retryAfterSeconds: number) {
    super("tenant ingestion rate limit exceeded");
    this.retryAfterSeconds = retryAfterSeconds;
  }
}

export class StorageCapacityError extends Error {
  readonly retryAfterSeconds = 300;

  constructor() {
    super("telemetry storage is temporarily at its configured capacity threshold");
  }
}

function boundedInteger(
  value: string | undefined,
  fallback: number,
  minimum: number,
  maximum: number,
): number {
  if (value === undefined || value === "") return fallback;
  const parsed = Number(value);
  return Number.isSafeInteger(parsed) && parsed >= minimum && parsed <= maximum
    ? parsed
    : fallback;
}

export function operationalConfig(env: Env): OperationalConfig {
  return {
    retentionDays: boundedInteger(env.EVENT_RETENTION_DAYS, DEFAULT_RETENTION_DAYS, 1, 365),
    retentionBatchSize: boundedInteger(
      env.RETENTION_BATCH_SIZE,
      DEFAULT_RETENTION_BATCH_SIZE,
      10,
      500,
    ),
    retentionMaxBatches: boundedInteger(
      env.RETENTION_MAX_BATCHES_PER_RUN,
      DEFAULT_RETENTION_MAX_BATCHES,
      1,
      10,
    ),
    ingestEventsPerMinute: boundedInteger(
      env.TENANT_INGEST_EVENTS_PER_MINUTE,
      DEFAULT_INGEST_EVENTS_PER_MINUTE,
      100,
      100_000,
    ),
    deviceIngestEventsPerMinute: boundedInteger(
      env.DEVICE_INGEST_EVENTS_PER_MINUTE,
      DEFAULT_DEVICE_INGEST_EVENTS_PER_MINUTE,
      100,
      100_000,
    ),
    databaseMaxBytes: boundedInteger(
      env.D1_MAX_DATABASE_BYTES,
      DEFAULT_D1_MAX_DATABASE_BYTES,
      500_000_000,
      10_000_000_000,
    ),
    capacityWriteStopPercent: boundedInteger(
      env.D1_CAPACITY_WRITE_STOP_PERCENT,
      DEFAULT_CAPACITY_WRITE_STOP_PERCENT,
      50,
      98,
    ),
  };
}

function minuteWindow(now: Date): { retryAfterSeconds: number; startedAt: string } {
  const started = new Date(now);
  started.setUTCSeconds(0, 0);
  const retryAfterSeconds = Math.max(1, 60 - now.getUTCSeconds());
  return { startedAt: started.toISOString(), retryAfterSeconds };
}

function ingestionWindowStatement(
  env: Env,
  tenantId: string,
  scopeType: "tenant" | "device",
  scopeId: string,
  requestedEvents: number,
  maximumEvents: number,
  startedAt: string,
  now: Date,
): D1PreparedStatement {
  return env.DB.prepare(
    `INSERT INTO tenant_ingestion_windows(
       tenant_id, scope_type, scope_id, window_started_at, event_count, event_limit, updated_at
     ) VALUES (?, ?, ?, ?, ?, ?, ?)
     ON CONFLICT(tenant_id, scope_type, scope_id) DO UPDATE SET
       window_started_at = excluded.window_started_at,
       event_count = CASE
         WHEN tenant_ingestion_windows.window_started_at = excluded.window_started_at
           THEN tenant_ingestion_windows.event_count + excluded.event_count
         ELSE excluded.event_count
       END,
       event_limit = excluded.event_limit,
       updated_at = excluded.updated_at`,
  ).bind(
    tenantId,
    scopeType,
    scopeId,
    startedAt,
    requestedEvents,
    maximumEvents,
    now.toISOString(),
  );
}

export async function enforceIngestionLimits(
  env: Env,
  tenantId: string,
  deviceId: string,
  requestedEvents: number,
  now = new Date(),
): Promise<void> {
  const config = operationalConfig(env);
  const { retryAfterSeconds, startedAt } = minuteWindow(now);
  if (
    requestedEvents < 1
    || requestedEvents > config.ingestEventsPerMinute
    || requestedEvents > config.deviceIngestEventsPerMinute
  ) {
    throw new TenantIngestionLimitError(retryAfterSeconds);
  }
  try {
    await env.DB.batch([
      ingestionWindowStatement(
        env,
        tenantId,
        "tenant",
        tenantId,
        requestedEvents,
        config.ingestEventsPerMinute,
        startedAt,
        now,
      ),
      ingestionWindowStatement(
        env,
        tenantId,
        "device",
        deviceId,
        requestedEvents,
        config.deviceIngestEventsPerMinute,
        startedAt,
        now,
      ),
    ]);
  } catch (error) {
    const summary = error instanceof Error ? error.message : "";
    if (summary.includes("ingestion rate limit exceeded")) {
      throw new TenantIngestionLimitError(retryAfterSeconds);
    }
    throw error;
  }
}

export async function requireIngestionCapacity(env: Env): Promise<void> {
  const config = operationalConfig(env);
  const probe = await env.DB.prepare("SELECT 1 AS ready").run();
  const size = databaseSize(probe);
  if (
    size !== null
    && size / config.databaseMaxBytes >= config.capacityWriteStopPercent / 100
  ) {
    throw new StorageCapacityError();
  }
}

function databaseSize(result: D1Result | undefined): number | null {
  const size = result?.meta.size_after;
  return typeof size === "number" && Number.isFinite(size) && size >= 0 ? size : null;
}

function sizeStatus(sizeBytes: number | null, maximumBytes: number): "unknown" | "normal" | "warning" | "critical" {
  if (sizeBytes === null) return "unknown";
  const ratio = sizeBytes / maximumBytes;
  if (ratio >= 0.85) return "critical";
  if (ratio >= 0.7) return "warning";
  return "normal";
}

export async function runTelemetryRetention(
  env: Env,
  now = new Date(),
): Promise<{ deletedEvents: number; skipped: boolean }> {
  const config = operationalConfig(env);
  const state = await env.DB.prepare(
    `SELECT next_run_at FROM retention_state WHERE singleton = 1`,
  ).first<{ next_run_at: string | null }>();
  if (state?.next_run_at && Date.parse(state.next_run_at) > now.getTime()) {
    return { deletedEvents: 0, skipped: true };
  }

  const startedAt = now.toISOString();
  const cutoffAt = new Date(now.getTime() - config.retentionDays * 86_400_000).toISOString();
  let deletedEvents = 0;
  let latestSize: number | null = null;
  try {
    for (let batch = 0; batch < config.retentionMaxBatches; batch += 1) {
      const deleted = await env.DB.prepare(
        `DELETE FROM events
          WHERE rowid IN (
            SELECT event.rowid FROM events event
             WHERE event.processed_at IS NOT NULL
               AND event.processing_error IS NULL
               AND event.received_at < ?
               AND NOT EXISTS (
                 SELECT 1 FROM alerts alert
                  WHERE alert.tenant_id = event.tenant_id
                    AND alert.event_id = event.event_id
               )
             ORDER BY event.received_at ASC
             LIMIT ?
          )`,
      ).bind(cutoffAt, config.retentionBatchSize).run();
      deletedEvents += deleted.meta.changes;
      latestSize = databaseSize(deleted) ?? latestSize;
      if (deleted.meta.changes < config.retentionBatchSize) break;
    }
    const saturated = deletedEvents === config.retentionBatchSize * config.retentionMaxBatches;
    const nextRunAt = new Date(
      now.getTime() + (saturated ? 5 * 60_000 : RETENTION_IDLE_INTERVAL_MS),
    ).toISOString();
    await env.DB.prepare(
      `UPDATE retention_state
          SET last_started_at = ?, last_completed_at = ?, next_run_at = ?, cutoff_at = ?,
              deleted_events = ?, last_error = NULL, database_size_bytes = coalesce(?, database_size_bytes),
              updated_at = ?
        WHERE singleton = 1`,
    ).bind(
      startedAt,
      new Date().toISOString(),
      nextRunAt,
      cutoffAt,
      deletedEvents,
      latestSize,
      new Date().toISOString(),
    ).run();
    return { deletedEvents, skipped: false };
  } catch (error) {
    const summary = error instanceof Error ? error.message.slice(0, 300) : "retention failed";
    try {
      await env.DB.prepare(
        `UPDATE retention_state
            SET last_started_at = ?, last_error = ?, updated_at = ?
          WHERE singleton = 1`,
      ).bind(startedAt, summary, new Date().toISOString()).run();
    } catch {
      // The original D1 failure remains authoritative when even health state cannot be persisted.
    }
    throw error;
  }
}

export async function loadOperationalHealth(
  env: Env,
  tenantId: string,
  now = new Date(),
): Promise<Record<string, unknown>> {
  const config = operationalConfig(env);
  const cutoffAt = new Date(now.getTime() - config.retentionDays * 86_400_000).toISOString();
  const results = await env.DB.batch([
    env.DB.prepare(
      `SELECT count(*) AS pending_events FROM (
         SELECT 1 FROM events
          WHERE tenant_id = ? AND processed_at IS NULL AND processing_error IS NULL
          LIMIT ?
       )`,
    ).bind(tenantId, HEALTH_COUNT_CAP),
    env.DB.prepare(
      `SELECT count(*) AS processing_errors FROM (
         SELECT 1 FROM events
          WHERE tenant_id = ? AND processing_error IS NOT NULL
          LIMIT ?
       )`,
    ).bind(tenantId, HEALTH_COUNT_CAP),
    env.DB.prepare(
      `SELECT count(*) AS eligible_events FROM (
         SELECT 1 FROM events event
          WHERE event.tenant_id = ?
            AND event.processed_at IS NOT NULL
            AND event.processing_error IS NULL
            AND event.received_at < ?
            AND NOT EXISTS (
              SELECT 1 FROM alerts alert
               WHERE alert.tenant_id = event.tenant_id
                 AND alert.event_id = event.event_id
            )
          LIMIT ?
       )`,
    ).bind(tenantId, cutoffAt, HEALTH_COUNT_CAP),
    env.DB.prepare(
      `SELECT last_completed_at, next_run_at, cutoff_at, deleted_events, last_error,
              database_size_bytes
         FROM retention_state WHERE singleton = 1`,
    ),
  ]);
  const pending = (results[0]?.results[0] ?? {}) as { pending_events?: number | null };
  const errors = (results[1]?.results[0] ?? {}) as { processing_errors?: number | null };
  const eligible = (results[2]?.results[0] ?? {}) as { eligible_events?: number | null };
  const state = (results[3]?.results[0] ?? {}) as Partial<RetentionStateRow>;
  const pendingEvents = pending.pending_events ?? 0;
  const processingErrors = errors.processing_errors ?? 0;
  const eligibleEvents = eligible.eligible_events ?? 0;
  const observedSize = databaseSize(results[3]) ?? state.database_size_bytes ?? null;
  const capacityStatus = sizeStatus(observedSize, config.databaseMaxBytes);
  const retentionStatus = state.last_error
    ? "degraded"
    : processingErrors > 0 || eligibleEvents >= HEALTH_COUNT_CAP
      ? "attention"
      : "healthy";
  return {
    status: capacityStatus === "critical" || retentionStatus === "degraded"
      ? "critical"
      : capacityStatus === "warning" || retentionStatus === "attention" || pendingEvents >= HEALTH_COUNT_CAP
        ? "attention"
        : "healthy",
    tenant: {
      pending_events: Math.min(pendingEvents, HEALTH_COUNT_CAP - 1),
      pending_events_capped: pendingEvents >= HEALTH_COUNT_CAP,
      processing_errors: Math.min(processingErrors, HEALTH_COUNT_CAP - 1),
      processing_errors_capped: processingErrors >= HEALTH_COUNT_CAP,
      retention_eligible_events: Math.min(eligibleEvents, HEALTH_COUNT_CAP - 1),
      retention_eligible_events_capped: eligibleEvents >= HEALTH_COUNT_CAP,
    },
    retention: {
      status: retentionStatus,
      days: config.retentionDays,
      batch_size: config.retentionBatchSize,
      max_batches_per_run: config.retentionMaxBatches,
      last_completed_at: state.last_completed_at ?? null,
      next_run_at: state.next_run_at ?? null,
      cutoff_at: state.cutoff_at ?? null,
      last_deleted_events: state.deleted_events ?? 0,
      last_error: state.last_error ? "retention maintenance failed" : null,
    },
    capacity: {
      status: capacityStatus,
      database_size_bytes: observedSize,
      configured_max_bytes: config.databaseMaxBytes,
      utilization_percent: observedSize === null
        ? null
        : Math.round((observedSize / config.databaseMaxBytes) * 10_000) / 100,
    },
    safeguards: {
      tenant_ingest_events_per_minute: config.ingestEventsPerMinute,
      device_ingest_events_per_minute: config.deviceIngestEventsPerMinute,
      capacity_write_stop_percent: config.capacityWriteStopPercent,
    },
  };
}
