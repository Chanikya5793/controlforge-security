import { env, exports } from "cloudflare:workers";
import {
  createExecutionContext,
  createMessageBatch,
  getQueueResult,
} from "cloudflare:test";
import { describe, expect, it, vi } from "vitest";

import worker from "../src/index";
import { detectStatelessEvent } from "../src/detector";
import { loadEvent, persistAlertAndCase } from "../src/repository";
import { hmacHex, sha256Hex } from "../src/security";
import type { Env, QueuedEvent } from "../src/types";

const authorization = { authorization: `Bearer ${"a".repeat(48)}` };

async function call(path: string, init: RequestInit = {}): Promise<Response> {
  return exports.default.fetch(new Request(`https://controlforge.test${path}`, init));
}

async function createTenant(deviceId = "device-1"): Promise<{
  credentialId: string;
  deviceId: string;
  secret: string;
  tenantId: string;
}> {
  const unique = crypto.randomUUID().slice(0, 8);
  const response = await call("/v1/admin/tenants", {
    method: "POST",
    headers: { ...authorization, "content-type": "application/json" },
    body: JSON.stringify({
      slug: `tenant-${unique}`,
      display_name: `Tenant ${unique}`,
      device_id: deviceId,
      device_name: `Device ${deviceId}`,
      credential_name: "integration-test",
      credential_ttl_days: 7,
    }),
  });
  expect(response.status).toBe(201);
  const payload = await response.json() as {
    tenant_id: string;
    credential: { credential_id: string; secret: string };
  };
  return {
    tenantId: payload.tenant_id,
    deviceId,
    credentialId: payload.credential.credential_id,
    secret: payload.credential.secret,
  };
}

async function signedIngestion(
  credentialId: string,
  secret: string,
  body: string,
  nonce = crypto.randomUUID().replaceAll("-", ""),
): Promise<{ headers: Headers; response: Response }> {
  const timestamp = new Date().toISOString();
  const canonical = [
    "POST",
    "/v1/ingest/events",
    timestamp,
    nonce,
    await sha256Hex(body),
  ].join("\n");
  const headers = new Headers({
    "content-type": "application/json",
    "x-controlforge-credential-id": credentialId,
    "x-controlforge-timestamp": timestamp,
    "x-controlforge-nonce": nonce,
    "x-controlforge-signature": await hmacHex(secret, canonical),
  });
  const response = await call("/v1/ingest/events", { method: "POST", headers, body });
  return { headers, response };
}

async function signedCollectorRequest(
  method: "GET" | "POST",
  path: string,
  credentialId: string,
  secret: string,
  body = "",
): Promise<Response> {
  const timestamp = new Date().toISOString();
  const nonce = crypto.randomUUID().replaceAll("-", "");
  const canonical = [
    method,
    new URL(`https://controlforge.test${path}`).pathname,
    timestamp,
    nonce,
    await sha256Hex(body),
  ].join("\n");
  const headers = new Headers({
    "x-controlforge-credential-id": credentialId,
    "x-controlforge-timestamp": timestamp,
    "x-controlforge-nonce": nonce,
    "x-controlforge-signature": await hmacHex(secret, canonical),
  });
  if (body) headers.set("content-type", "application/json");
  return call(path, { method, headers, ...(body ? { body } : {}) });
}

describe("ControlForge Worker API", () => {
  it("exposes only minimal public health and hardened response headers", async () => {
    const response = await call("/health");
    expect(response.status).toBe(200);
    await expect(response.json()).resolves.toMatchObject({
      status: "ok",
      service: "controlforge-soc",
      environment: "test",
    });
    expect(response.headers.get("x-content-type-options")).toBe("nosniff");
    expect(response.headers.get("cache-control")).toBe("no-store");
  });

  it("fails closed on unauthenticated administration and dashboard access", async () => {
    const createResponse = await call("/v1/admin/tenants", {
      method: "POST",
      headers: { "content-type": "application/json" },
      body: JSON.stringify({ slug: "unauthorized", display_name: "Unauthorized" }),
    });
    const dashboardResponse = await call("/dashboard");

    expect(createResponse.status).toBe(401);
    expect(dashboardResponse.status).toBe(401);
  });

  it("serves the authenticated dashboard with a nonce-restricted content policy", async () => {
    const response = await call("/dashboard", { headers: authorization });
    const policy = response.headers.get("content-security-policy");
    expect(response.status).toBe(200);
    expect(policy).toContain("script-src 'nonce-");
    expect(policy).not.toContain("unsafe-inline");
    const html = await response.text();
    expect(html).toContain("Evidence-first SOC");
    expect(html).toContain("Prioritized case queue");
    expect(html).toContain("Skip to main content");
    expect(html).not.toContain("Autonomous SOC");
  });

  it("rejects invalid query bounds as a client error", async () => {
    const tenant = await createTenant();
    const response = await call("/v1/alerts?limit=1001", {
      headers: { ...authorization, "x-controlforge-tenant-id": tenant.tenantId },
    });
    expect(response.status).toBe(400);
  });

  it("creates a tenant and returns the encrypted collector credential only once", async () => {
    const tenant = await createTenant();
    expect(tenant.secret.length).toBeGreaterThan(32);
    const credential = await env.DB.prepare(
      `SELECT device_id, secret_ciphertext, secret_iv
         FROM collector_credentials WHERE credential_id = ?`,
    ).bind(tenant.credentialId).first<{
      device_id: string;
      secret_ciphertext: string;
      secret_iv: string;
    }>();
    expect(credential?.device_id).toBe(tenant.deviceId);
    expect(credential?.secret_ciphertext).not.toContain(tenant.secret);
    expect(credential?.secret_iv).toBeTruthy();

    const audit = await env.DB.prepare(
      "SELECT integrity_hmac FROM audit_log WHERE tenant_id = ? AND action = 'tenant.created'",
    ).bind(tenant.tenantId).first<{ integrity_hmac: string }>();
    expect(audit?.integrity_hmac).toMatch(/^[a-f0-9]{64}$/u);
  });

  it("accepts signed events, rejects nonce replay, detects, persists, and opens a case", async () => {
    const tenant = await createTenant();
    const eventId = `powershell-${crypto.randomUUID()}`;
    const body = JSON.stringify({ events: [{
      event_id: eventId,
      event_type: "process_start",
      timestamp: "2026-08-18T06:00:00Z",
      actor: "analyst@example.com",
      device_id: "device-1",
      attributes: {
        process_name: "powershell.exe",
        command_line: "powershell.exe -enc SQBFAFgA",
      },
    }] });
    const nonce = crypto.randomUUID().replaceAll("-", "");
    const accepted = await signedIngestion(tenant.credentialId, tenant.secret, body, nonce);
    expect(accepted.response.status).toBe(202);
    await expect(accepted.response.json()).resolves.toMatchObject({ accepted: 1, duplicates: 0 });

    const replay = await call("/v1/ingest/events", {
      method: "POST",
      headers: accepted.headers,
      body,
    });
    expect(replay.status).toBe(401);

    const batch = createMessageBatch<QueuedEvent>("controlforge-test-events", [{
      id: crypto.randomUUID(),
      timestamp: new Date(),
      attempts: 1,
      body: { tenantId: tenant.tenantId, eventId, attemptId: crypto.randomUUID() },
    }]);
    const context = createExecutionContext();
    await worker.queue?.(batch, env as unknown as Env, context);
    const queueResult = await getQueueResult(batch, context);
    expect(queueResult.ackAll).toBe(false);
    expect(queueResult.explicitAcks).toHaveLength(1);

    const alertsResponse = await call("/v1/alerts?limit=10", {
      headers: { ...authorization, "x-controlforge-tenant-id": tenant.tenantId },
    });
    const alerts = await alertsResponse.json() as Array<{
      rule_id: string;
      rule_version: number | null;
      rule_digest: string | null;
      rule_snapshot: unknown;
      fingerprint_version: string;
      detector_version: string;
      evidence: { source_event_id?: string; source_event_sha256?: string };
    }>;
    expect(alerts.map((alert) => alert.rule_id)).toContain("CF-ENDPOINT-001");
    const detected = alerts.find((alert) => alert.rule_id === "CF-ENDPOINT-001");
    expect(detected).toMatchObject({
      rule_version: 1,
      fingerprint_version: "alert-fingerprint-v1",
      detector_version: "controlforge-cloud-canonical-v1",
      evidence: { source_event_id: eventId },
    });
    expect(detected?.rule_digest).toMatch(/^sha256:[a-f0-9]{64}$/u);
    expect(detected?.rule_snapshot).toMatchObject({ id: "CF-ENDPOINT-001", rule_version: 1 });
    expect(detected?.evidence.source_event_sha256).toMatch(/^[a-f0-9]{64}$/u);
    const caseCount = await env.DB.prepare(
      "SELECT COUNT(*) AS count FROM cases WHERE tenant_id = ?",
    ).bind(tenant.tenantId).first<{ count: number }>();
    expect(caseCount?.count).toBe(1);
  });

  it("aggregates concurrent recurring detections and opens a fresh case after closure", async () => {
    const tenant = await createTenant("aggregate-device");
    const eventIds = [`aggregate-${crypto.randomUUID()}-1`, `aggregate-${crypto.randomUUID()}-2`];
    for (const eventId of eventIds) {
      const ingested = await signedIngestion(
        tenant.credentialId,
        tenant.secret,
        JSON.stringify({ events: [{
          event_id: eventId,
          event_type: "process_start",
          timestamp: new Date().toISOString(),
          actor: "device:aggregate-device",
          device_id: "aggregate-device",
          attributes: {
            process_name: "powershell.exe",
            command_line: "powershell.exe -enc SQBFAFgA",
          },
        }] }),
      );
      expect(ingested.response.status).toBe(202);
    }
    const concurrentBatch = createMessageBatch<QueuedEvent>(
      "controlforge-test-events",
      eventIds.map((eventId) => ({
        id: crypto.randomUUID(),
        timestamp: new Date(),
        attempts: 1,
        body: { tenantId: tenant.tenantId, eventId, attemptId: crypto.randomUUID() },
      })),
    );
    const concurrentContext = createExecutionContext();
    await worker.queue?.(concurrentBatch, env as unknown as Env, concurrentContext);
    const activeCases = await env.DB.prepare(
      `SELECT case_id, semantic_key FROM cases
        WHERE tenant_id = ? AND status != 'closed'`,
    ).bind(tenant.tenantId).all<{ case_id: string; semantic_key: string | null }>();
    expect(activeCases.results).toHaveLength(1);
    expect(activeCases.results[0]?.semantic_key).toMatch(/^[a-f0-9]{64}$/u);
    const caseId = activeCases.results[0]?.case_id ?? "";
    const links = await env.DB.prepare(
      "SELECT alert_id FROM case_alerts WHERE tenant_id = ? AND case_id = ?",
    ).bind(tenant.tenantId, caseId).all<{ alert_id: string }>();
    expect(links.results).toHaveLength(2);

    const detailResponse = await call(`/v1/cases/${caseId}`, {
      headers: { ...authorization, "x-controlforge-tenant-id": tenant.tenantId },
    });
    expect(detailResponse.status).toBe(200);
    const detail = await detailResponse.json() as {
      alerts: Array<{
        alert_id: string;
        event: { payload_sha256: string };
        rule_provenance: {
          rule_version: number | null;
          rule_digest: string | null;
          fingerprint_version: string;
          detector: string;
          immutable_snapshot_stored: boolean;
          original_replay_available: boolean;
        };
      }>;
    };
    expect(detail.alerts).toHaveLength(2);
    expect(detail.alerts[0]?.event.payload_sha256).toMatch(/^[a-f0-9]{64}$/u);
    expect(detail.alerts[0]?.rule_provenance).toMatchObject({
      rule_version: 1,
      fingerprint_version: "alert-fingerprint-v1",
      detector: "controlforge-cloud-canonical-v1",
      immutable_snapshot_stored: true,
      original_replay_available: true,
    });
    expect(detail.alerts[0]?.rule_provenance.rule_digest).toMatch(/^sha256:[a-f0-9]{64}$/u);
    const foreignDetail = await call(`/v1/cases/${caseId}`, {
      headers: {
        ...authorization,
        "x-controlforge-tenant-id": crypto.randomUUID(),
      },
    });
    expect(foreignDetail.status).toBe(404);

    const replay = await call(`/v1/alerts/${detail.alerts[0]?.alert_id ?? ""}/replay`, {
      method: "POST",
      headers: { ...authorization, "x-controlforge-tenant-id": tenant.tenantId },
    });
    expect(replay.status).toBe(201);
    await expect(replay.json()).resolves.toMatchObject({
      mode: "current",
      outcome: "same",
      original_available: true,
    });
    const originalReplay = await call(
      `/v1/alerts/${detail.alerts[0]?.alert_id ?? ""}/replay?mode=original`,
      {
        method: "POST",
        headers: { ...authorization, "x-controlforge-tenant-id": tenant.tenantId },
      },
    );
    expect(originalReplay.status).toBe(201);
    await expect(originalReplay.json()).resolves.toMatchObject({
      mode: "original",
      outcome: "same",
      original_available: true,
      snapshot_kind: "sigma",
      evidence_basis: "source_event",
    });
    const evaluations = await env.DB.prepare(
      `SELECT mode, outcome, snapshot_kind, evidence_basis
         FROM alert_replay_evaluations WHERE tenant_id = ? AND alert_id = ?
         ORDER BY created_at, evaluation_id`,
    ).bind(tenant.tenantId, detail.alerts[0]?.alert_id).all();
    expect(evaluations.results).toHaveLength(2);
    expect(evaluations.results).toEqual(expect.arrayContaining([
      { mode: "current", outcome: "same", snapshot_kind: "sigma", evidence_basis: "source_event" },
      { mode: "original", outcome: "same", snapshot_kind: "sigma", evidence_basis: "source_event" },
    ]));

    const legacyCaseId = crypto.randomUUID();
    const now = new Date().toISOString();
    await env.DB.batch([
      env.DB.prepare(
        `INSERT INTO cases(
          tenant_id, case_id, title, priority, status, opened_at, updated_at
        ) VALUES (?, ?, 'Legacy duplicate', 'high', 'open', ?, ?)`,
      ).bind(tenant.tenantId, legacyCaseId, now, now),
      env.DB.prepare(
        `INSERT INTO case_alerts(tenant_id, case_id, alert_id, linked_at)
         VALUES (?, ?, ?, ?)`,
      ).bind(tenant.tenantId, legacyCaseId, detail.alerts[0]?.alert_id, now),
    ]);
    const queueResponse = await call("/v1/case-queue?limit=20", {
      headers: { ...authorization, "x-controlforge-tenant-id": tenant.tenantId },
    });
    const queue = await queueResponse.json() as {
      groups: Array<{ case_count: number; recurrence_count: number }>;
      scan_truncated: boolean;
    };
    expect(queueResponse.status).toBe(200);
    expect(queue.groups).toEqual([
      expect.objectContaining({ case_count: 2, recurrence_count: 2 }),
    ]);
    expect(queue.scan_truncated).toBe(false);
    const summaryResponse = await call("/v1/dashboard/summary", {
      headers: { ...authorization, "x-controlforge-tenant-id": tenant.tenantId },
    });
    await expect(summaryResponse.json()).resolves.toMatchObject({
      active_devices: 1,
      alerts_24h: 2,
      open_cases: 2,
      pending_events: 0,
      processing_errors: 0,
    });

    await env.DB.prepare(
      "UPDATE cases SET status = 'closed', closed_at = ? WHERE tenant_id = ?",
    ).bind(now, tenant.tenantId).run();
    const thirdEventId = `aggregate-${crypto.randomUUID()}-3`;
    const third = await signedIngestion(
      tenant.credentialId,
      tenant.secret,
      JSON.stringify({ events: [{
        event_id: thirdEventId,
        event_type: "process_start",
        timestamp: new Date().toISOString(),
        actor: "device:aggregate-device",
        device_id: "aggregate-device",
        attributes: {
          process_name: "powershell.exe",
          command_line: "powershell.exe -enc SQBFAFgA",
        },
      }] }),
    );
    expect(third.response.status).toBe(202);
    const reopenedBatch = createMessageBatch<QueuedEvent>("controlforge-test-events", [{
      id: crypto.randomUUID(),
      timestamp: new Date(),
      attempts: 1,
      body: {
        tenantId: tenant.tenantId,
        eventId: thirdEventId,
        attemptId: crypto.randomUUID(),
      },
    }]);
    const reopenedContext = createExecutionContext();
    await worker.queue?.(reopenedBatch, env as unknown as Env, reopenedContext);
    const allCases = await env.DB.prepare(
      "SELECT status FROM cases WHERE tenant_id = ? ORDER BY opened_at",
    ).bind(tenant.tenantId).all<{ status: string }>();
    expect(allCases.results.filter((item) => item.status === "closed")).toHaveLength(2);
    expect(allCases.results.filter((item) => item.status === "open")).toHaveLength(1);
    const allLinks = await env.DB.prepare(
      "SELECT alert_id FROM case_alerts WHERE tenant_id = ?",
    ).bind(tenant.tenantId).all();
    expect(allLinks.results).toHaveLength(4);
  });

  it("projects pre-migration alert provenance as explicit legacy unknowns", async () => {
    const tenant = await createTenant();
    const eventId = crypto.randomUUID();
    const alertId = crypto.randomUUID();
    const now = new Date().toISOString();
    await env.DB.batch([
      env.DB.prepare(
        `INSERT INTO events(
          tenant_id, event_id, event_type, occurred_at, received_at, actor,
          attributes_json, payload_sha256
        ) VALUES (?, ?, 'legacy_fixture', ?, ?, 'legacy@example.com', '{}', ?)`,
      ).bind(tenant.tenantId, eventId, now, now, "b".repeat(64)),
      env.DB.prepare(
        `INSERT INTO alerts(
          tenant_id, alert_id, event_id, rule_id, title, severity, actor,
          reasons_json, tags_json, created_at
        ) VALUES (?, ?, ?, 'CF-LEGACY-001', 'Legacy alert', 'medium',
          'legacy@example.com', '[]', '[]', ?)`,
      ).bind(tenant.tenantId, alertId, eventId, now),
    ]);

    const response = await call("/v1/alerts?limit=10", {
      headers: { ...authorization, "x-controlforge-tenant-id": tenant.tenantId },
    });
    const alerts = await response.json() as Array<Record<string, unknown>>;

    expect(alerts).toContainEqual(expect.objectContaining({
      alert_id: alertId,
      rule_version: null,
      rule_digest: null,
      rule_snapshot: null,
      fingerprint_version: "legacy-cloud-v0",
      detector_version: "legacy-cloud-unknown",
      evidence: { provenance: "legacy-cloud-alert" },
    }));
    const replay = await call(`/v1/alerts/${alertId}/replay?mode=original`, {
      method: "POST",
      headers: { ...authorization, "x-controlforge-tenant-id": tenant.tenantId },
    });
    expect(replay.status).toBe(409);
    await expect(replay.json()).resolves.toEqual({
      error: "original replay is unavailable for this legacy alert",
    });
  });

  it("resolves a legacy semantic occurrence without duplicating its alert or case link", async () => {
    const tenant = await createTenant();
    const eventId = crypto.randomUUID();
    const legacyAlertId = crypto.randomUUID();
    const caseId = crypto.randomUUID();
    const now = "2026-08-22T18:00:00.000Z";
    await env.DB.batch([
      env.DB.prepare(
        `INSERT INTO events(
           tenant_id, event_id, event_type, occurred_at, received_at, actor,
           device_id, attributes_json, payload_sha256
         ) VALUES (?, ?, 'process_start', ?, ?, 'analyst@example.com', 'device-1', ?, ?)`,
      ).bind(
        tenant.tenantId,
        eventId,
        now,
        now,
        JSON.stringify({
          process_name: "powershell.exe",
          command_line: "powershell.exe -EncodedCommand SQBFAFgA",
        }),
        "a".repeat(64),
      ),
      env.DB.prepare(
        `INSERT INTO alerts(
           tenant_id, alert_id, event_id, rule_id, title, severity, actor,
           reasons_json, tags_json, created_at
         ) VALUES (?, ?, ?, 'CF-ENDPOINT-001', 'Legacy alert', 'high',
           'analyst@example.com', '["legacy"]', '[]', ?)`,
      ).bind(tenant.tenantId, legacyAlertId, eventId, now),
      env.DB.prepare(
        `INSERT INTO cases(
           tenant_id, case_id, title, priority, status, opened_at, updated_at
         ) VALUES (?, ?, 'Legacy case', 'high', 'open', ?, ?)`,
      ).bind(tenant.tenantId, caseId, now, now),
      env.DB.prepare(
        `INSERT INTO case_alerts(tenant_id, case_id, alert_id, linked_at)
         VALUES (?, ?, ?, ?)`,
      ).bind(tenant.tenantId, caseId, legacyAlertId, now),
    ]);
    const stored = await loadEvent(env.DB, tenant.tenantId, eventId);
    if (!stored) throw new Error("test event missing");
    const candidate = (await detectStatelessEvent(stored))[0];
    if (!candidate) throw new Error("test detection missing");
    expect(candidate.alertId).not.toBe(legacyAlertId);

    await persistAlertAndCase(env as Env, tenant.tenantId, candidate, stored);

    const alerts = await env.DB.prepare(
      "SELECT alert_id FROM alerts WHERE tenant_id = ? AND rule_id = ? AND event_id = ?",
    ).bind(tenant.tenantId, candidate.ruleId, eventId).all<{ alert_id: string }>();
    expect(alerts.results).toEqual([{ alert_id: legacyAlertId }]);
    const links = await env.DB.prepare(
      "SELECT case_id, alert_id FROM case_alerts WHERE tenant_id = ?",
    ).bind(tenant.tenantId).all();
    expect(links.results).toEqual([{ case_id: caseId, alert_id: legacyAlertId }]);
    await expect(env.DB.prepare(
      `INSERT INTO alerts(
         tenant_id, alert_id, event_id, rule_id, title, severity, actor,
         reasons_json, tags_json, created_at
       ) VALUES (?, ?, ?, ?, 'Duplicate', 'high', 'analyst@example.com', '[]', '[]', ?)`,
    ).bind(
      tenant.tenantId,
      crypto.randomUUID(),
      eventId,
      candidate.ruleId,
      now,
    ).run()).rejects.toThrow();
  });

  it("binds collector ingestion and action polling to one device", async () => {
    const tenant = await createTenant("bound-device");
    const wrongDeviceBody = JSON.stringify({ events: [{
      event_id: `wrong-device-${crypto.randomUUID()}`,
      event_type: "endpoint_control_status",
      timestamp: new Date().toISOString(),
      actor: "device:other-device",
      device_id: "other-device",
      attributes: { status: "healthy" },
    }] });

    const ingestion = await signedIngestion(
      tenant.credentialId,
      tenant.secret,
      wrongDeviceBody,
    );
    expect(ingestion.response.status).toBe(403);

    const polling = await signedCollectorRequest(
      "GET",
      "/v1/agent/actions?device_id=other-device",
      tenant.credentialId,
      tenant.secret,
    );
    expect(polling.status).toBe(403);
  });

  it("accepts collector batches larger than one queue batch", async () => {
    const tenant = await createTenant("batch-test");
    const sendBatch = vi.spyOn(env.EVENT_QUEUE, "sendBatch");
    const timestamp = new Date().toISOString();
    const events = Array.from({ length: 205 }, (_, index) => ({
      event_id: `batch-${crypto.randomUUID()}-${String(index)}`,
      event_type: "endpoint_control_status",
      timestamp,
      actor: "device:batch-test",
      device_id: "batch-test",
      attributes: { status: "healthy" },
    }));
    const result = await signedIngestion(
      tenant.credentialId,
      tenant.secret,
      JSON.stringify({ events }),
    );
    expect(result.response.status).toBe(202);
    await expect(result.response.json()).resolves.toMatchObject({
      accepted: 205,
      duplicates: 0,
    });
    const queuedBatches = sendBatch.mock.calls.flatMap(([messages]) => Array.from(messages));
    expect(queuedBatches).toHaveLength(5);
    expect(queuedBatches.flatMap((message) => {
      const queued = message.body as QueuedEvent;
      return "eventIds" in queued ? queued.eventIds : [queued.eventId];
    })).toHaveLength(205);

    const retry = await signedIngestion(
      tenant.credentialId,
      tenant.secret,
      JSON.stringify({ events }),
    );
    expect(retry.response.status).toBe(202);
    await expect(retry.response.json()).resolves.toMatchObject({
      accepted: 0,
      duplicates: 205,
    });
    expect(sendBatch.mock.calls.flatMap(([messages]) => Array.from(messages))).toHaveLength(10);
    sendBatch.mockRestore();
  });

  it("processes multiple event identities from one queue message", async () => {
    const tenant = await createTenant("queue-group-test");
    const eventIds = [`queue-group-${crypto.randomUUID()}-1`, `queue-group-${crypto.randomUUID()}-2`];
    const result = await signedIngestion(
      tenant.credentialId,
      tenant.secret,
      JSON.stringify({ events: eventIds.map((eventId) => ({
        event_id: eventId,
        event_type: "endpoint_control_status",
        timestamp: new Date().toISOString(),
        actor: "device:queue-group-test",
        device_id: "queue-group-test",
        attributes: { status: "healthy" },
      })) }),
    );
    expect(result.response.status).toBe(202);

    const batch = createMessageBatch<QueuedEvent>("controlforge-test-events", [{
      id: crypto.randomUUID(),
      timestamp: new Date(),
      attempts: 1,
      body: { tenantId: tenant.tenantId, eventIds, attemptId: crypto.randomUUID() },
    }]);
    const context = createExecutionContext();
    await worker.queue?.(batch, env as unknown as Env, context);
    const queueResult = await getQueueResult(batch, context);
    expect(queueResult.explicitAcks).toHaveLength(1);

    const processed = await env.DB.prepare(
      "SELECT COUNT(*) AS count FROM events WHERE tenant_id = ? AND processed_at IS NOT NULL",
    ).bind(tenant.tenantId).first<{ count: number }>();
    expect(processed?.count).toBe(2);
  });

  it("retries an oversized grouped queue message without processing it", async () => {
    const tenant = await createTenant();
    const batch = createMessageBatch<QueuedEvent>("controlforge-test-events", [{
      id: crypto.randomUUID(),
      timestamp: new Date(),
      attempts: 1,
      body: {
        tenantId: tenant.tenantId,
        eventIds: Array.from({ length: 51 }, (_, index) => `oversized-${String(index)}`),
        attemptId: crypto.randomUUID(),
      },
    }]);
    const context = createExecutionContext();
    await worker.queue?.(batch, env as unknown as Env, context);
    const queueResult = await getQueueResult(batch, context);
    expect(queueResult.explicitAcks).toHaveLength(0);
    expect(queueResult.retryMessages).toHaveLength(1);
  });

  it("reconciles accepted events directly without amplifying queue writes", async () => {
    const tenant = await createTenant("recovery-test");
    await env.DB.prepare(
      "UPDATE events SET processed_at = ? WHERE processed_at IS NULL",
    ).bind(new Date().toISOString()).run();
    const eventId = `orphan-${crypto.randomUUID()}`;
    const santaEventId = `orphan-santa-${crypto.randomUUID()}`;
    const result = await signedIngestion(
      tenant.credentialId,
      tenant.secret,
      JSON.stringify({ events: [{
        event_id: eventId,
        event_type: "endpoint_control_status",
        timestamp: new Date().toISOString(),
        actor: "device:recovery-test",
        device_id: "recovery-test",
        attributes: { status: "healthy" },
      }, {
        event_id: santaEventId,
        event_type: "santa_execution",
        timestamp: new Date().toISOString(),
        actor: "device:recovery-test",
        device_id: "recovery-test",
        attributes: { decision: "DECISION_ALLOW", process_path: "/usr/bin/true" },
      }] }),
    );
    expect(result.response.status).toBe(202);

    const sendBatch = vi.spyOn(env.EVENT_QUEUE, "sendBatch");
    const context = createExecutionContext();
    await worker.scheduled?.(
      { cron: "*/5 * * * *", scheduledTime: Date.now(), noRetry: vi.fn() },
      env as unknown as Env,
      context,
    );
    expect(sendBatch).not.toHaveBeenCalled();
    const recovered = await env.DB.prepare(
      `SELECT event_id, processed_at, processing_error FROM events
       WHERE tenant_id = ? AND event_id IN (?, ?) ORDER BY event_id`,
    ).bind(tenant.tenantId, eventId, santaEventId).all<{
      event_id: string;
      processed_at: string | null;
      processing_error: string | null;
    }>();
    expect(recovered.results).toEqual(expect.arrayContaining([
      expect.objectContaining({ event_id: eventId, processed_at: expect.any(String), processing_error: null }),
      expect.objectContaining({ event_id: santaEventId, processed_at: expect.any(String), processing_error: null }),
    ]));
    sendBatch.mockRestore();
  });

  it("keeps audit records append-only at the database boundary", async () => {
    const tenant = await createTenant();
    await expect(env.DB.prepare(
      "UPDATE audit_log SET action = 'tampered' WHERE tenant_id = ?",
    ).bind(tenant.tenantId).run()).rejects.toThrow(/append-only/iu);
    await expect(env.DB.prepare(
      "DELETE FROM audit_log WHERE tenant_id = ?",
    ).bind(tenant.tenantId).run()).rejects.toThrow(/append-only/iu);
  });

  it("enforces append-only case workflow and conflict-safe reopen transitions", async () => {
    const tenant = await createTenant("workflow-device");
    const caseId = crypto.randomUUID();
    const semanticKey = "b".repeat(64);
    const now = new Date().toISOString();
    await env.DB.prepare(
      `INSERT INTO cases(
         tenant_id, case_id, semantic_key, title, priority, status, opened_at, updated_at
       ) VALUES (?, ?, ?, 'Credential investigation', 'high', 'open', ?, ?)`,
    ).bind(tenant.tenantId, caseId, semanticKey, now, now).run();
    const mutationHeaders = {
      ...authorization,
      "content-type": "application/json",
      "x-controlforge-tenant-id": tenant.tenantId,
    };
    const transition = (status: string): Promise<Response> => call(
      `/v1/cases/${caseId}/transitions`,
      {
        method: "POST",
        headers: mutationHeaders,
        body: JSON.stringify({ status }),
      },
    );

    const mismatchedResponse = await call(`/v1/cases/${caseId}/actions`, {
      method: "POST",
      headers: mutationHeaders,
      body: JSON.stringify({
        action_type: "isolate_endpoint",
        target_type: "identity",
        target_id: "user@example.com",
        rationale: "This invalid target pairing must fail schema validation.",
      }),
    });
    expect(mismatchedResponse.status).toBe(400);

    expect((await transition("contained")).status).toBe(409);
    expect((await transition("closed")).status).toBe(409);
    const invalidNote = await call(`/v1/cases/${caseId}/notes`, {
      method: "POST",
      headers: mutationHeaders,
      body: JSON.stringify({ body: "Evidence reviewed.", overwrite: true }),
    });
    expect(invalidNote.status).toBe(400);
    const note = await call(`/v1/cases/${caseId}/notes`, {
      method: "POST",
      headers: mutationHeaders,
      body: JSON.stringify({ body: "Reviewed the preserved endpoint evidence." }),
    });
    expect(note.status).toBe(201);
    const notePayload = await note.json() as { note_id: string };
    const disposition = await call(`/v1/cases/${caseId}/dispositions`, {
      method: "POST",
      headers: mutationHeaders,
      body: JSON.stringify({
        disposition: "true_positive",
        rationale: "The deterministic evidence confirms the documented test signal.",
      }),
    });
    expect(disposition.status).toBe(201);
    const dispositionPayload = await disposition.json() as { disposition_id: string };

    expect((await transition("investigating")).status).toBe(200);
    expect((await transition("contained")).status).toBe(200);
    expect((await transition("investigating")).status).toBe(200);
    expect((await transition("closed")).status).toBe(200);
    expect((await transition("investigating")).status).toBe(409);
    expect((await transition("open")).status).toBe(200);
    expect((await transition("closed")).status).toBe(409);
    const redisposition = await call(`/v1/cases/${caseId}/dispositions`, {
      method: "POST",
      headers: mutationHeaders,
      body: JSON.stringify({
        disposition: "true_positive",
        rationale: "Reopened evidence was reviewed and confirms the same disposition.",
      }),
    });
    expect(redisposition.status).toBe(201);
    expect((await transition("closed")).status).toBe(200);

    const competingCaseId = crypto.randomUUID();
    await env.DB.prepare(
      `INSERT INTO cases(
         tenant_id, case_id, semantic_key, title, priority, status, opened_at, updated_at
       ) VALUES (?, ?, ?, 'Recurring credential investigation', 'high', 'open', ?, ?)`,
    ).bind(tenant.tenantId, competingCaseId, semanticKey, now, now).run();
    const conflictedReopen = await transition("open");
    expect(conflictedReopen.status).toBe(409);
    await expect(conflictedReopen.json()).resolves.toEqual({
      error: "case cannot be reopened while its semantic case is active",
    });

    const legacyCaseId = crypto.randomUUID();
    await env.DB.prepare(
      `INSERT INTO cases(
         tenant_id, case_id, title, priority, status, opened_at, updated_at, closed_at
       ) VALUES (?, ?, 'Legacy closed case', 'low', 'closed', ?, ?, ?)`,
    ).bind(tenant.tenantId, legacyCaseId, now, now, now).run();
    const legacyReopen = await call(`/v1/cases/${legacyCaseId}/transitions`, {
      method: "POST",
      headers: mutationHeaders,
      body: JSON.stringify({ status: "open" }),
    });
    expect(legacyReopen.status).toBe(409);

    await expect(env.DB.prepare(
      "UPDATE case_notes SET body = 'changed' WHERE tenant_id = ? AND note_id = ?",
    ).bind(tenant.tenantId, notePayload.note_id).run()).rejects.toThrow(/append-only/iu);
    await expect(env.DB.prepare(
      "DELETE FROM case_dispositions WHERE tenant_id = ? AND disposition_id = ?",
    ).bind(tenant.tenantId, dispositionPayload.disposition_id).run()).rejects.toThrow(
      /append-only/iu,
    );

    const detail = await call(`/v1/cases/${caseId}`, {
      headers: { ...authorization, "x-controlforge-tenant-id": tenant.tenantId },
    });
    const detailPayload = await detail.json() as {
      notes: Array<{ body: string }>;
      dispositions: Array<{ disposition: string }>;
      audit: Array<{ action: string }>;
    };
    expect(detailPayload.notes).toEqual([
      expect.objectContaining({ body: "Reviewed the preserved endpoint evidence." }),
    ]);
    expect(detailPayload.dispositions).toHaveLength(2);
    expect(detailPayload.dispositions).toEqual(expect.arrayContaining([
      expect.objectContaining({ disposition: "true_positive" }),
    ]));
    expect(detailPayload.audit.map((item) => item.action)).toEqual(expect.arrayContaining([
      "case.note_added",
      "case.disposition_added",
      "case.status_changed",
    ]));
  });

  it("keeps case ownership tenant-scoped and records canonical false-positive context", async () => {
    const tenant = await createTenant("ownership-device");
    const otherTenant = await createTenant("other-ownership-device");
    const caseId = crypto.randomUUID();
    const now = new Date().toISOString();
    await env.DB.batch([
      env.DB.prepare(
        `INSERT INTO cases(
           tenant_id, case_id, title, priority, status, opened_at, updated_at
         ) VALUES (?, ?, 'Endpoint ownership review', 'high', 'open', ?, ?)`,
      ).bind(tenant.tenantId, caseId, now, now),
      env.DB.prepare(
        `INSERT INTO analyst_memberships(tenant_id, principal_id, role, created_at)
         VALUES (?, 'analyst-2', 'analyst', ?)`,
      ).bind(tenant.tenantId, now),
      env.DB.prepare(
        `INSERT INTO analyst_memberships(tenant_id, principal_id, role, created_at)
         VALUES (?, 'viewer-1', 'viewer', ?)`,
      ).bind(tenant.tenantId, now),
      env.DB.prepare(
        `INSERT INTO analyst_memberships(tenant_id, principal_id, role, created_at)
         VALUES (?, 'other-analyst', 'analyst', ?)`,
      ).bind(otherTenant.tenantId, now),
    ]);
    const headers = {
      ...authorization,
      "content-type": "application/json",
      "x-controlforge-tenant-id": tenant.tenantId,
    };

    const assignees = await call("/v1/case-assignees", { headers });
    expect(assignees.status).toBe(200);
    await expect(assignees.json()).resolves.toEqual({
      assignees: expect.arrayContaining([
        expect.objectContaining({ principal_id: "analyst-2", role: "analyst" }),
      ]),
    });
    const assigneePayload = await call("/v1/case-assignees", { headers }).then(
      (response) => response.json() as Promise<{ assignees: Array<{ principal_id: string }> }>,
    );
    expect(assigneePayload.assignees.map((item) => item.principal_id)).not.toContain("viewer-1");

    const assign = (assigneePrincipalId: string | null): Promise<Response> => call(
      `/v1/cases/${caseId}/assignment`,
      {
        method: "POST",
        headers,
        body: JSON.stringify({ assignee_principal_id: assigneePrincipalId }),
      },
    );
    expect((await assign("analyst-2")).status).toBe(200);
    expect((await assign("analyst-2")).status).toBe(409);
    expect((await assign("viewer-1")).status).toBe(409);
    expect((await assign("other-analyst")).status).toBe(409);

    const missingReason = await call(`/v1/cases/${caseId}/dispositions`, {
      method: "POST",
      headers,
      body: JSON.stringify({
        disposition: "false_positive",
        rationale: "This signal is safe after reviewing the preserved evidence.",
      }),
    });
    expect(missingReason.status).toBe(400);
    const falsePositive = await call(`/v1/cases/${caseId}/dispositions`, {
      method: "POST",
      headers,
      body: JSON.stringify({
        disposition: "false_positive",
        rationale: "This signal is safe after reviewing the preserved evidence.",
        false_positive_reason: "Trusted internal software",
      }),
    });
    expect(falsePositive.status).toBe(201);
    await expect(falsePositive.json()).resolves.toEqual(expect.objectContaining({
      disposition: "false_positive",
      false_positive_reason: "Trusted internal software",
    }));
    const benign = await call(`/v1/cases/${caseId}/dispositions`, {
      method: "POST",
      headers,
      body: JSON.stringify({
        disposition: "benign",
        rationale: "Expected administrative activity was independently verified.",
      }),
    });
    expect(benign.status).toBe(201);
    await expect(benign.json()).resolves.toEqual(expect.objectContaining({
      disposition: "benign",
      false_positive_reason: null,
    }));

    const detail = await call(`/v1/cases/${caseId}`, { headers });
    const detailPayload = await detail.json() as {
      case: { assignee_principal_id: string | null };
      dispositions: Array<{ disposition: string; false_positive_reason: string | null }>;
      audit: Array<{ action: string }>;
    };
    expect(detailPayload.case.assignee_principal_id).toBe("analyst-2");
    expect(detailPayload.dispositions).toEqual(expect.arrayContaining([
      expect.objectContaining({ disposition: "benign", false_positive_reason: null }),
      expect.objectContaining({
        disposition: "false_positive",
        false_positive_reason: "Trusted internal software",
      }),
    ]));
    expect(detailPayload.audit.map((item) => item.action)).toContain("case.assignment_changed");
    expect((await assign(null)).status).toBe(200);
  });

  it("requires a second principal before approving an active response", async () => {
    const tenant = await createTenant();
    const now = new Date().toISOString();
    const caseId = crypto.randomUUID();
    await env.DB.prepare(
      `INSERT INTO cases(tenant_id, case_id, title, priority, status, opened_at, updated_at)
       VALUES (?, ?, 'Credential dumping', 'critical', 'open', ?, ?)`,
    ).bind(tenant.tenantId, caseId, now, now).run();
    const proposal = await call(`/v1/cases/${caseId}/actions`, {
      method: "POST",
      headers: {
        ...authorization,
        "content-type": "application/json",
        "x-controlforge-tenant-id": tenant.tenantId,
      },
      body: JSON.stringify({
        action_type: "isolate_endpoint",
        target_type: "device",
        target_id: "device-1",
        rationale: "Contain a high-confidence credential dumping event.",
      }),
    });
    expect(proposal.status).toBe(201);
    const { action_id: actionId } = await proposal.json() as { action_id: string };
    const decision = await call(`/v1/actions/${actionId}/decision`, {
      method: "POST",
      headers: {
        ...authorization,
        "content-type": "application/json",
        "x-controlforge-tenant-id": tenant.tenantId,
      },
      body: JSON.stringify({ decision: "approve", rationale: "Approve containment." }),
    });
    expect(decision.status).toBe(409);
  });

  it("auto-approves read-only collection and accepts a signed agent result", async () => {
    const tenant = await createTenant();
    const now = new Date().toISOString();
    const caseId = crypto.randomUUID();
    await env.DB.prepare(
      `INSERT INTO cases(tenant_id, case_id, title, priority, status, opened_at, updated_at)
       VALUES (?, ?, 'Endpoint investigation', 'high', 'open', ?, ?)`,
    ).bind(tenant.tenantId, caseId, now, now).run();
    const proposal = await call(`/v1/cases/${caseId}/actions`, {
      method: "POST",
      headers: {
        ...authorization,
        "content-type": "application/json",
        "x-controlforge-tenant-id": tenant.tenantId,
      },
      body: JSON.stringify({
        action_type: "collect_diagnostics",
        target_type: "device",
        target_id: "device-1",
        rationale: "Collect process and control state for analyst review.",
      }),
    });
    expect(proposal.status).toBe(201);
    const proposed = await proposal.json() as { action_id: string; status: string };
    expect(proposed.status).toBe("approved");

    const poll = await signedCollectorRequest(
      "GET",
      "/v1/agent/actions?device_id=device-1",
      tenant.credentialId,
      tenant.secret,
    );
    expect(poll.status).toBe(200);
    const polled = await poll.json() as { actions: Array<{ action_id: string }> };
    expect(polled.actions.map((action) => action.action_id)).toContain(proposed.action_id);

    const result = await signedCollectorRequest(
      "POST",
      `/v1/agent/actions/${proposed.action_id}/result`,
      tenant.credentialId,
      tenant.secret,
      JSON.stringify({
        status: "succeeded",
        summary: "Read-only diagnostics collected.",
        evidence: ["endpoint controls enumerated", "process inventory captured"],
      }),
    );
    expect(result.status).toBe(200);
    const stored = await env.DB.prepare(
      "SELECT status, result_json FROM response_actions WHERE tenant_id = ? AND action_id = ?",
    ).bind(tenant.tenantId, proposed.action_id).first<{ status: string; result_json: string }>();
    expect(stored?.status).toBe("succeeded");
    expect(stored?.result_json).toContain("diagnostics collected");
  });

  it("fails closed when AI triage is not configured", async () => {
    const tenant = await createTenant();
    const eventId = crypto.randomUUID();
    const alertId = crypto.randomUUID();
    const now = new Date().toISOString();
    await env.DB.batch([
      env.DB.prepare(
        `INSERT INTO events(
          tenant_id, event_id, event_type, occurred_at, received_at, actor, attributes_json, payload_sha256
        ) VALUES (?, ?, 'edge_auth_failure', ?, ?, 'user@example.com', '{}', ?)`,
      ).bind(tenant.tenantId, eventId, now, now, "a".repeat(64)),
      env.DB.prepare(
        `INSERT INTO alerts(
          tenant_id, alert_id, event_id, rule_id, title, severity, actor, reasons_json, tags_json, created_at
        ) VALUES (?, ?, ?, 'CF-EDGE-002', 'Credential stuffing', 'high', 'user@example.com', '["20 failures"]', '[]', ?)`,
      ).bind(tenant.tenantId, alertId, eventId, now),
    ]);
    const response = await call(`/v1/alerts/${alertId}/triage`, {
      method: "POST",
      headers: { ...authorization, "x-controlforge-tenant-id": tenant.tenantId },
    });
    expect(response.status).toBe(503);
  });

  it("permits a distinct principal decision and rejects a repeated decision", async () => {
    const tenant = await createTenant();
    const now = new Date().toISOString();
    const caseId = crypto.randomUUID();
    const actionId = crypto.randomUUID();
    await env.DB.batch([
      env.DB.prepare(
        `INSERT INTO cases(tenant_id, case_id, title, priority, status, opened_at, updated_at)
         VALUES (?, ?, 'Identity takeover', 'critical', 'open', ?, ?)`,
      ).bind(tenant.tenantId, caseId, now, now),
      env.DB.prepare(
        `INSERT INTO response_actions(
          tenant_id, action_id, case_id, action_type, target_type, target_id, rationale,
          risk_level, status, proposed_by, proposed_at, expires_at
        ) VALUES (?, ?, ?, 'revoke_sessions', 'identity', 'user@example.com', ?,
          'high_impact', 'proposed', 'first-analyst', ?, ?)`,
      ).bind(
        tenant.tenantId,
        actionId,
        caseId,
        "Revoke active sessions after confirmed account takeover.",
        now,
        new Date(Date.now() + 60_000).toISOString(),
      ),
    ]);
    const decide = (): Promise<Response> => call(`/v1/actions/${actionId}/decision`, {
      method: "POST",
      headers: {
        ...authorization,
        "content-type": "application/json",
        "x-controlforge-tenant-id": tenant.tenantId,
      },
      body: JSON.stringify({ decision: "approve", rationale: "Independent approval granted." }),
    });
    expect((await decide()).status).toBe(200);
    expect((await decide()).status).toBe(409);
  });

  it("rejects an expired active-response decision without changing its state", async () => {
    const tenant = await createTenant();
    const now = new Date().toISOString();
    const caseId = crypto.randomUUID();
    const actionId = crypto.randomUUID();
    await env.DB.batch([
      env.DB.prepare(
        `INSERT INTO cases(tenant_id, case_id, title, priority, status, opened_at, updated_at)
         VALUES (?, ?, 'Expired containment request', 'critical', 'open', ?, ?)`,
      ).bind(tenant.tenantId, caseId, now, now),
      env.DB.prepare(
        `INSERT INTO response_actions(
          tenant_id, action_id, case_id, action_type, target_type, target_id, rationale,
          risk_level, status, proposed_by, proposed_at, expires_at
        ) VALUES (?, ?, ?, 'isolate_endpoint', 'device', ?, ?,
          'active', 'proposed', 'first-analyst', ?, ?)`,
      ).bind(
        tenant.tenantId,
        actionId,
        caseId,
        tenant.deviceId,
        "Containment approval window elapsed before a second analyst responded.",
        now,
        new Date(Date.now() - 60_000).toISOString(),
      ),
    ]);

    const response = await call(`/v1/actions/${actionId}/decision`, {
      method: "POST",
      headers: {
        ...authorization,
        "content-type": "application/json",
        "x-controlforge-tenant-id": tenant.tenantId,
      },
      body: JSON.stringify({ decision: "approve", rationale: "Late approval must fail closed." }),
    });
    expect(response.status).toBe(409);
    const stored = await env.DB.prepare(
      "SELECT status, approved_by, approved_at FROM response_actions WHERE tenant_id = ? AND action_id = ?",
    ).bind(tenant.tenantId, actionId).first<{
      approved_at: string | null;
      approved_by: string | null;
      status: string;
    }>();
    expect(stored).toEqual({ status: "proposed", approved_by: null, approved_at: null });
  });
});
