import { env, exports } from "cloudflare:workers";
import {
  createExecutionContext,
  createMessageBatch,
  getQueueResult,
} from "cloudflare:test";
import { describe, expect, it, vi } from "vitest";

import worker from "../src/index";
import { hmacHex, sha256Hex } from "../src/security";
import type { Env, QueuedEvent } from "../src/types";

const authorization = { authorization: `Bearer ${"a".repeat(48)}` };

async function call(path: string, init: RequestInit = {}): Promise<Response> {
  return exports.default.fetch(new Request(`https://controlforge.test${path}`, init));
}

async function createTenant(): Promise<{
  credentialId: string;
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
    expect(await response.text()).toContain("Autonomous SOC");
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
      "SELECT secret_ciphertext, secret_iv FROM collector_credentials WHERE credential_id = ?",
    ).bind(tenant.credentialId).first<{ secret_ciphertext: string; secret_iv: string }>();
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
    const alerts = await alertsResponse.json() as Array<{ rule_id: string }>;
    expect(alerts.map((alert) => alert.rule_id)).toContain("CF-ENDPOINT-001");
    const caseCount = await env.DB.prepare(
      "SELECT COUNT(*) AS count FROM cases WHERE tenant_id = ?",
    ).bind(tenant.tenantId).first<{ count: number }>();
    expect(caseCount?.count).toBe(1);
  });

  it("accepts collector batches larger than one queue batch", async () => {
    const tenant = await createTenant();
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
  });

  it("requeues accepted events left unprocessed by an interrupted ingestion", async () => {
    const tenant = await createTenant();
    const eventId = `orphan-${crypto.randomUUID()}`;
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
    expect(sendBatch).toHaveBeenCalled();
    const queuedEventIds = sendBatch.mock.calls.flatMap(([messages]) => (
      Array.from(messages, (message) => (message.body as QueuedEvent).eventId)
    ));
    expect(queuedEventIds).toContain(eventId);
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
});
