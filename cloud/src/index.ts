import { Hono } from "hono";
import { z } from "zod";

import { dashboardHtml } from "./dashboard";
import { detectEvent } from "./detector";
import {
  appendAudit,
  loadEvent,
  mapAlert,
  markEventProcessed,
  persistAlertAndCase,
  persistEvents,
} from "./repository";
import {
  actionDecisionSchema,
  actionProposalSchema,
  actionResultSchema,
  createTenantSchema,
  eventBatchSchema,
} from "./schemas";
import {
  AuthenticationError,
  encryptCollectorSecret,
  generateSecret,
  requireAnalyst,
  requireCollector,
} from "./security";
import { triageAlert, TriageError } from "./triage";
import type {
  AlertRow,
  AuthenticatedPrincipal,
  CaseRow,
  Env,
  QueuedEvent,
} from "./types";

type AppContext = { Bindings: Env };
const app = new Hono<AppContext>();

class AuthorizationError extends Error {}
class BadRequestError extends Error {}

function jsonError(message: string, status: 400 | 401 | 403 | 404 | 409 | 413 | 500 | 503): Response {
  return Response.json({ error: message }, { status });
}

function boundedLimit(value: string | undefined, defaultValue = 100): number {
  const parsed = Number(value ?? defaultValue);
  if (!Number.isInteger(parsed) || parsed < 1 || parsed > 1_000) {
    throw new BadRequestError("limit must be an integer between 1 and 1000");
  }
  return parsed;
}

async function requireTenant(
  request: Request,
  env: Env,
): Promise<{ principal: AuthenticatedPrincipal; tenantId: string }> {
  const principal = await requireAnalyst(request, env);
  const tenantId = request.headers.get("x-controlforge-tenant-id") ?? "";
  if (!/^[0-9a-f-]{36}$/iu.test(tenantId)) throw new AuthorizationError("valid tenant context is required");
  if (principal.type !== "admin_token") {
    const membership = await env.DB.prepare(
      "SELECT role FROM analyst_memberships WHERE tenant_id = ? AND principal_id = ?",
    ).bind(tenantId, principal.id).first<{ role: string }>();
    if (!membership) throw new AuthorizationError("principal is not a member of this tenant");
  }
  return { principal, tenantId };
}

app.use("*", async (context, next) => {
  const requestId = context.req.header("cf-ray") ?? crypto.randomUUID();
  context.header("x-controlforge-request-id", requestId);
  context.header("x-content-type-options", "nosniff");
  context.header("x-frame-options", "DENY");
  context.header("referrer-policy", "no-referrer");
  context.header("permissions-policy", "camera=(), microphone=(), geolocation=()");
  context.header("strict-transport-security", "max-age=63072000; includeSubDomains; preload");
  context.header("cache-control", "no-store");
  await next();
});

app.onError((error) => {
  if (error instanceof AuthenticationError) return jsonError("authentication failed", 401);
  if (error instanceof AuthorizationError) return jsonError(error.message, 403);
  if (error instanceof BadRequestError) return jsonError(error.message, 400);
  if (error instanceof TriageError) return jsonError(error.message, 503);
  if (error instanceof z.ZodError) return jsonError("request body failed schema validation", 400);
  if (error instanceof SyntaxError) return jsonError("request body must be valid JSON", 400);
  console.error("request failed", error instanceof Error ? error.message : "unknown error");
  return jsonError("request could not be completed", 500);
});

app.get("/health", (context) => context.json({
  status: "ok",
  service: "controlforge-soc",
  version: "0.3.0",
  environment: context.env.ENVIRONMENT,
}));

app.get("/", (context) => context.redirect("/dashboard", 302));

app.get("/dashboard", async (context) => {
  await requireAnalyst(context.req.raw, context.env);
  const nonce = generateSecret(18);
  context.header(
    "content-security-policy",
    `default-src 'none'; style-src 'nonce-${nonce}'; script-src 'nonce-${nonce}'; connect-src 'self'; img-src 'self'; base-uri 'none'; form-action 'none'; frame-ancestors 'none'`,
  );
  return context.html(dashboardHtml.replaceAll("__CSP_NONCE__", nonce));
});

app.post("/v1/admin/tenants", async (context) => {
  const principal = await requireAnalyst(context.req.raw, context.env);
  const input = createTenantSchema.parse(await context.req.json());
  const tenantId = crypto.randomUUID();
  const credentialId = crypto.randomUUID();
  const collectorSecret = generateSecret(32);
  const encrypted = await encryptCollectorSecret(collectorSecret, context.env.CREDENTIAL_KEK);
  const createdAt = new Date().toISOString();
  const expiresAt = new Date(Date.now() + input.credential_ttl_days * 86_400_000).toISOString();
  await context.env.DB.batch([
    context.env.DB.prepare(
      "INSERT INTO tenants(tenant_id, slug, display_name, status, created_at) VALUES (?, ?, ?, 'active', ?)",
    ).bind(tenantId, input.slug, input.display_name, createdAt),
    context.env.DB.prepare(
      "INSERT INTO analyst_memberships(tenant_id, principal_id, role, created_at) VALUES (?, ?, 'admin', ?)",
    ).bind(tenantId, principal.id, createdAt),
    context.env.DB.prepare(
      `INSERT INTO collector_credentials(
         credential_id, tenant_id, name, secret_ciphertext, secret_iv, created_at, expires_at
       ) VALUES (?, ?, ?, ?, ?, ?, ?)`,
    ).bind(
      credentialId, tenantId, input.credential_name, encrypted.ciphertext, encrypted.iv,
      createdAt, expiresAt,
    ),
  ]);
  await appendAudit(context.env, tenantId, "tenant.created", principal, "tenant", tenantId, {
    slug: input.slug,
    credential_id: credentialId,
  });
  return context.json({
    tenant_id: tenantId,
    credential: {
      credential_id: credentialId,
      secret: collectorSecret,
      expires_at: expiresAt,
      warning: "This collector secret is returned once and must be stored in a managed secret store.",
    },
  }, 201);
});

app.post("/v1/ingest/events", async (context) => {
  const body = await context.req.text();
  if (new TextEncoder().encode(body).byteLength > 8_000_000) {
    return jsonError("request exceeds the 8 MB ingestion limit", 413);
  }
  const principal = await requireCollector(context.req.raw, body, context.env);
  if (!principal.tenantId) throw new AuthorizationError("collector has no tenant");
  const input = eventBatchSchema.parse(JSON.parse(body));
  const result = await persistEvents(context.env, principal.tenantId, input.events);
  await appendAudit(
    context.env,
    principal.tenantId,
    "events.ingested",
    principal,
    "event_batch",
    crypto.randomUUID(),
    { accepted: result.accepted.length, duplicates: result.duplicates.length },
  );
  return context.json({
    accepted: result.accepted.length,
    duplicates: result.duplicates.length,
    event_ids: result.accepted,
  }, 202);
});

app.get("/v1/alerts", async (context) => {
  const { tenantId } = await requireTenant(context.req.raw, context.env);
  const limit = boundedLimit(context.req.query("limit"));
  const result = await context.env.DB.prepare(
    "SELECT * FROM alerts WHERE tenant_id = ? ORDER BY created_at DESC LIMIT ?",
  ).bind(tenantId, limit).all<AlertRow>();
  return context.json(result.results.map(mapAlert));
});

app.get("/v1/cases", async (context) => {
  const { tenantId } = await requireTenant(context.req.raw, context.env);
  const limit = boundedLimit(context.req.query("limit"));
  const result = await context.env.DB.prepare(
    "SELECT * FROM cases WHERE tenant_id = ? ORDER BY updated_at DESC LIMIT ?",
  ).bind(tenantId, limit).all<CaseRow>();
  return context.json(result.results.map((row) => ({
    case_id: row.case_id,
    title: row.title,
    priority: row.priority,
    status: row.status,
    opened_at: row.opened_at,
    updated_at: row.updated_at,
    closed_at: row.closed_at,
  })));
});

app.get("/v1/dashboard/summary", async (context) => {
  const { tenantId } = await requireTenant(context.req.raw, context.env);
  const [events, alerts, critical, cases] = await context.env.DB.batch([
    context.env.DB.prepare(
      "SELECT COUNT(*) AS count FROM events WHERE tenant_id = ? AND julianday(received_at) >= julianday('now') - 1",
    ).bind(tenantId),
    context.env.DB.prepare(
      "SELECT COUNT(*) AS count FROM alerts WHERE tenant_id = ? AND julianday(created_at) >= julianday('now') - 1",
    ).bind(tenantId),
    context.env.DB.prepare(
      "SELECT COUNT(*) AS count FROM cases WHERE tenant_id = ? AND priority = 'critical' AND status != 'closed'",
    ).bind(tenantId),
    context.env.DB.prepare(
      "SELECT COUNT(*) AS count FROM cases WHERE tenant_id = ? AND status != 'closed'",
    ).bind(tenantId),
  ]);
  const count = (result: D1Result | undefined): number => {
    if (!result) return 0;
    const row = result.results[0] as { count?: number } | undefined;
    return row?.count ?? 0;
  };
  return context.json({
    events_24h: count(events),
    alerts_24h: count(alerts),
    critical_open: count(critical),
    open_cases: count(cases),
  });
});

app.post("/v1/alerts/:alertId/triage", async (context) => {
  const { principal, tenantId } = await requireTenant(context.req.raw, context.env);
  const alert = await context.env.DB.prepare(
    "SELECT * FROM alerts WHERE tenant_id = ? AND alert_id = ?",
  ).bind(tenantId, context.req.param("alertId")).first<AlertRow>();
  if (!alert) return jsonError("alert not found", 404);
  return context.json(await triageAlert(context.env, alert, principal), 201);
});

const actionRisk = {
  collect_diagnostics: "read_only",
  enrich_indicator: "read_only",
  isolate_endpoint: "active",
  release_endpoint: "active",
  disable_identity: "high_impact",
  revoke_sessions: "high_impact",
} as const;

app.post("/v1/cases/:caseId/actions", async (context) => {
  const { principal, tenantId } = await requireTenant(context.req.raw, context.env);
  const input = actionProposalSchema.parse(await context.req.json());
  const existingCase = await context.env.DB.prepare(
    "SELECT case_id FROM cases WHERE tenant_id = ? AND case_id = ? AND status != 'closed'",
  ).bind(tenantId, context.req.param("caseId")).first<{ case_id: string }>();
  if (!existingCase) return jsonError("open case not found", 404);
  const actionId = crypto.randomUUID();
  const proposedAt = new Date().toISOString();
  const expiresAt = new Date(Date.now() + input.expires_in_minutes * 60_000).toISOString();
  const risk = actionRisk[input.action_type];
  const status = risk === "read_only" ? "approved" : "proposed";
  await context.env.DB.prepare(
    `INSERT INTO response_actions(
       tenant_id, action_id, case_id, action_type, target_type, target_id, rationale,
       risk_level, status, proposed_by, proposed_at, approved_by, approved_at, expires_at
     ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
  ).bind(
    tenantId, actionId, existingCase.case_id, input.action_type, input.target_type,
    input.target_id, input.rationale, risk, status, principal.id, proposedAt,
    risk === "read_only" ? "policy:auto-read-only" : null,
    risk === "read_only" ? proposedAt : null,
    expiresAt,
  ).run();
  await appendAudit(context.env, tenantId, "response.proposed", principal, "response_action", actionId, {
    action_type: input.action_type,
    risk_level: risk,
    status,
    case_id: existingCase.case_id,
  });
  return context.json({ action_id: actionId, status, risk_level: risk, expires_at: expiresAt }, 201);
});

app.post("/v1/actions/:actionId/decision", async (context) => {
  const { principal, tenantId } = await requireTenant(context.req.raw, context.env);
  const input = actionDecisionSchema.parse(await context.req.json());
  const action = await context.env.DB.prepare(
    "SELECT proposed_by, risk_level, status FROM response_actions WHERE tenant_id = ? AND action_id = ?",
  ).bind(tenantId, context.req.param("actionId")).first<{
    proposed_by: string;
    risk_level: string;
    status: string;
  }>();
  if (!action) return jsonError("response action not found", 404);
  if (action.status !== "proposed") return jsonError("response action is not awaiting a decision", 409);
  if (action.risk_level !== "read_only" && action.proposed_by === principal.id) {
    return jsonError("active response requires approval by a second principal", 409);
  }
  const status = input.decision === "approve" ? "approved" : "rejected";
  const decidedAt = new Date().toISOString();
  await context.env.DB.prepare(
    "UPDATE response_actions SET status = ?, approved_by = ?, approved_at = ? WHERE tenant_id = ? AND action_id = ?",
  ).bind(status, principal.id, decidedAt, tenantId, context.req.param("actionId")).run();
  await appendAudit(context.env, tenantId, `response.${status}`, principal, "response_action", context.req.param("actionId"), {
    decision_rationale: input.rationale,
  });
  return context.json({ action_id: context.req.param("actionId"), status });
});

app.get("/v1/agent/actions", async (context) => {
  const principal = await requireCollector(context.req.raw, "", context.env);
  if (!principal.tenantId) throw new AuthorizationError("collector has no tenant");
  const deviceId = context.req.query("device_id") ?? "";
  if (!/^[A-Za-z0-9._:-]{1,128}$/u.test(deviceId)) return jsonError("valid device_id is required", 400);
  const actions = await context.env.DB.prepare(
    `SELECT action_id, action_type, target_type, target_id, rationale, risk_level, expires_at
       FROM response_actions
      WHERE tenant_id = ? AND target_type = 'device' AND target_id = ?
        AND status IN ('approved', 'dispatched') AND expires_at > ?
      ORDER BY proposed_at LIMIT 20`,
  ).bind(principal.tenantId, deviceId, new Date().toISOString()).all();
  if (actions.results.length > 0) {
    await context.env.DB.prepare(
      `UPDATE response_actions SET status = 'dispatched'
        WHERE tenant_id = ? AND target_id = ? AND status = 'approved'`,
    ).bind(principal.tenantId, deviceId).run();
  }
  return context.json({ actions: actions.results });
});

app.post("/v1/agent/actions/:actionId/result", async (context) => {
  const body = await context.req.text();
  const principal = await requireCollector(context.req.raw, body, context.env);
  if (!principal.tenantId) throw new AuthorizationError("collector has no tenant");
  const input = actionResultSchema.parse(JSON.parse(body));
  const actionId = context.req.param("actionId");
  const result = await context.env.DB.prepare(
    `UPDATE response_actions SET status = ?, result_json = ?, completed_at = ?
      WHERE tenant_id = ? AND action_id = ? AND status = 'dispatched'`,
  ).bind(
    input.status,
    JSON.stringify({ summary: input.summary, evidence: input.evidence }),
    new Date().toISOString(),
    principal.tenantId,
    actionId,
  ).run();
  if (result.meta.changes !== 1) return jsonError("dispatched response action not found", 404);
  await appendAudit(context.env, principal.tenantId, `response.${input.status}`, principal, "response_action", actionId, {
    summary: input.summary,
    evidence_count: input.evidence.length,
  });
  return context.json({ action_id: actionId, status: input.status });
});

async function consumeEvent(message: Message<QueuedEvent>, env: Env): Promise<void> {
  const { tenantId, eventId } = message.body;
  try {
    const event = await loadEvent(env.DB, tenantId, eventId);
    if (!event) {
      message.ack();
      return;
    }
    if (event.processed_at) {
      message.ack();
      return;
    }
    const alerts = await detectEvent(event, env.DB);
    for (const alert of alerts) await persistAlertAndCase(env, tenantId, alert);
    await markEventProcessed(env.DB, tenantId, eventId);
    message.ack();
  } catch (error) {
    const summary = error instanceof Error ? error.message.slice(0, 500) : "unknown processing error";
    await markEventProcessed(env.DB, tenantId, eventId, summary);
    message.retry({ delaySeconds: 5 });
  }
}

const worker: ExportedHandler<Env, QueuedEvent> = {
  fetch: app.fetch,
  async queue(batch, env): Promise<void> {
    await Promise.all(batch.messages.map(async (message) => consumeEvent(message, env)));
  },
  async scheduled(_controller, env): Promise<void> {
    const now = new Date().toISOString();
    const pending = await env.DB.prepare(
      `SELECT tenant_id, event_id FROM events
       WHERE processed_at IS NULL
       ORDER BY received_at ASC
       LIMIT 1000`,
    ).all<{ tenant_id: string; event_id: string }>();
    for (let offset = 0; offset < pending.results.length; offset += 100) {
      await env.EVENT_QUEUE.sendBatch(pending.results.slice(offset, offset + 100).map((event) => ({
        body: {
          tenantId: event.tenant_id,
          eventId: event.event_id,
          attemptId: crypto.randomUUID(),
        },
        contentType: "json",
      })));
    }
    await env.DB.batch([
      env.DB.prepare("DELETE FROM ingestion_nonces WHERE expires_at < ?").bind(now),
      env.DB.prepare(
        "UPDATE response_actions SET status = 'expired' WHERE status IN ('proposed', 'approved', 'dispatched') AND expires_at < ?",
      ).bind(now),
    ]);
  },
};

export default worker;
