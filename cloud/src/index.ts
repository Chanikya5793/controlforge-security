import { Hono } from "hono";
import { z } from "zod";

import {
  isTenantRole,
  roleHasCapability,
  type Capability,
  type TenantRole,
} from "./authorization";
import {
  assignCase,
  appendCaseDisposition,
  appendCaseNote,
  CaseWorkflowError,
  transitionCase,
} from "./case-workflow";
import { dashboardHtml } from "./dashboard";
import { detectEvent, replayStoredSnapshot } from "./detector";
import {
  enforceIngestionLimits,
  loadOperationalHealth,
  requireIngestionCapacity,
  runTelemetryRetention,
  StorageCapacityError,
  TenantIngestionLimitError,
} from "./operational-safety";
import {
  loadCaseDetail,
  loadCaseQueue,
  loadDashboardSummary,
  loadResponseActions,
} from "./operations";
import {
  EventIdentityConflictError,
  loadEvent,
  mapAlert,
  markEventProcessed,
  markEventsProcessed,
  persistAlertAndCase,
  persistEvents,
  prepareAuditStatement,
} from "./repository";
import {
  actionDecisionSchema,
  actionProposalSchema,
  actionResultSchema,
  caseAssignmentSchema,
  caseDispositionSchema,
  caseNoteSchema,
  caseTransitionSchema,
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
import { compiledDetectionProvenance, parseDetectionSnapshot } from "./sigma";
import { triageAlert, TriageError } from "./triage";
import type {
  AlertRow,
  AuthenticatedPrincipal,
  CaseRow,
  Env,
  QueuedEvent,
  StoredEvent,
} from "./types";

type AppContext = { Bindings: Env };
const app = new Hono<AppContext>();
const SAFE_RECOVERY_EVENTS_PER_RUN = 500;
const GENERAL_RECOVERY_EVENTS_PER_RUN = 50;
const RECOVERY_CONCURRENCY = 20;

class AuthorizationError extends Error {}
class BadRequestError extends Error {}
class ReplayError extends Error {}

function requireHumanMutationBoundary(
  request: Request,
  principal: AuthenticatedPrincipal,
): void {
  if (principal.type === "admin_token") return;
  const origin = request.headers.get("origin");
  const fetchSite = request.headers.get("sec-fetch-site");
  if (origin !== new URL(request.url).origin || fetchSite !== "same-origin") {
    throw new AuthorizationError("same-origin human mutation is required");
  }
}

function jsonError(message: string, status: 400 | 401 | 403 | 404 | 409 | 413 | 429 | 500 | 503): Response {
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
  capability: Capability,
): Promise<{ principal: AuthenticatedPrincipal; tenantId: string; role: TenantRole }> {
  const principal = await requireAnalyst(request, env);
  const tenantId = request.headers.get("x-controlforge-tenant-id") ?? "";
  if (!/^[0-9a-f-]{36}$/iu.test(tenantId)) throw new AuthorizationError("valid tenant context is required");
  let role: TenantRole = "admin";
  if (principal.type !== "admin_token") {
    const membership = await env.DB.prepare(
      "SELECT role FROM analyst_memberships WHERE tenant_id = ? AND principal_id = ?",
    ).bind(tenantId, principal.id).first<{ role: string }>();
    if (!membership) throw new AuthorizationError("principal is not a member of this tenant");
    if (!isTenantRole(membership.role)) throw new AuthorizationError("principal has an invalid tenant role");
    role = membership.role;
  }
  if (!roleHasCapability(role, capability)) {
    throw new AuthorizationError("principal role does not permit this operation");
  }
  return { principal, tenantId, role };
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
  if (error instanceof ReplayError) return jsonError(error.message, 409);
  if (error instanceof EventIdentityConflictError) return jsonError(error.message, 409);
  if (error instanceof TenantIngestionLimitError) {
    const response = jsonError(error.message, 429);
    response.headers.set("retry-after", String(error.retryAfterSeconds));
    return response;
  }
  if (error instanceof StorageCapacityError) {
    const response = jsonError(error.message, 503);
    response.headers.set("retry-after", String(error.retryAfterSeconds));
    return response;
  }
  if (error instanceof CaseWorkflowError) {
    if (error.code === "case_not_found") return jsonError("case not found", 404);
    if (error.code === "disposition_required") {
      return jsonError("case closure requires a recorded disposition", 409);
    }
    if (error.code === "reopen_conflict") {
      return jsonError("case cannot be reopened while its semantic case is active", 409);
    }
    if (error.code === "assignee_not_found") {
      return jsonError("assignee is not an eligible member of this tenant", 409);
    }
    if (error.code === "assignment_conflict") {
      return jsonError("case assignment changed or is already current", 409);
    }
    return jsonError("case status transition is not allowed", 409);
  }
  if (error instanceof TriageError) return jsonError(error.message, 503);
  if (error instanceof z.ZodError) return jsonError("request body failed schema validation", 400);
  if (error instanceof SyntaxError) return jsonError("request body must be valid JSON", 400);
  console.error("request failed", error instanceof Error ? error.message : "unknown error");
  return jsonError("request could not be completed", 500);
});

app.get("/health", (context) => context.json({
  status: "ok",
  service: "controlforge-soc",
  version: "0.5.0",
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

app.get("/v1/me", async (context) => {
  const principal = await requireAnalyst(context.req.raw, context.env);
  const memberships = principal.type === "admin_token"
    ? await context.env.DB.prepare(
      `SELECT t.tenant_id, t.slug, t.display_name, 'admin' AS role
         FROM tenants t WHERE t.status = 'active' ORDER BY t.display_name`,
    ).all<{ tenant_id: string; slug: string; display_name: string; role: TenantRole }>()
    : await context.env.DB.prepare(
      `SELECT t.tenant_id, t.slug, t.display_name, m.role
         FROM analyst_memberships m
         JOIN tenants t ON t.tenant_id = m.tenant_id
        WHERE m.principal_id = ? AND t.status = 'active'
        ORDER BY t.display_name`,
    ).bind(principal.id).all<{
      tenant_id: string;
      slug: string;
      display_name: string;
      role: TenantRole;
    }>();
  return context.json({
    principal: {
      id: principal.id,
      type: principal.type,
      ...(principal.email ? { email: principal.email } : {}),
    },
    tenants: memberships.results,
  });
});

app.post("/v1/admin/tenants", async (context) => {
  const principal = await requireAnalyst(context.req.raw, context.env);
  requireHumanMutationBoundary(context.req.raw, principal);
  if (principal.type !== "admin_token") {
    const existingAdministration = await context.env.DB.prepare(
      "SELECT 1 AS allowed FROM analyst_memberships WHERE principal_id = ? AND role = 'admin' LIMIT 1",
    ).bind(principal.id).first<{ allowed: number }>();
    if (!existingAdministration) {
      throw new AuthorizationError("tenant creation requires an existing administrator");
    }
  }
  const input = createTenantSchema.parse(await context.req.json());
  const tenantId = crypto.randomUUID();
  const credentialId = crypto.randomUUID();
  const collectorSecret = generateSecret(32);
  const encrypted = await encryptCollectorSecret(collectorSecret, context.env.CREDENTIAL_KEK);
  const createdAt = new Date().toISOString();
  const expiresAt = new Date(Date.now() + input.credential_ttl_days * 86_400_000).toISOString();
  const audit = await prepareAuditStatement(
    context.env,
    tenantId,
    "tenant.created",
    principal,
    "tenant",
    tenantId,
    { slug: input.slug, credential_id: credentialId, device_id: input.device_id },
    true,
  );
  await context.env.DB.batch([
    context.env.DB.prepare(
      "INSERT INTO tenants(tenant_id, slug, display_name, status, created_at) VALUES (?, ?, ?, 'active', ?)",
    ).bind(tenantId, input.slug, input.display_name, createdAt),
    context.env.DB.prepare(
      "INSERT INTO analyst_memberships(tenant_id, principal_id, role, created_at) VALUES (?, ?, 'admin', ?)",
    ).bind(tenantId, principal.id, createdAt),
    context.env.DB.prepare(
      `INSERT INTO devices(
         tenant_id, device_id, display_name, status, created_at
       ) VALUES (?, ?, ?, 'pending', ?)`,
    ).bind(tenantId, input.device_id, input.device_name, createdAt),
    context.env.DB.prepare(
      `INSERT INTO collector_credentials(
         credential_id, tenant_id, device_id, name, secret_ciphertext, secret_iv,
         created_at, expires_at
       ) VALUES (?, ?, ?, ?, ?, ?, ?, ?)`,
    ).bind(
      credentialId, tenantId, input.device_id, input.credential_name,
      encrypted.ciphertext, encrypted.iv, createdAt, expiresAt,
    ),
    audit,
  ]);
  return context.json({
    tenant_id: tenantId,
    device: {
      device_id: input.device_id,
      display_name: input.device_name,
      status: "pending",
    },
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
  if (!principal.tenantId || !principal.deviceId) {
    throw new AuthorizationError("collector has no bound tenant and device");
  }
  const input = eventBatchSchema.parse(JSON.parse(body));
  if (input.events.some((event) => event.device_id !== principal.deviceId)) {
    throw new AuthorizationError("collector may ingest events only for its bound device");
  }
  await requireIngestionCapacity(context.env);
  await enforceIngestionLimits(
    context.env,
    principal.tenantId,
    principal.deviceId,
    input.events.length,
  );
  const result = await persistEvents(context.env, principal.tenantId, input.events);
  const observedAt = new Date().toISOString();
  const deviceUpdate = context.env.DB.prepare(
    `UPDATE devices
        SET status = 'active',
            first_seen_at = coalesce(first_seen_at, ?),
            last_seen_at = ?
      WHERE tenant_id = ? AND device_id = ? AND revoked_at IS NULL`,
  ).bind(
    observedAt,
    observedAt,
    principal.tenantId,
    principal.deviceId,
  );
  const audit = await prepareAuditStatement(
    context.env,
    principal.tenantId,
    "events.ingested",
    principal,
    "event_batch",
    crypto.randomUUID(),
    { accepted: result.accepted.length, duplicates: result.duplicates.length },
    true,
  );
  const [updatedDevice] = await context.env.DB.batch([deviceUpdate, audit]);
  if (updatedDevice?.meta.changes !== 1) {
    throw new AuthorizationError("collector device is no longer active");
  }
  return context.json({
    accepted: result.accepted.length,
    duplicates: result.duplicates.length,
    event_ids: result.accepted,
  }, 202);
});

app.get("/v1/alerts", async (context) => {
  const { tenantId } = await requireTenant(
    context.req.raw,
    context.env,
    "view_security_data",
  );
  const limit = boundedLimit(context.req.query("limit"));
  const result = await context.env.DB.prepare(
    "SELECT * FROM alerts WHERE tenant_id = ? ORDER BY created_at DESC LIMIT ?",
  ).bind(tenantId, limit).all<AlertRow>();
  return context.json(result.results.map(mapAlert));
});

app.get("/v1/cases", async (context) => {
  const { tenantId } = await requireTenant(
    context.req.raw,
    context.env,
    "view_security_data",
  );
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

app.get("/v1/case-queue", async (context) => {
  const { tenantId } = await requireTenant(
    context.req.raw,
    context.env,
    "view_security_data",
  );
  const limit = boundedLimit(context.req.query("limit"), 100);
  return context.json(await loadCaseQueue(context.env.DB, tenantId, limit));
});

app.get("/v1/cases/:caseId", async (context) => {
  const { tenantId } = await requireTenant(
    context.req.raw,
    context.env,
    "view_security_data",
  );
  const detail = await loadCaseDetail(
    context.env.DB,
    tenantId,
    context.req.param("caseId"),
  );
  if (!detail) return jsonError("case not found", 404);
  return context.json(detail);
});

app.post("/v1/cases/:caseId/notes", async (context) => {
  const { principal, tenantId } = await requireTenant(
    context.req.raw,
    context.env,
    "manage_case",
  );
  requireHumanMutationBoundary(context.req.raw, principal);
  const input = caseNoteSchema.parse(await context.req.json());
  return context.json(await appendCaseNote(
    context.env,
    tenantId,
    context.req.param("caseId"),
    input.body,
    principal,
  ), 201);
});

app.post("/v1/cases/:caseId/dispositions", async (context) => {
  const { principal, tenantId } = await requireTenant(
    context.req.raw,
    context.env,
    "manage_case",
  );
  requireHumanMutationBoundary(context.req.raw, principal);
  const input = caseDispositionSchema.parse(await context.req.json());
  return context.json(await appendCaseDisposition(
    context.env,
    tenantId,
    context.req.param("caseId"),
    input.disposition,
    input.rationale,
    input.false_positive_reason ?? null,
    principal,
  ), 201);
});

app.get("/v1/case-assignees", async (context) => {
  const { tenantId } = await requireTenant(
    context.req.raw,
    context.env,
    "view_security_data",
  );
  const memberships = await context.env.DB.prepare(
    `SELECT principal_id, role FROM analyst_memberships
      WHERE tenant_id = ? AND role IN ('analyst', 'responder', 'admin')
      ORDER BY role, principal_id LIMIT 500`,
  ).bind(tenantId).all<{ principal_id: string; role: TenantRole }>();
  return context.json({ assignees: memberships.results });
});

app.post("/v1/cases/:caseId/assignment", async (context) => {
  const { principal, tenantId } = await requireTenant(
    context.req.raw,
    context.env,
    "manage_case",
  );
  requireHumanMutationBoundary(context.req.raw, principal);
  const input = caseAssignmentSchema.parse(await context.req.json());
  return context.json(await assignCase(
    context.env,
    tenantId,
    context.req.param("caseId"),
    input.assignee_principal_id,
    principal,
  ));
});

app.post("/v1/cases/:caseId/transitions", async (context) => {
  const { principal, tenantId } = await requireTenant(
    context.req.raw,
    context.env,
    "manage_case",
  );
  requireHumanMutationBoundary(context.req.raw, principal);
  const input = caseTransitionSchema.parse(await context.req.json());
  return context.json(await transitionCase(
    context.env,
    tenantId,
    context.req.param("caseId"),
    input.status,
    principal,
  ));
});

app.get("/v1/response-actions", async (context) => {
  const { tenantId } = await requireTenant(
    context.req.raw,
    context.env,
    "view_security_data",
  );
  const limit = boundedLimit(context.req.query("limit"), 50);
  return context.json(await loadResponseActions(context.env.DB, tenantId, limit));
});

app.get("/v1/dashboard/summary", async (context) => {
  const { tenantId } = await requireTenant(
    context.req.raw,
    context.env,
    "view_security_data",
  );
  return context.json(
    await loadDashboardSummary(context.env.DB, tenantId, new Date().toISOString()),
  );
});

app.get("/v1/operations/storage-health", async (context) => {
  const { tenantId } = await requireTenant(
    context.req.raw,
    context.env,
    "view_security_data",
  );
  return context.json(await loadOperationalHealth(context.env, tenantId));
});

app.get("/v1/devices", async (context) => {
  const { tenantId } = await requireTenant(
    context.req.raw,
    context.env,
    "view_security_data",
  );
  const limit = boundedLimit(context.req.query("limit"));
  const devices = await context.env.DB.prepare(
    `SELECT device_id, display_name, status, platform, agent_version,
            first_seen_at, last_seen_at, created_at, revoked_at
       FROM devices WHERE tenant_id = ?
       ORDER BY coalesce(last_seen_at, created_at) DESC LIMIT ?`,
  ).bind(tenantId, limit).all();
  return context.json(devices.results);
});

app.get("/v1/devices/:deviceId", async (context) => {
  const { tenantId } = await requireTenant(
    context.req.raw,
    context.env,
    "view_security_data",
  );
  const device = await context.env.DB.prepare(
    `SELECT device_id, display_name, status, platform, agent_version,
            first_seen_at, last_seen_at, created_at, revoked_at
       FROM devices WHERE tenant_id = ? AND device_id = ?`,
  ).bind(tenantId, context.req.param("deviceId")).first();
  if (!device) return jsonError("device not found", 404);
  return context.json(device);
});

app.post("/v1/alerts/:alertId/triage", async (context) => {
  const { principal, tenantId } = await requireTenant(
    context.req.raw,
    context.env,
    "triage_alert",
  );
  requireHumanMutationBoundary(context.req.raw, principal);
  const alert = await context.env.DB.prepare(
    "SELECT * FROM alerts WHERE tenant_id = ? AND alert_id = ?",
  ).bind(tenantId, context.req.param("alertId")).first<AlertRow>();
  if (!alert) return jsonError("alert not found", 404);
  return context.json(await triageAlert(context.env, alert, principal), 201);
});

app.post("/v1/alerts/:alertId/replay", async (context) => {
  const { principal, tenantId } = await requireTenant(
    context.req.raw,
    context.env,
    "triage_alert",
  );
  requireHumanMutationBoundary(context.req.raw, principal);
  const alert = await context.env.DB.prepare(
    "SELECT * FROM alerts WHERE tenant_id = ? AND alert_id = ?",
  ).bind(tenantId, context.req.param("alertId")).first<AlertRow>();
  if (!alert) return jsonError("alert not found", 404);
  const event = await loadEvent(context.env.DB, tenantId, alert.event_id);
  if (!event) return jsonError("alert evidence is unavailable", 409);
  const mode = context.req.query("mode") ?? "current";
  if (mode !== "current" && mode !== "original") {
    throw new BadRequestError("replay mode must be current or original");
  }
  let recordedReasons: unknown;
  let recordedTags: unknown;
  try {
    recordedReasons = JSON.parse(alert.reasons_json) as unknown;
    recordedTags = JSON.parse(alert.tags_json) as unknown;
  } catch {
    throw new ReplayError("recorded alert decision is malformed");
  }
  if (
    !Array.isArray(recordedReasons) || !recordedReasons.every((item) => typeof item === "string") ||
    !Array.isArray(recordedTags) || !recordedTags.every((item) => typeof item === "string")
  ) throw new ReplayError("recorded alert decision is malformed");
  const originalAvailable = alert.rule_version !== null && alert.rule_digest !== null &&
    alert.rule_snapshot_json !== null;
  let replayed: Awaited<ReturnType<typeof detectEvent>>[number] | undefined;
  let evaluatedRuleVersion: number | null = null;
  let evaluatedRuleDigest: string | null = null;
  let snapshotKind: "sigma" | "builtin" | "correlation" | "unavailable" = "unavailable";
  let evidenceBasis: "source_event" | "current_retained_history" = "source_event";
  if (mode === "original") {
    if (!originalAvailable) throw new ReplayError("original replay is unavailable for this legacy alert");
    let rawSnapshot: unknown;
    try {
      rawSnapshot = JSON.parse(alert.rule_snapshot_json ?? "") as unknown;
    } catch {
      throw new ReplayError("stored rule snapshot is malformed");
    }
    try {
      const result = await replayStoredSnapshot(
        event,
        rawSnapshot,
        alert.rule_digest ?? "",
        context.env.DB,
      );
      replayed = result.alert ?? undefined;
      snapshotKind = result.snapshotKind;
      evidenceBasis = result.evidenceBasis;
      evaluatedRuleVersion = alert.rule_version;
      evaluatedRuleDigest = alert.rule_digest;
    } catch (error) {
      throw new ReplayError(error instanceof Error ? error.message : "original replay failed");
    }
  } else {
    const decisions = await detectEvent(event, context.env.DB);
    replayed = decisions.find((decision) => decision.ruleId === alert.rule_id);
    try {
      const provenance = compiledDetectionProvenance(alert.rule_id);
      const parsed = await parseDetectionSnapshot(provenance.ruleSnapshot, provenance.ruleDigest);
      evaluatedRuleVersion = provenance.ruleVersion;
      evaluatedRuleDigest = provenance.ruleDigest;
      snapshotKind = parsed.kind;
      evidenceBasis = parsed.kind === "correlation" ? "current_retained_history" : "source_event";
    } catch {
      // A removed rule is a valid current-detector no-match with unavailable provenance.
    }
  }
  const outcome = !replayed
    ? "no_match"
    : replayed.title === alert.title
        && replayed.severity === alert.severity
        && replayed.actor === alert.actor
        && JSON.stringify(replayed.reasons) === JSON.stringify(recordedReasons)
        && JSON.stringify(replayed.tags) === JSON.stringify(recordedTags)
      ? "same"
      : "changed";
  const evaluated = replayed
    ? {
        rule_id: replayed.ruleId,
        rule_version: replayed.ruleVersion,
        rule_digest: replayed.ruleDigest,
        title: replayed.title,
        severity: replayed.severity,
        actor: replayed.actor,
        reasons: replayed.reasons,
        tags: replayed.tags,
      }
    : null;
  const evaluationId = crypto.randomUUID();
  const createdAt = new Date().toISOString();
  const evaluationInsert = context.env.DB.prepare(
    `INSERT INTO alert_replay_evaluations(
       tenant_id, evaluation_id, alert_id, mode, outcome, evaluated_rule_version,
       evaluated_rule_digest, snapshot_kind, evidence_basis, result_json, created_by, created_at
     ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
  ).bind(
    tenantId,
    evaluationId,
    alert.alert_id,
    mode,
    outcome,
    evaluatedRuleVersion,
    evaluatedRuleDigest,
    snapshotKind,
    evidenceBasis,
    JSON.stringify({
      contract_version: "1.0",
      source_event_id: event.event_id,
      source_event_sha256: event.payload_sha256,
      evaluated,
    }),
    principal.id,
    createdAt,
  );
  const audit = await prepareAuditStatement(
    context.env,
    tenantId,
    "alert.replayed",
    principal,
    "alert",
    alert.alert_id,
    {
      evaluation_id: evaluationId,
      mode,
      outcome,
      original_available: originalAvailable,
      evaluated_rule_version: evaluatedRuleVersion,
      evaluated_rule_digest: evaluatedRuleDigest,
      snapshot_kind: snapshotKind,
      evidence_basis: evidenceBasis,
    },
    true,
  );
  await context.env.DB.batch([evaluationInsert, audit]);
  return context.json({
    evaluation_id: evaluationId,
    mode,
    outcome,
    original_available: originalAvailable,
    snapshot_kind: snapshotKind,
    evidence_basis: evidenceBasis,
    recorded: mapAlert(alert),
    evaluated,
    ...(mode === "current" ? { current: evaluated } : { original: evaluated }),
  }, 201);
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
  const { principal, tenantId, role } = await requireTenant(
    context.req.raw,
    context.env,
    "propose_read_only_action",
  );
  requireHumanMutationBoundary(context.req.raw, principal);
  const input = actionProposalSchema.parse(await context.req.json());
  const existingCase = await context.env.DB.prepare(
    "SELECT case_id FROM cases WHERE tenant_id = ? AND case_id = ? AND status != 'closed'",
  ).bind(tenantId, context.req.param("caseId")).first<{ case_id: string }>();
  if (!existingCase) return jsonError("open case not found", 404);
  const actionId = crypto.randomUUID();
  const proposedAt = new Date().toISOString();
  const expiresAt = new Date(Date.now() + input.expires_in_minutes * 60_000).toISOString();
  const risk = actionRisk[input.action_type];
  if (risk !== "read_only" && !roleHasCapability(role, "propose_active_action")) {
    throw new AuthorizationError("principal role cannot propose active response");
  }
  const status = risk === "read_only" ? "approved" : "proposed";
  const actionInsert = context.env.DB.prepare(
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
  );
  const audit = await prepareAuditStatement(
    context.env,
    tenantId,
    "response.proposed",
    principal,
    "response_action",
    actionId,
    {
      action_type: input.action_type,
      risk_level: risk,
      status,
      case_id: existingCase.case_id,
    },
    true,
  );
  await context.env.DB.batch([actionInsert, audit]);
  return context.json({ action_id: actionId, status, risk_level: risk, expires_at: expiresAt }, 201);
});

app.post("/v1/actions/:actionId/decision", async (context) => {
  const { principal, tenantId } = await requireTenant(
    context.req.raw,
    context.env,
    "approve_active_action",
  );
  requireHumanMutationBoundary(context.req.raw, principal);
  const input = actionDecisionSchema.parse(await context.req.json());
  const action = await context.env.DB.prepare(
    `SELECT proposed_by, risk_level, status, expires_at
       FROM response_actions WHERE tenant_id = ? AND action_id = ?`,
  ).bind(tenantId, context.req.param("actionId")).first<{
    proposed_by: string;
    risk_level: string;
    status: string;
    expires_at: string;
  }>();
  if (!action) return jsonError("response action not found", 404);
  if (action.status !== "proposed") return jsonError("response action is not awaiting a decision", 409);
  if (Date.parse(action.expires_at) <= Date.now()) {
    return jsonError("response action has expired", 409);
  }
  if (action.risk_level !== "read_only" && action.proposed_by === principal.id) {
    return jsonError("active response requires approval by a second principal", 409);
  }
  const status = input.decision === "approve" ? "approved" : "rejected";
  const decidedAt = new Date().toISOString();
  const decisionUpdate = context.env.DB.prepare(
    `UPDATE response_actions SET status = ?, approved_by = ?, approved_at = ?
      WHERE tenant_id = ? AND action_id = ? AND status = 'proposed' AND expires_at > ?`,
  ).bind(
    status,
    principal.id,
    decidedAt,
    tenantId,
    context.req.param("actionId"),
    decidedAt,
  );
  const audit = await prepareAuditStatement(
    context.env,
    tenantId,
    `response.${status}`,
    principal,
    "response_action",
    context.req.param("actionId"),
    { decision_rationale: input.rationale },
    true,
  );
  const [decision] = await context.env.DB.batch([decisionUpdate, audit]);
  if (decision?.meta.changes !== 1) {
    return jsonError("response action is no longer awaiting a decision", 409);
  }
  return context.json({ action_id: context.req.param("actionId"), status });
});

app.get("/v1/agent/actions", async (context) => {
  const principal = await requireCollector(context.req.raw, "", context.env);
  if (!principal.tenantId || !principal.deviceId) {
    throw new AuthorizationError("collector has no bound tenant and device");
  }
  const deviceId = context.req.query("device_id") ?? "";
  if (!/^[A-Za-z0-9._:-]{1,128}$/u.test(deviceId)) return jsonError("valid device_id is required", 400);
  if (deviceId !== principal.deviceId) {
    throw new AuthorizationError("collector may retrieve actions only for its bound device");
  }
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
  if (!principal.tenantId || !principal.deviceId) {
    throw new AuthorizationError("collector has no bound tenant and device");
  }
  const input = actionResultSchema.parse(JSON.parse(body));
  const actionId = context.req.param("actionId");
  const resultUpdate = context.env.DB.prepare(
    `UPDATE response_actions SET status = ?, result_json = ?, completed_at = ?
      WHERE tenant_id = ? AND action_id = ? AND target_type = 'device'
        AND target_id = ? AND status = 'dispatched'`,
  ).bind(
    input.status,
    JSON.stringify({ summary: input.summary, evidence: input.evidence }),
    new Date().toISOString(),
    principal.tenantId,
    actionId,
    principal.deviceId,
  );
  const audit = await prepareAuditStatement(
    context.env,
    principal.tenantId,
    `response.${input.status}`,
    principal,
    "response_action",
    actionId,
    { summary: input.summary, evidence_count: input.evidence.length },
    true,
  );
  const [result] = await context.env.DB.batch([resultUpdate, audit]);
  if (result?.meta.changes !== 1) return jsonError("dispatched response action not found", 404);
  return context.json({ action_id: actionId, status: input.status });
});

async function processEvent(env: Env, tenantId: string, eventId: string): Promise<void> {
  try {
    const event = await loadEvent(env.DB, tenantId, eventId);
    if (!event || event.processed_at) return;
    const alerts = await detectEvent(event, env.DB);
    for (const alert of alerts) await persistAlertAndCase(env, tenantId, alert, event);
    await markEventProcessed(env.DB, tenantId, eventId);
  } catch (error) {
    const summary = error instanceof Error ? error.message.slice(0, 500) : "unknown processing error";
    await markEventProcessed(env.DB, tenantId, eventId, summary);
    throw error;
  }
}

function parseQueuedEvent(body: unknown): { tenantId: string; eventIds: string[] } {
  if (!body || typeof body !== "object") throw new Error("queue body must be an object");
  const queued = body as Record<string, unknown>;
  if (typeof queued.tenantId !== "string" || !/^[0-9a-f-]{36}$/iu.test(queued.tenantId)) {
    throw new Error("queue body has an invalid tenant identity");
  }
  const eventIds = Array.isArray(queued.eventIds) ? queued.eventIds : [queued.eventId];
  if (
    eventIds.length < 1
    || eventIds.length > 50
    || eventIds.some((eventId) => (
      typeof eventId !== "string"
      || eventId.length > 128
      || !/^[A-Za-z0-9._:-]+$/u.test(eventId)
    ))
  ) {
    throw new Error("queue body has invalid event identities");
  }
  return { tenantId: queued.tenantId, eventIds: eventIds as string[] };
}

async function consumeEvent(message: Message<QueuedEvent>, env: Env): Promise<void> {
  try {
    const { tenantId, eventIds } = parseQueuedEvent(message.body);
    // Process sequentially so a full Queue delivery never multiplies D1 concurrency.
    for (const eventId of eventIds) await processEvent(env, tenantId, eventId);
    message.ack();
  } catch {
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
    const safePending = await env.DB.prepare(
      `SELECT * FROM events
       WHERE processed_at IS NULL AND event_type = 'santa_execution'
         AND upper(json_extract(attributes_json, '$.decision'))
             IN ('DECISION_ALLOW', 'DECISION_UNKNOWN')
       ORDER BY received_at ASC
       LIMIT ?`,
    ).bind(SAFE_RECOVERY_EVENTS_PER_RUN).all<StoredEvent>();
    for (const event of safePending.results) {
      const alerts = await detectEvent(event, env.DB);
      if (alerts.length > 0) {
        throw new Error("safe Santa recovery classification unexpectedly produced an alert");
      }
    }
    await markEventsProcessed(env.DB, safePending.results);

    const generalPending = await env.DB.prepare(
      `SELECT tenant_id, event_id FROM events
       WHERE processed_at IS NULL AND (
         event_type != 'santa_execution'
         OR coalesce(upper(json_extract(attributes_json, '$.decision')), '')
              NOT IN ('DECISION_ALLOW', 'DECISION_UNKNOWN')
       )
       ORDER BY received_at ASC
       LIMIT ?`,
    ).bind(GENERAL_RECOVERY_EVENTS_PER_RUN).all<{ tenant_id: string; event_id: string }>();
    // Reconcile directly from durable D1 state. Re-enqueueing every five minutes can
    // amplify Queue operations while a large ingestion backlog is still being consumed.
    for (let offset = 0; offset < generalPending.results.length; offset += RECOVERY_CONCURRENCY) {
      await Promise.all(generalPending.results.slice(offset, offset + RECOVERY_CONCURRENCY).map(
        async (event) => processEvent(env, event.tenant_id, event.event_id),
      ));
    }
    await env.DB.batch([
      env.DB.prepare("DELETE FROM ingestion_nonces WHERE expires_at < ?").bind(now),
      env.DB.prepare(
        "UPDATE response_actions SET status = 'expired' WHERE status IN ('proposed', 'approved', 'dispatched') AND expires_at < ?",
      ).bind(now),
    ]);
    await runTelemetryRetention(env);
  },
};

export default worker;
