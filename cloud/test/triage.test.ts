import { env } from "cloudflare:workers";
import { afterEach, describe, expect, it, vi } from "vitest";

import { triageAlert, TriageError } from "../src/triage";
import type { AlertRow, Env } from "../src/types";

function triageEnvironment(): Env {
  return {
    DB: env.DB,
    EVENT_QUEUE: env.EVENT_QUEUE as Queue,
    ENVIRONMENT: "test",
    ADMIN_TOKEN: "a".repeat(48),
    CREDENTIAL_KEK: btoa(String.fromCharCode(...new Uint8Array(32).fill(7))),
    AUDIT_HMAC_SECRET: "audit-secret-for-test-environment-only",
    ACCESS_TEAM_DOMAIN: "",
    ACCESS_AUD: "",
    TRIAGE_PROVIDER: "gemini",
    META_MODEL: "fixture-meta-model",
    GEMINI_API_KEY: "fixture-api-key-for-tests-only",
    GEMINI_MODEL: "fixture-model",
  };
}

async function storedAlert(): Promise<AlertRow> {
  const tenantId = crypto.randomUUID();
  const eventId = crypto.randomUUID();
  const alertId = crypto.randomUUID();
  const now = new Date().toISOString();
  await env.DB.batch([
    env.DB.prepare(
      "INSERT INTO tenants(tenant_id, slug, display_name, status, created_at) VALUES (?, ?, 'Triage Test', 'active', ?)",
    ).bind(tenantId, `triage-${tenantId.slice(0, 8)}`, now),
    env.DB.prepare(
      `INSERT INTO events(
        tenant_id, event_id, event_type, occurred_at, received_at, actor, attributes_json, payload_sha256
      ) VALUES (?, ?, 'edge_auth_failure', ?, ?, 'user@example.com', '{}', ?)`,
    ).bind(tenantId, eventId, now, now, "a".repeat(64)),
    env.DB.prepare(
      `INSERT INTO alerts(
        tenant_id, alert_id, event_id, rule_id, title, severity, actor, reasons_json, tags_json, created_at
      ) VALUES (?, ?, ?, 'CF-EDGE-002', 'Credential stuffing', 'high', 'user@example.com', ?, ?, ?)`,
    ).bind(
      tenantId,
      alertId,
      eventId,
      JSON.stringify(["20 failures from one IP", "12 accounts targeted"]),
      JSON.stringify(["edge-security", "account-takeover"]),
      now,
    ),
  ]);
  const alert = await env.DB.prepare(
    "SELECT * FROM alerts WHERE tenant_id = ? AND alert_id = ?",
  ).bind(tenantId, alertId).first<AlertRow>();
  if (!alert) throw new Error("test alert missing");
  return alert;
}

afterEach(() => {
  vi.restoreAllMocks();
});

describe("evidence-bounded triage", () => {
  it("uses Meta's contributor model with schema-constrained output", async () => {
    const alert = await storedAlert();
    const environment = triageEnvironment();
    environment.TRIAGE_PROVIDER = "meta";
    environment.META_MODEL = "muse-spark-1.2-contributor";
    environment.META_MODEL_API_KEY = "fixture-meta-key-for-tests-only";
    const fetchMock = vi.spyOn(globalThis, "fetch").mockResolvedValue(new Response(JSON.stringify({
      choices: [{ message: { content: JSON.stringify({
        summary: "Deterministic evidence warrants review.",
        confidence: 0.74,
        evidence_refs: [1],
        hypotheses: ["Automated password attempts"],
        next_steps: ["Review the source IP across identity logs"],
        requires_human_review: true,
      }) } }],
    }), { status: 200, headers: { "content-type": "application/json" } }));

    const result = await triageAlert(
      environment,
      alert,
      { id: "analyst-1", type: "access_user" },
    );

    expect(result.model).toBe("muse-spark-1.2-contributor");
    const [requestUrl, requestInit] = fetchMock.mock.calls[0] ?? [];
    expect(requestUrl).toBe("https://api.meta.ai/v1/chat/completions");
    expect((requestInit?.headers as Record<string, string>).authorization).toBe(
      "Bearer fixture-meta-key-for-tests-only",
    );
    if (typeof requestInit?.body !== "string") throw new Error("expected a JSON request body");
    const requestBody = JSON.parse(requestInit.body) as {
      model: string;
      response_format: { type: string; json_schema: { strict: boolean } };
    };
    expect(requestBody.model).toBe("muse-spark-1.2-contributor");
    expect(requestBody.response_format).toMatchObject({
      type: "json_schema",
      json_schema: { strict: true },
    });
  });

  it("stores a structured assessment grounded in supplied evidence", async () => {
    const alert = await storedAlert();
    vi.spyOn(globalThis, "fetch").mockResolvedValue(new Response(JSON.stringify({
      candidates: [{ content: { parts: [{ text: JSON.stringify({
        summary: "Pattern warrants analyst review.",
        confidence: 0.82,
        evidence_refs: [1, 2],
        hypotheses: ["Credential-stuffing attempt"],
        next_steps: ["Review source reputation"],
        requires_human_review: true,
      }) }] } }],
    }), { status: 200, headers: { "content-type": "application/json" } }));

    const result = await triageAlert(
      triageEnvironment(),
      alert,
      { id: "analyst-1", type: "access_user", email: "analyst@example.com" },
    );
    expect(result.assessment.evidence_refs).toEqual([1, 2]);
    const stored = await env.DB.prepare(
      "SELECT assessment_json FROM triage_assessments WHERE assessment_id = ?",
    ).bind(result.assessment_id).first<{ assessment_json: string }>();
    expect(stored?.assessment_json).toContain("requires_human_review");
  });

  it("rejects evidence references outside the deterministic alert", async () => {
    const alert = await storedAlert();
    vi.spyOn(globalThis, "fetch").mockResolvedValue(new Response(JSON.stringify({
      candidates: [{ content: { parts: [{ text: JSON.stringify({
        summary: "Unsupported conclusion.",
        confidence: 0.5,
        evidence_refs: [3],
        hypotheses: [],
        next_steps: [],
        requires_human_review: true,
      }) }] } }],
    }), { status: 200, headers: { "content-type": "application/json" } }));

    await expect(triageAlert(
      triageEnvironment(),
      alert,
      { id: "analyst-1", type: "access_user" },
    )).rejects.toThrow(TriageError);
  });

  it("fails closed on provider errors and malformed output", async () => {
    const alert = await storedAlert();
    vi.spyOn(globalThis, "fetch").mockResolvedValueOnce(new Response("unavailable", { status: 429 }));
    await expect(triageAlert(
      triageEnvironment(), alert, { id: "analyst-1", type: "access_user" },
    )).rejects.toThrow(/HTTP 429/u);

    vi.spyOn(globalThis, "fetch").mockResolvedValueOnce(new Response(JSON.stringify({ candidates: [] }), {
      status: 200,
      headers: { "content-type": "application/json" },
    }));
    await expect(triageAlert(
      triageEnvironment(), alert, { id: "analyst-1", type: "access_user" },
    )).rejects.toThrow(/invalid response envelope/u);
  });
});
