import { env } from "cloudflare:workers";
import { describe, expect, it } from "vitest";

import { detectEvent } from "../src/detector";
import type { StoredEvent } from "../src/types";

async function tenant(): Promise<string> {
  const tenantId = crypto.randomUUID();
  await env.DB.prepare(
    "INSERT INTO tenants(tenant_id, slug, display_name, status, created_at) VALUES (?, ?, ?, 'active', ?)",
  ).bind(tenantId, `detector-${tenantId.slice(0, 8)}`, "Detector Test", new Date().toISOString()).run();
  return tenantId;
}

async function insertEvent(
  tenantId: string,
  eventId: string,
  eventType: string,
  timestamp: string,
  actor: string,
  attributes: Record<string, unknown>,
  sourceIp: string | null = null,
): Promise<StoredEvent> {
  const receivedAt = new Date().toISOString();
  await env.DB.prepare(
    `INSERT INTO events(
      tenant_id, event_id, event_type, occurred_at, received_at, actor,
      source_ip, target, device_id, attributes_json, payload_sha256
    ) VALUES (?, ?, ?, ?, ?, ?, ?, NULL, NULL, ?, ?)`,
  ).bind(
    tenantId, eventId, eventType, timestamp, receivedAt, actor, sourceIp,
    JSON.stringify(attributes), "a".repeat(64),
  ).run();
  const stored = await env.DB.prepare(
    "SELECT * FROM events WHERE tenant_id = ? AND event_id = ?",
  ).bind(tenantId, eventId).first<StoredEvent>();
  if (!stored) throw new Error("test event was not persisted");
  return stored;
}

describe("stateful SIEM correlation", () => {
  it("detects bulk sensitive-data access by count", async () => {
    const tenantId = await tenant();
    let current: StoredEvent | undefined;
    for (let index = 0; index < 10; index += 1) {
      current = await insertEvent(
        tenantId,
        `bulk-${String(index)}`,
        "sensitive_data_access",
        `2026-08-18T06:${String(index).padStart(2, "0")}:00Z`,
        "contractor@example.com",
        { bytes: 1_000 },
      );
    }
    if (!current) throw new Error("current event missing");
    const alerts = await detectEvent(current, env.DB);
    expect(alerts.map((alert) => alert.ruleId)).toContain("CF-INSIDER-001");
  });

  it("detects impossible travel from the previous authentication", async () => {
    const tenantId = await tenant();
    await insertEvent(
      tenantId,
      "login-sfo",
      "authentication_success",
      "2026-08-18T06:00:00Z",
      "user@example.com",
      { latitude: 37.7749, longitude: -122.4194 },
    );
    const current = await insertEvent(
      tenantId,
      "login-nyc",
      "authentication_success",
      "2026-08-18T06:30:00Z",
      "user@example.com",
      { latitude: 40.7128, longitude: -74.0060 },
    );
    const alerts = await detectEvent(current, env.DB);
    expect(alerts.map((alert) => alert.ruleId)).toContain("CF-IDENTITY-001");
  });

  it("detects credential stuffing only after both thresholds are reached", async () => {
    const tenantId = await tenant();
    let current: StoredEvent | undefined;
    for (let index = 0; index < 20; index += 1) {
      current = await insertEvent(
        tenantId,
        `failure-${String(index)}`,
        "edge_auth_failure",
        `2026-08-18T06:00:${String(index).padStart(2, "0")}Z`,
        `account-${String(index % 10)}@example.com`,
        {},
        "198.51.100.44",
      );
    }
    if (!current) throw new Error("current event missing");
    const alerts = await detectEvent(current, env.DB);
    expect(alerts.map((alert) => alert.ruleId)).toContain("CF-EDGE-002");
  });

  it("detects cross-address reuse of a hashed session", async () => {
    const tenantId = await tenant();
    const sessionHash = "b".repeat(64);
    await insertEvent(
      tenantId,
      "session-one",
      "edge_session_use",
      "2026-08-18T06:00:00Z",
      "user@example.com",
      { session_id_hash: sessionHash },
      "198.51.100.10",
    );
    const current = await insertEvent(
      tenantId,
      "session-two",
      "edge_session_use",
      "2026-08-18T06:02:00Z",
      "user@example.com",
      { session_id_hash: sessionHash },
      "203.0.113.20",
    );
    const alerts = await detectEvent(current, env.DB);
    expect(alerts.map((alert) => alert.ruleId)).toContain("CF-EDGE-003");
  });
});
