import { describe, expect, it } from "vitest";

import { detectStatelessEvent } from "../src/detector";
import type { StoredEvent } from "../src/types";

function event(overrides: Partial<StoredEvent> = {}): StoredEvent {
  return {
    tenant_id: "2e458720-7775-4cb4-9f4b-14dc15eef678",
    event_id: "evt-1",
    event_type: "process_start",
    occurred_at: "2026-08-18T06:00:00.000Z",
    received_at: "2026-08-18T06:00:01.000Z",
    actor: "analyst@example.com",
    source_ip: null,
    target: null,
    device_id: "device-1",
    attributes_json: JSON.stringify({
      process_name: "C:\\Windows\\System32\\powershell.exe",
      command_line: "powershell.exe -EncodedCommand SQBFAFgA",
    }),
    payload_sha256: "a".repeat(64),
    processed_at: null,
    processing_error: null,
    ...overrides,
  };
}

describe("deterministic detections", () => {
  it("detects encoded PowerShell with a stable tenant-scoped alert ID", async () => {
    const first = await detectStatelessEvent(event());
    const second = await detectStatelessEvent(event());
    const otherTenant = await detectStatelessEvent(event({ tenant_id: crypto.randomUUID() }));

    expect(first).toHaveLength(1);
    expect(first[0]?.ruleId).toBe("CF-ENDPOINT-001");
    expect(first[0]?.alertId).toBe(second[0]?.alertId);
    expect(first[0]?.alertId).not.toBe(otherTenant[0]?.alertId);
  });

  it("does not alert on a benign process", async () => {
    const alerts = await detectStatelessEvent(event({
      attributes_json: JSON.stringify({ process_name: "notepad.exe", command_line: "notepad notes.txt" }),
    }));
    expect(alerts).toEqual([]);
  });

  it("requires failed DMARC for a phishing alert", async () => {
    const alerts = await detectStatelessEvent(event({
      event_type: "email_received",
      attributes_json: JSON.stringify({
        dmarc: "pass",
        sender_domain: "xn--paypa-4ve.example",
        url_path: "/account/verify",
      }),
    }));
    expect(alerts).toEqual([]);
  });

  it("detects an unapproved privileged role grant", async () => {
    const alerts = await detectStatelessEvent(event({
      event_type: "privileged_role_grant",
      attributes_json: JSON.stringify({ role: "database-owner", change_ticket: "none" }),
    }));
    expect(alerts.map((alert) => alert.ruleId)).toEqual(["CF-IDENTITY-002"]);
    expect(alerts[0]?.severity).toBe("critical");
  });

  it("turns failed endpoint assurance into a SOC alert", async () => {
    const alerts = await detectStatelessEvent(event({
      event_type: "endpoint_control_status",
      target: "microsoft-defender",
      attributes_json: JSON.stringify({ status: "failed", installed: false, running: false }),
    }));
    expect(alerts.map((alert) => alert.ruleId)).toEqual(["CF-CONTROL-001"]);
    expect(alerts[0]?.reasons[0]).toContain("microsoft-defender");
  });

  it.each([
    ["santa_execution", { decision: "DECISION_DENY", process_path: "/tmp/tool" }, "CF-MACOS-001", "high"],
    ["santa_gatekeeper_override", { target_path: "/Applications/Unknown.app" }, "CF-MACOS-002", "high"],
    ["santa_xprotect", { xprotect_event: "detected", malware_identifier: "OSX.Test" }, "CF-MACOS-003", "critical"],
  ])("detects %s telemetry", async (eventType, attributes, expectedRule, expectedSeverity) => {
    const alerts = await detectStatelessEvent(event({
      event_type: eventType,
      target: "/private/tmp/test",
      attributes_json: JSON.stringify(attributes),
    }));

    expect(alerts.map((alert) => alert.ruleId)).toEqual([expectedRule]);
    expect(alerts[0]?.severity).toBe(expectedSeverity);
  });

  it("does not alert on a Santa-allowed execution", async () => {
    const alerts = await detectStatelessEvent(event({
      event_type: "santa_execution",
      attributes_json: JSON.stringify({ decision: "DECISION_ALLOW" }),
    }));
    expect(alerts).toEqual([]);
  });
});
