import { describe, expect, it } from "vitest";

import { roleHasCapability } from "../src/authorization";

describe("tenant role capabilities", () => {
  it("keeps viewers read-only and analysts outside active response", () => {
    expect(roleHasCapability("viewer", "view_security_data")).toBe(true);
    expect(roleHasCapability("viewer", "triage_alert")).toBe(false);
    expect(roleHasCapability("viewer", "manage_case")).toBe(false);
    expect(roleHasCapability("viewer", "propose_read_only_action")).toBe(false);
    expect(roleHasCapability("analyst", "triage_alert")).toBe(true);
    expect(roleHasCapability("analyst", "manage_case")).toBe(true);
    expect(roleHasCapability("analyst", "propose_read_only_action")).toBe(true);
    expect(roleHasCapability("analyst", "propose_active_action")).toBe(false);
    expect(roleHasCapability("analyst", "approve_active_action")).toBe(false);
  });

  it("limits tenant administration and active approval to elevated roles", () => {
    expect(roleHasCapability("responder", "propose_active_action")).toBe(true);
    expect(roleHasCapability("responder", "approve_active_action")).toBe(true);
    expect(roleHasCapability("responder", "manage_tenant")).toBe(false);
    expect(roleHasCapability("admin", "manage_tenant")).toBe(true);
  });
});
