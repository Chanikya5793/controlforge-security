import { describe, expect, it } from "vitest";

import {
  evaluateCanonicalRule,
  type CanonicalEvent,
  type CompiledRule,
} from "../src/sigma";

function event(attributes: Record<string, unknown> = {}): CanonicalEvent {
  return {
    event_id: "sigma-event-1",
    event_type: "test_event",
    timestamp: "2026-08-22T12:00:00Z",
    actor: "analyst@example.com",
    source_ip: "203.0.113.10",
    attributes,
  };
}

function rule(detection: Record<string, unknown>): CompiledRule {
  return {
    id: "TEST-SIGMA-001",
    rule_version: 1,
    rule_digest: `sha256:${"a".repeat(64)}`,
    title: "Sigma contract test",
    detection,
    level: "medium",
    tags: ["test"],
  };
}

describe("canonical Sigma evaluator boundaries", () => {
  it("supports wildcard equality and one-of selection patterns", () => {
    const decision = evaluateCanonicalRule(rule({
      selection_actor: { actor: "analyst@*.com" },
      selection_unused: { actor: "nobody@example.com" },
      condition: "1 of selection_*",
    }), event());
    expect(decision?.rule_id).toBe("TEST-SIGMA-001");
  });

  it("supports all-of, selection branches, and list-valued telemetry", () => {
    const decision = evaluateCanonicalRule(rule({
      selection_one: [{ role: "unused" }, { role: ["admin", "owner"] }],
      selection_two: { "groups|contains": "security" },
      condition: "all of selection_*",
    }), event({ role: "owner", groups: ["finance", "Security-Team"] }));
    expect(decision).not.toBeNull();
  });

  it.each([
    ["203.0.113.10", "203.0.113.0/24", true],
    ["198.51.100.10", "203.0.113.0/24", false],
    ["2001:db8::10", "2001:db8::/32", true],
    ["2001:db9::10", "2001:db8::/32", false],
    ["not-an-ip", "203.0.113.0/24", false],
  ])("evaluates CIDR membership for %s", (sourceIp, network, matched) => {
    const candidate = event();
    candidate.source_ip = sourceIp;
    expect(evaluateCanonicalRule(rule({
      selection: { "source_ip|cidr": network },
      condition: "selection",
    }), candidate) !== null).toBe(matched);
  });

  it("supports startswith and explicit nested negation", () => {
    expect(evaluateCanonicalRule(rule({
      selection: { "actor|startswith": "analyst@" },
      excluded: { actor: "blocked@example.com" },
      condition: "selection and not (not not excluded)",
    }), event())).not.toBeNull();
  });

  it.each([
    [{ selection: { actor: "x" }, condition: "missing" }, "unknown selection"],
    [{ selection: { "actor|unsupported": "x" }, condition: "selection" }, "unsupported Sigma modifier"],
    [{ selection: "invalid", condition: "selection" }, "must be a mapping"],
    [{ selection: { actor: "x" }, condition: "(selection" }, "unclosed parenthesis"],
    [{ selection: { actor: "x" }, condition: "" }, "cannot be empty"],
    [{ selection: { actor: "x" } }, "detection.condition must be a string"],
  ])("fails closed on malformed rules", (detection, message) => {
    expect(() => evaluateCanonicalRule(rule(detection), event())).toThrow(message);
  });
});
