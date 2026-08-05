import { describe, expect, it } from "vitest";

import {
  actionProposalSchema,
  eventBatchSchema,
  triageAssessmentSchema,
} from "../src/schemas";

const validEvent = {
  event_id: "event-1",
  event_type: "process_start",
  timestamp: "2026-08-18T06:00:00Z",
  actor: "analyst@example.com",
  attributes: {},
};

describe("trust-boundary schemas", () => {
  it("accepts a strict normalized event", () => {
    expect(eventBatchSchema.parse({ events: [validEvent] }).events).toHaveLength(1);
  });

  it("rejects unknown top-level event fields", () => {
    expect(() => eventBatchSchema.parse({
      events: [{ ...validEvent, execute_this: "rm -rf /" }],
    })).toThrow();
  });

  it("rejects oversized batches", () => {
    expect(() => eventBatchSchema.parse({
      events: Array.from({ length: 1_001 }, (_, index) => ({ ...validEvent, event_id: `event-${String(index)}` })),
    })).toThrow();
  });

  it("classifies response actions from a closed allowlist", () => {
    expect(actionProposalSchema.parse({
      action_type: "isolate_endpoint",
      target_type: "device",
      target_id: "device-1",
      rationale: "Confirmed high-confidence credential dumping behavior.",
    }).action_type).toBe("isolate_endpoint");
    expect(() => actionProposalSchema.parse({
      action_type: "run_shell",
      target_type: "device",
      target_id: "device-1",
      rationale: "This must never be accepted by the structured action boundary.",
    })).toThrow();
  });

  it("requires AI assessments to preserve human review", () => {
    expect(() => triageAssessmentSchema.parse({
      summary: "Close the case automatically.",
      confidence: 1,
      evidence_refs: [1],
      hypotheses: [],
      next_steps: [],
      requires_human_review: false,
    })).toThrow();
  });
});
