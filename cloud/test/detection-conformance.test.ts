import { describe, expect, it } from "vitest";

import fixtureJson from "../../tests/fixtures/detection_conformance/stateless.v1.json";
import fingerprintJson from "../../tests/fixtures/detection_conformance/fingerprints.v1.json";
import { detectStatelessEvent } from "../src/detector";
import { alertFingerprintV1, detectCanonicalStatelessEvent } from "../src/sigma";
import type { StoredEvent } from "../src/types";

interface RuleMetadata {
  rule_version: number;
  rule_digest: string;
  title: string;
  severity: string;
  tags: string[];
}

interface EventInput {
  event_id: string;
  event_type: string;
  timestamp: string;
  actor: string;
  source_ip?: string;
  target?: string;
  device_id?: string;
  attributes: Record<string, unknown>;
}

interface Vector {
  id: string;
  event: EventInput;
  expected_rule_ids: string[];
  expected_reasons: string[];
}

interface Fixture {
  contract_version: "1.0";
  rules: Record<string, RuleMetadata>;
  vectors: Vector[];
}

const fixture = fixtureJson as Fixture;

function expectedDecisions(vector: Vector): Array<Record<string, unknown>> {
  return vector.expected_rule_ids.map((ruleId) => ({
    contract_version: fixture.contract_version,
    matched: true,
    rule_id: ruleId,
    ...fixture.rules[ruleId],
    event_id: vector.event.event_id,
    actor: vector.event.actor,
    reasons: vector.expected_reasons,
    created_at: vector.event.timestamp,
  }));
}

function storedEvent(event: EventInput): StoredEvent {
  return {
    tenant_id: "2e458720-7775-4cb4-9f4b-14dc15eef678",
    event_id: event.event_id,
    event_type: event.event_type,
    occurred_at: event.timestamp,
    received_at: event.timestamp,
    actor: event.actor,
    source_ip: event.source_ip ?? null,
    target: event.target ?? null,
    device_id: event.device_id ?? null,
    attributes_json: JSON.stringify(event.attributes),
    payload_sha256: "a".repeat(64),
    processed_at: null,
    processing_error: null,
  };
}

describe("shared stateless detection conformance", () => {
  for (const vector of fixture.vectors) {
    it(`matches the exact canonical projection for ${vector.id}`, () => {
      expect(detectCanonicalStatelessEvent(vector.event)).toEqual(expectedDecisions(vector));
    });

    it(`does not drift from the deployed detector for ${vector.id}`, async () => {
      const legacy = await detectStatelessEvent(storedEvent(vector.event));
      expect(legacy.map((alert) => alert.ruleId)).toEqual(vector.expected_rule_ids);
      expect(legacy.flatMap((alert) => alert.reasons)).toEqual(vector.expected_reasons);
    });
  }
});

describe("shared alert fingerprint conformance", () => {
  for (const vector of fingerprintJson.vectors) {
    it(`matches the portable v1 occurrence ID for ${vector.event_id}`, async () => {
      await expect(alertFingerprintV1(vector.tenant_id, vector.rule_id, vector.event_id))
        .resolves.toBe(vector.expected_alert_id);
    });
  }
});
