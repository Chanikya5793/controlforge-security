import compiledRules from "./generated/rules.v1.json";
import { sha256Hex } from "./security";
import type { Severity } from "./types";

type Attributes = Record<string, unknown>;
type Selection = Record<string, unknown>;

export interface CanonicalEvent {
  event_id: string;
  event_type: string;
  timestamp: string;
  actor: string;
  source_ip?: string;
  target?: string;
  device_id?: string;
  attributes: Attributes;
}

export interface CompiledRule {
  id: string;
  rule_version: number;
  rule_digest: string;
  title: string;
  detection: Record<string, unknown>;
  level: Severity;
  tags: string[];
}

interface CompiledArtifact {
  contract_version: "1.0";
  rules: CompiledRule[];
  builtins: CompiledBuiltin[];
  correlations: CompiledCorrelation[];
}

export interface CompiledBuiltin {
  rule_id: string;
  rule_version: number;
  rule_digest: string;
  event_type: string;
  attribute: string;
  outcomes: Array<{ value: string; title: string; severity: Severity }>;
  tags: string[];
}

export interface CompiledCorrelation {
  rule_id: string;
  rule_version: number;
  rule_digest: string;
  title: string;
  severity: Severity;
  tags: string[];
  event_type: string;
  window_minutes: number | null;
  event_threshold: number | null;
  distinct_threshold: number | null;
  byte_threshold: number | null;
  maximum_speed_kph: number | null;
}

export interface CanonicalDetectionDecision {
  contract_version: "1.0";
  matched: true;
  rule_id: string;
  rule_version: number;
  rule_digest: string;
  title: string;
  severity: Severity;
  event_id: string;
  actor: string;
  reasons: string[];
  tags: string[];
  created_at: string;
}

const artifact = compiledRules as CompiledArtifact;
export const compiledCorrelations = artifact.correlations;
const operators = new Set(["contains", "startswith", "endswith", "re", "cidr"]);

export interface CompiledDetectionProvenance {
  ruleVersion: number;
  ruleDigest: string;
  ruleSnapshot: Record<string, unknown>;
}

export type DetectionSnapshot =
  | { kind: "sigma"; rule: CompiledRule }
  | { kind: "builtin"; rule: CompiledBuiltin }
  | { kind: "correlation"; rule: CompiledCorrelation };

const severityValues = new Set<Severity>([
  "informational", "low", "medium", "high", "critical",
]);

function record(value: unknown): Record<string, unknown> | null {
  return typeof value === "object" && value !== null && !Array.isArray(value)
    ? value as Record<string, unknown>
    : null;
}

function hasOnlyKeys(value: Record<string, unknown>, allowed: Set<string>): boolean {
  return Object.keys(value).every((key) => allowed.has(key));
}

function boundedString(value: unknown, maximum: number): value is string {
  return typeof value === "string" && value.length > 0 && value.length <= maximum;
}

function validVersion(value: unknown): value is number {
  return Number.isSafeInteger(value) && typeof value === "number" && value >= 1;
}

function validSeverity(value: unknown): value is Severity {
  return typeof value === "string" && severityValues.has(value as Severity);
}

function validTags(value: unknown): value is string[] {
  return Array.isArray(value) && value.length <= 128 && value.every((item) => boundedString(item, 128));
}

function canonicalJson(value: unknown): string {
  if (value === null || typeof value === "boolean" || typeof value === "string") {
    return JSON.stringify(value);
  }
  if (typeof value === "number") {
    if (!Number.isFinite(value)) throw new Error("snapshot contains a non-finite number");
    return JSON.stringify(value);
  }
  if (Array.isArray(value)) return `[${value.map((item) => canonicalJson(item)).join(",")}]`;
  const object = record(value);
  if (!object) throw new Error("snapshot contains an unsupported value");
  return `{${Object.keys(object).sort().map((key) => (
    `${JSON.stringify(key)}:${canonicalJson(object[key])}`
  )).join(",")}}`;
}

function parseSigmaSnapshot(value: Record<string, unknown>): CompiledRule | null {
  const allowed = new Set([
    "id", "rule_version", "title", "description", "status", "logsource",
    "detection", "level", "tags",
  ]);
  if (
    !hasOnlyKeys(value, allowed) || !boundedString(value.id, 128) ||
    !validVersion(value.rule_version) || !boundedString(value.title, 256) ||
    !validSeverity(value.level) || !validTags(value.tags) || !record(value.detection)
  ) return null;
  return value as unknown as CompiledRule;
}

function parseBuiltinSnapshot(value: Record<string, unknown>): CompiledBuiltin | null {
  const allowed = new Set([
    "rule_id", "rule_version", "event_type", "attribute", "outcomes", "tags",
  ]);
  if (
    !hasOnlyKeys(value, allowed) || !boundedString(value.rule_id, 128) ||
    !validVersion(value.rule_version) || !boundedString(value.event_type, 128) ||
    !boundedString(value.attribute, 128) || !validTags(value.tags) ||
    !Array.isArray(value.outcomes) || value.outcomes.length < 1 || value.outcomes.length > 32
  ) return null;
  for (const rawOutcome of value.outcomes) {
    const outcome = record(rawOutcome);
    if (
      !outcome || !hasOnlyKeys(outcome, new Set(["value", "title", "severity"])) ||
      !boundedString(outcome.value, 128) || !boundedString(outcome.title, 256) ||
      !validSeverity(outcome.severity)
    ) return null;
  }
  return value as unknown as CompiledBuiltin;
}

function nullablePositiveNumber(value: unknown): boolean {
  return value === null || (
    typeof value === "number" && Number.isFinite(value) && value > 0
  );
}

function parseCorrelationSnapshot(value: Record<string, unknown>): CompiledCorrelation | null {
  const allowed = new Set([
    "rule_id", "rule_version", "title", "severity", "tags", "event_type",
    "window_minutes", "event_threshold", "distinct_threshold", "byte_threshold",
    "maximum_speed_kph",
  ]);
  if (
    !hasOnlyKeys(value, allowed) || !boundedString(value.rule_id, 128) ||
    !validVersion(value.rule_version) || !boundedString(value.title, 256) ||
    !validSeverity(value.severity) || !validTags(value.tags) ||
    !boundedString(value.event_type, 128) ||
    !nullablePositiveNumber(value.window_minutes) ||
    !nullablePositiveNumber(value.event_threshold) ||
    !nullablePositiveNumber(value.distinct_threshold) ||
    !nullablePositiveNumber(value.byte_threshold) ||
    !nullablePositiveNumber(value.maximum_speed_kph)
  ) return null;
  return value as unknown as CompiledCorrelation;
}

export async function parseDetectionSnapshot(
  rawSnapshot: unknown,
  expectedDigest: string,
): Promise<DetectionSnapshot> {
  const snapshot = record(rawSnapshot);
  if (!snapshot || !/^sha256:[0-9a-f]{64}$/u.test(expectedDigest)) {
    throw new Error("stored rule snapshot provenance is invalid");
  }
  const actualDigest = `sha256:${await sha256Hex(canonicalJson(snapshot))}`;
  if (actualDigest !== expectedDigest) throw new Error("stored rule snapshot digest does not match");
  const sigma = parseSigmaSnapshot(snapshot);
  if (sigma) return { kind: "sigma", rule: { ...sigma, rule_digest: expectedDigest } };
  const builtin = parseBuiltinSnapshot(snapshot);
  if (builtin) return { kind: "builtin", rule: { ...builtin, rule_digest: expectedDigest } };
  const correlation = parseCorrelationSnapshot(snapshot);
  if (correlation) {
    return { kind: "correlation", rule: { ...correlation, rule_digest: expectedDigest } };
  }
  throw new Error("stored rule snapshot shape is unsupported");
}

export function compiledDetectionProvenance(ruleId: string): CompiledDetectionProvenance {
  const candidate = (
    artifact.rules.find((item) => item.id === ruleId) ??
    artifact.builtins.find((item) => item.rule_id === ruleId) ??
    artifact.correlations.find((item) => item.rule_id === ruleId)
  ) as Record<string, unknown> | undefined;
  if (!candidate) throw new Error(`missing compiled provenance for ${ruleId}`);
  const { rule_digest: ruleDigest, ...snapshot } = candidate;
  const ruleVersion = candidate.rule_version;
  if (typeof ruleVersion !== "number" || typeof ruleDigest !== "string") {
    throw new Error(`invalid compiled provenance for ${ruleId}`);
  }
  return { ruleVersion, ruleDigest, ruleSnapshot: snapshot };
}

export async function alertFingerprintV1(
  tenantId: string,
  ruleId: string,
  eventId: string,
): Promise<string> {
  return (await sha256Hex(JSON.stringify(["controlforge-alert", 1, tenantId, ruleId, eventId]))).slice(0, 32);
}

function fieldValue(event: CanonicalEvent, field: string): unknown {
  const direct: Record<string, unknown> = {
    event_id: event.event_id,
    event_type: event.event_type,
    timestamp: event.timestamp,
    actor: event.actor,
    source_ip: event.source_ip ?? "",
    target: event.target ?? "",
    device_id: event.device_id ?? "",
  };
  return field in direct ? direct[field] : (event.attributes[field] ?? "");
}

function globMatches(value: string, pattern: string): boolean {
  let regex = "^";
  for (const character of pattern) {
    if (character === "*") regex += ".*";
    else if (character === "?") regex += ".";
    else regex += character.replace(/[\\^$.*+?()[\]{}|]/gu, "\\$&");
  }
  return new RegExp(`${regex}$`, "iu").test(value);
}

function parseIpv4(value: string): bigint | null {
  const parts = value.split(".");
  if (parts.length !== 4) return null;
  let result = 0n;
  for (const part of parts) {
    if (!/^\d{1,3}$/u.test(part)) return null;
    const octet = Number(part);
    if (octet > 255) return null;
    result = (result << 8n) | BigInt(octet);
  }
  return result;
}

function parseIpv6(value: string): bigint | null {
  if (!/^[0-9a-f:]+$/iu.test(value) || value.split("::").length > 2) return null;
  const sides = value.split("::");
  const left = sides[0] ? sides[0].split(":") : [];
  const right = sides.length === 2 && sides[1] ? sides[1].split(":") : [];
  if (sides.length === 1 && left.length !== 8) return null;
  const missing = 8 - left.length - right.length;
  if (missing < (sides.length === 2 ? 1 : 0)) return null;
  const groups = [...left, ...Array<string>(missing).fill("0"), ...right];
  if (groups.length !== 8) return null;
  let result = 0n;
  for (const group of groups) {
    if (!/^[0-9a-f]{1,4}$/iu.test(group)) return null;
    result = (result << 16n) | BigInt(`0x${group}`);
  }
  return result;
}

function cidrMatches(address: string, network: string): boolean {
  const [networkAddress, prefixText, ...rest] = network.split("/");
  if (!networkAddress || !prefixText || rest.length > 0 || !/^\d+$/u.test(prefixText)) return false;
  const ipv4Address = parseIpv4(address);
  const ipv4Network = parseIpv4(networkAddress);
  const bits = ipv4Address !== null && ipv4Network !== null ? 32 : 128;
  const parsedAddress = bits === 32 ? ipv4Address : parseIpv6(address);
  const parsedNetwork = bits === 32 ? ipv4Network : parseIpv6(networkAddress);
  const prefix = Number(prefixText);
  if (parsedAddress === null || parsedNetwork === null || prefix < 0 || prefix > bits) return false;
  const hostBits = BigInt(bits - prefix);
  const mask = prefix === 0 ? 0n : ((1n << BigInt(bits)) - 1n) ^ ((1n << hostBits) - 1n);
  return (parsedAddress & mask) === (parsedNetwork & mask);
}

function scalarMatches(actual: unknown, expected: unknown, operator: string): boolean {
  const actualText = String(actual).toLocaleLowerCase("en-US");
  const expectedText = String(expected).toLocaleLowerCase("en-US");
  if (operator === "equals") return actual === expected || globMatches(actualText, expectedText);
  if (operator === "contains") return actualText.includes(expectedText);
  if (operator === "startswith") return actualText.startsWith(expectedText);
  if (operator === "endswith") return actualText.endsWith(expectedText);
  if (operator === "re") return new RegExp(String(expected), "iu").test(String(actual));
  if (operator === "cidr") return cidrMatches(String(actual), String(expected));
  throw new Error(`unsupported Sigma operator: ${operator}`);
}

function valueMatches(actual: unknown, expected: unknown, operator: string): boolean {
  const actualValues = Array.isArray(actual) ? actual : [actual];
  const expectedValues = Array.isArray(expected) ? expected : [expected];
  return actualValues.some((actualValue) => (
    expectedValues.some((expectedValue) => scalarMatches(actualValue, expectedValue, operator))
  ));
}

function parseExpression(expression: string): [string, string] {
  const separator = expression.indexOf("|");
  if (separator === -1) return [expression, "equals"];
  const field = expression.slice(0, separator);
  const operator = expression.slice(separator + 1);
  if (!operators.has(operator)) throw new Error(`unsupported Sigma modifier: ${operator}`);
  return [field, operator];
}

interface MatchResult {
  matched: boolean;
  reasons: string[];
}

function safeExpected(expected: unknown): string {
  const rendered = JSON.stringify(expected);
  return rendered.length <= 80 ? rendered : `${rendered.slice(0, 77)}...`;
}

function selectionMatches(selection: unknown, event: CanonicalEvent): MatchResult {
  const branches = Array.isArray(selection) ? selection : [selection];
  for (const branch of branches) {
    if (typeof branch !== "object" || branch === null || Array.isArray(branch)) {
      throw new Error("Sigma selection must be a mapping or list of mappings");
    }
    const reasons: string[] = [];
    let matched = true;
    for (const [expression, expected] of Object.entries(branch as Selection)) {
      const [field, operator] = parseExpression(expression);
      if (!valueMatches(fieldValue(event, field), expected, operator)) {
        matched = false;
        break;
      }
      reasons.push(`${expression} matched ${safeExpected(expected)}`);
    }
    if (matched) return { matched: true, reasons };
  }
  return { matched: false, reasons: [] };
}

function tokenize(condition: string): string[] {
  const token = /\s*(1\s+of\s+[a-zA-Z0-9_*?-]+|all\s+of\s+[a-zA-Z0-9_*?-]+|and\b|or\b|not\b|\(|\)|[a-zA-Z0-9_*?-]+)/iy;
  const tokens: string[] = [];
  let position = 0;
  while (position < condition.length) {
    token.lastIndex = position;
    const match = token.exec(condition);
    if (!match || match.index !== position || !match[1]) {
      if (condition.slice(position).trim() === "") break;
      throw new Error(`unsupported Sigma condition near: ${condition.slice(position)}`);
    }
    const normalized = match[1].trim().replace(/\s+/gu, " ");
    const lowered = normalized.toLocaleLowerCase("en-US");
    tokens.push(["and", "or", "not"].includes(lowered) ? lowered : normalized);
    position = token.lastIndex;
  }
  if (tokens.length === 0) throw new Error("Sigma condition cannot be empty");
  return tokens;
}

function conditionMatches(
  condition: string,
  selections: Record<string, unknown>,
  event: CanonicalEvent,
): MatchResult {
  const tokens = tokenize(condition);
  let position = 0;
  const current = (): string | undefined => tokens[position];

  const named = (name: string): MatchResult => {
    if (!(name in selections)) throw new Error(`unknown selection in condition: ${name}`);
    return selectionMatches(selections[name], event);
  };
  const candidates = (pattern: string): string[] => (
    Object.keys(selections).filter((name) => globMatches(name, pattern))
  );

  const primary = (): MatchResult => {
    const symbol = current();
    if (!symbol) throw new Error("unexpected end of Sigma condition");
    if (symbol === "(") {
      position += 1;
      const result = parseOr();
      if (current() !== ")") throw new Error("unclosed parenthesis in Sigma condition");
      position += 1;
      return result;
    }
    if (symbol === ")") throw new Error("unexpected closing parenthesis in Sigma condition");
    position += 1;
    const oneOf = /^1 of ([a-zA-Z0-9_*?-]+)$/iu.exec(symbol);
    if (oneOf?.[1]) {
      for (const name of candidates(oneOf[1])) {
        const result = named(name);
        if (result.matched) return result;
      }
      return { matched: false, reasons: [] };
    }
    const allOf = /^all of ([a-zA-Z0-9_*?-]+)$/iu.exec(symbol);
    if (allOf?.[1]) {
      const matches = candidates(allOf[1]);
      const reasons: string[] = [];
      for (const name of matches) {
        const result = named(name);
        if (!result.matched) return { matched: false, reasons: [] };
        reasons.push(...result.reasons);
      }
      return { matched: matches.length > 0, reasons };
    }
    return named(symbol);
  };

  const parseNot = (): MatchResult => {
    if (current() === "not") {
      position += 1;
      return { matched: !parseNot().matched, reasons: [] };
    }
    return primary();
  };
  const parseAnd = (): MatchResult => {
    let result = parseNot();
    while (current() === "and") {
      position += 1;
      const right = parseNot();
      result = result.matched && right.matched
        ? { matched: true, reasons: [...result.reasons, ...right.reasons] }
        : { matched: false, reasons: [] };
    }
    return result;
  };
  function parseOr(): MatchResult {
    let result = parseAnd();
    while (current() === "or") {
      position += 1;
      const right = parseAnd();
      if (!result.matched && right.matched) result = right;
    }
    return result;
  }

  const result = parseOr();
  if (position !== tokens.length) {
    throw new Error(`unexpected token in Sigma condition: ${String(tokens[position])}`);
  }
  return result;
}

function ruleMatches(rule: CompiledRule, event: CanonicalEvent): MatchResult {
  const condition = rule.detection.condition;
  if (typeof condition !== "string") throw new Error(`${rule.id}: detection.condition must be a string`);
  const selections = Object.fromEntries(
    Object.entries(rule.detection).filter(([name]) => !["condition", "timeframe"].includes(name)),
  );
  return conditionMatches(condition, selections, event);
}

export function evaluateCanonicalRule(
  rule: CompiledRule,
  event: CanonicalEvent,
): CanonicalDetectionDecision | null {
  const result = ruleMatches(rule, event);
  if (!result.matched) return null;
  return {
    contract_version: artifact.contract_version,
    matched: true,
    rule_id: rule.id,
    rule_version: rule.rule_version,
    rule_digest: rule.rule_digest,
    title: rule.title,
    severity: rule.level,
    event_id: event.event_id,
    actor: event.actor,
    reasons: result.reasons,
    tags: rule.tags,
    created_at: event.timestamp,
  };
}

export function evaluateCanonicalBuiltin(
  rule: CompiledBuiltin,
  event: CanonicalEvent,
): CanonicalDetectionDecision | null {
  if (event.event_type !== rule.event_type) return null;
  const rawValue = event.attributes[rule.attribute];
  const value = typeof rawValue === "string" ? rawValue.toLocaleLowerCase("en-US") : "";
  const outcome = rule.outcomes.find((item) => item.value === value);
  if (!outcome) return null;
  const evidenceValue = (raw: unknown): string => {
    if (typeof raw === "boolean") return raw ? "true" : "false";
    return "unknown";
  };
  return {
    contract_version: artifact.contract_version,
    matched: true,
    rule_id: rule.rule_id,
    rule_version: rule.rule_version,
    rule_digest: rule.rule_digest,
    title: outcome.title,
    severity: outcome.severity,
    event_id: event.event_id,
    actor: event.actor,
    reasons: [
      `endpoint control ${event.target ?? "unknown"} reported ${value}`,
      `installed=${evidenceValue(event.attributes.installed)} running=${evidenceValue(event.attributes.running)}`,
    ],
    tags: rule.tags,
    created_at: event.timestamp,
  };
}

export function detectCanonicalStatelessEvent(event: CanonicalEvent): CanonicalDetectionDecision[] {
  const builtins = artifact.builtins.flatMap((rule) => {
    const decision = evaluateCanonicalBuiltin(rule, event);
    return decision ? [{ ...decision, rule_digest: rule.rule_digest }] : [];
  });
  const sigma = artifact.rules.flatMap((rule) => {
    const decision = evaluateCanonicalRule(rule, event);
    return decision ? [decision] : [];
  });
  return [...builtins, ...sigma];
}
