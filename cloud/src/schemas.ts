import { z } from "zod";

const identifier = z.string().min(1).max(128).regex(/^[A-Za-z0-9._:-]+$/);
const safeText = z.string().min(1).max(512);

export const securityEventSchema = z.object({
  event_id: identifier,
  event_type: identifier,
  timestamp: z.iso.datetime({ offset: true }),
  actor: z.string().min(1).max(320),
  source_ip: z.string().min(2).max(45).optional(),
  target: safeText.optional(),
  device_id: identifier.optional(),
  attributes: z.record(z.string().max(128), z.unknown()).default({}),
}).strict();

export const eventBatchSchema = z.object({
  events: z.array(securityEventSchema).min(1).max(1_000),
}).strict();

export type SecurityEventInput = z.infer<typeof securityEventSchema>;

export const createTenantSchema = z.object({
  slug: z.string().min(3).max(48).regex(/^[a-z0-9]+(?:-[a-z0-9]+)*$/),
  display_name: z.string().min(1).max(120),
  device_id: identifier,
  device_name: z.string().min(1).max(120),
  credential_name: z.string().min(1).max(120).default("primary-collector"),
  credential_ttl_days: z.number().int().min(1).max(365).default(90),
}).strict();

export const actionProposalSchema = z.object({
  action_type: z.enum([
    "collect_diagnostics",
    "enrich_indicator",
    "isolate_endpoint",
    "release_endpoint",
    "disable_identity",
    "revoke_sessions",
  ]),
  target_type: z.enum(["device", "identity", "indicator"]),
  target_id: z.string().min(1).max(320),
  rationale: z.string().min(10).max(2_000),
  expires_in_minutes: z.number().int().min(5).max(1_440).default(60),
}).strict().superRefine((value, context) => {
  const requiredTarget = value.action_type === "enrich_indicator"
    ? "indicator"
    : value.action_type === "disable_identity" || value.action_type === "revoke_sessions"
      ? "identity"
      : "device";
  if (value.target_type !== requiredTarget) {
    context.addIssue({
      code: "custom",
      path: ["target_type"],
      message: `${value.action_type} requires target_type ${requiredTarget}`,
    });
  }
});

export const caseNoteSchema = z.object({
  body: z.string().trim().min(1).max(4_000),
}).strict();

export const caseDispositionSchema = z.object({
  disposition: z.enum(["true_positive", "false_positive", "benign", "inconclusive"]),
  rationale: z.string().trim().min(10).max(2_000),
  false_positive_reason: z.string().trim().min(1).max(1_000).nullable().optional(),
}).strict().superRefine((value, context) => {
  const hasReason = value.false_positive_reason !== undefined
    && value.false_positive_reason !== null;
  if (value.disposition === "false_positive" && !hasReason) {
    context.addIssue({
      code: "custom",
      path: ["false_positive_reason"],
      message: "false_positive requires false_positive_reason",
    });
  }
  if (value.disposition !== "false_positive" && hasReason) {
    context.addIssue({
      code: "custom",
      path: ["false_positive_reason"],
      message: "false_positive_reason is only valid for false_positive",
    });
  }
});

export const caseAssignmentSchema = z.object({
  assignee_principal_id: identifier.nullable(),
}).strict();

export const caseTransitionSchema = z.object({
  status: z.enum(["open", "investigating", "contained", "closed"]),
}).strict();

export const actionDecisionSchema = z.object({
  decision: z.enum(["approve", "reject"]),
  rationale: z.string().min(3).max(1_000),
}).strict();

export const actionResultSchema = z.object({
  status: z.enum(["succeeded", "failed"]),
  summary: z.string().min(1).max(2_000),
  evidence: z.array(z.string().min(1).max(1_000)).max(20).default([]),
}).strict();

export const triageAssessmentSchema = z.object({
  summary: z.string().min(1).max(500),
  confidence: z.number().min(0).max(1),
  evidence_refs: z.array(z.number().int().positive()).min(1).max(20),
  hypotheses: z.array(z.string().min(1).max(300)).max(5),
  next_steps: z.array(z.string().min(1).max(300)).max(5),
  requires_human_review: z.literal(true),
}).strict();

export type TriageAssessment = z.infer<typeof triageAssessmentSchema>;
