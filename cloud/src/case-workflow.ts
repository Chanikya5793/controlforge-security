import { appendAudit } from "./repository";
import type { AuthenticatedPrincipal, Env } from "./types";

export type CaseStatus = "open" | "investigating" | "contained" | "closed";

export class CaseWorkflowError extends Error {
  constructor(
    public readonly code:
      | "case_not_found"
      | "invalid_transition"
      | "disposition_required"
      | "reopen_conflict"
      | "assignee_not_found"
      | "assignment_conflict",
  ) {
    super(code);
  }
}

async function requireCase(
  env: Env,
  tenantId: string,
  caseId: string,
): Promise<{
  disposition_required_after: string | null;
  semantic_key: string | null;
  status: CaseStatus;
}> {
  const selected = await env.DB.prepare(
    `SELECT disposition_required_after, semantic_key, status
       FROM cases WHERE tenant_id = ? AND case_id = ?`,
  ).bind(tenantId, caseId).first<{
    disposition_required_after: string | null;
    semantic_key: string | null;
    status: CaseStatus;
  }>();
  if (!selected) throw new CaseWorkflowError("case_not_found");
  return selected;
}

export async function appendCaseNote(
  env: Env,
  tenantId: string,
  caseId: string,
  body: string,
  principal: AuthenticatedPrincipal,
): Promise<Record<string, string>> {
  await requireCase(env, tenantId, caseId);
  const noteId = crypto.randomUUID();
  const createdAt = new Date().toISOString();
  await env.DB.prepare(
    `INSERT INTO case_notes(tenant_id, note_id, case_id, body, created_by, created_at)
     VALUES (?, ?, ?, ?, ?, ?)`,
  ).bind(tenantId, noteId, caseId, body, principal.id, createdAt).run();
  await appendAudit(env, tenantId, "case.note_added", principal, "case", caseId, {
    note_id: noteId,
    body_length: body.length,
  });
  return {
    note_id: noteId,
    case_id: caseId,
    body,
    created_by: principal.id,
    created_at: createdAt,
  };
}

export async function appendCaseDisposition(
  env: Env,
  tenantId: string,
  caseId: string,
  disposition: string,
  rationale: string,
  falsePositiveReason: string | null,
  principal: AuthenticatedPrincipal,
): Promise<Record<string, string | null>> {
  await requireCase(env, tenantId, caseId);
  const dispositionId = crypto.randomUUID();
  const createdAt = new Date().toISOString();
  const storedDisposition = disposition === "benign" ? "benign_positive" : disposition;
  await env.DB.prepare(
    `INSERT INTO case_dispositions(
       tenant_id, disposition_id, case_id, disposition, rationale,
       created_by, created_at, false_positive_reason
     ) VALUES (?, ?, ?, ?, ?, ?, ?, ?)`,
  ).bind(
    tenantId,
    dispositionId,
    caseId,
    storedDisposition,
    rationale,
    principal.id,
    createdAt,
    falsePositiveReason,
  ).run();
  await appendAudit(env, tenantId, "case.disposition_added", principal, "case", caseId, {
    disposition_id: dispositionId,
    disposition,
    rationale_length: rationale.length,
    false_positive_reason_recorded: falsePositiveReason !== null,
  });
  return {
    disposition_id: dispositionId,
    case_id: caseId,
    disposition,
    rationale,
    false_positive_reason: falsePositiveReason,
    created_by: principal.id,
    created_at: createdAt,
  };
}

export async function assignCase(
  env: Env,
  tenantId: string,
  caseId: string,
  assigneePrincipalId: string | null,
  principal: AuthenticatedPrincipal,
): Promise<Record<string, string | null>> {
  await requireCase(env, tenantId, caseId);
  if (assigneePrincipalId !== null) {
    const membership = await env.DB.prepare(
      `SELECT role FROM analyst_memberships
        WHERE tenant_id = ? AND principal_id = ?
          AND role IN ('analyst', 'responder', 'admin')`,
    ).bind(tenantId, assigneePrincipalId).first<{ role: string }>();
    if (!membership) throw new CaseWorkflowError("assignee_not_found");
  }
  const selected = await env.DB.prepare(
    "SELECT assignee_principal_id FROM cases WHERE tenant_id = ? AND case_id = ?",
  ).bind(tenantId, caseId).first<{ assignee_principal_id: string | null }>();
  if (!selected) throw new CaseWorkflowError("case_not_found");
  if (selected.assignee_principal_id === assigneePrincipalId) {
    throw new CaseWorkflowError("assignment_conflict");
  }
  const updatedAt = new Date().toISOString();
  const changed = await env.DB.prepare(
    `UPDATE cases SET assignee_principal_id = ?, updated_at = ?
      WHERE tenant_id = ? AND case_id = ?
        AND (assignee_principal_id IS ? OR assignee_principal_id = ?)`,
  ).bind(
    assigneePrincipalId,
    updatedAt,
    tenantId,
    caseId,
    selected.assignee_principal_id,
    selected.assignee_principal_id,
  ).run();
  if (changed.meta.changes !== 1) throw new CaseWorkflowError("assignment_conflict");
  await appendAudit(env, tenantId, "case.assignment_changed", principal, "case", caseId, {
    from_principal_id: selected.assignee_principal_id,
    to_principal_id: assigneePrincipalId,
  });
  return {
    case_id: caseId,
    assignee_principal_id: assigneePrincipalId,
    updated_at: updatedAt,
  };
}

const ALLOWED_TRANSITIONS: Readonly<Record<CaseStatus, ReadonlySet<CaseStatus>>> = {
  open: new Set(["investigating", "closed"]),
  investigating: new Set(["contained", "closed"]),
  contained: new Set(["investigating", "closed"]),
  closed: new Set(["open"]),
};

export async function transitionCase(
  env: Env,
  tenantId: string,
  caseId: string,
  requested: CaseStatus,
  principal: AuthenticatedPrincipal,
): Promise<Record<string, string | null>> {
  const selected = await requireCase(env, tenantId, caseId);
  if (!ALLOWED_TRANSITIONS[selected.status].has(requested)) {
    throw new CaseWorkflowError("invalid_transition");
  }
  if (requested === "closed") {
    const disposition = await env.DB.prepare(
      `SELECT disposition_id FROM case_dispositions
        WHERE tenant_id = ? AND case_id = ?
          AND (? IS NULL OR created_at >= ?)
        ORDER BY created_at DESC LIMIT 1`,
    ).bind(
      tenantId,
      caseId,
      selected.disposition_required_after,
      selected.disposition_required_after,
    ).first<{ disposition_id: string }>();
    if (!disposition) throw new CaseWorkflowError("disposition_required");
  }
  if (selected.status === "closed") {
    if (!selected.semantic_key) throw new CaseWorkflowError("reopen_conflict");
    const conflicting = await env.DB.prepare(
      `SELECT case_id FROM cases
        WHERE tenant_id = ? AND semantic_key = ? AND status != 'closed' AND case_id != ?
        LIMIT 1`,
    ).bind(tenantId, selected.semantic_key, caseId).first<{ case_id: string }>();
    if (conflicting) throw new CaseWorkflowError("reopen_conflict");
  }
  const updatedAt = new Date().toISOString();
  let changed: D1Result;
  try {
    changed = await env.DB.prepare(
      `UPDATE cases
          SET status = ?, updated_at = ?, closed_at = ?,
              disposition_required_after = ?
        WHERE tenant_id = ? AND case_id = ? AND status = ?`,
    ).bind(
      requested,
      updatedAt,
      requested === "closed" ? updatedAt : null,
      selected.status === "closed" ? updatedAt : selected.disposition_required_after,
      tenantId,
      caseId,
      selected.status,
    ).run();
  } catch (error) {
    const summary = error instanceof Error ? error.message : "";
    if (
      selected.status === "closed"
      && summary.includes("UNIQUE constraint failed")
      && summary.includes("cases.semantic_key")
    ) {
      throw new CaseWorkflowError("reopen_conflict");
    }
    throw error;
  }
  if (changed.meta.changes !== 1) throw new CaseWorkflowError("invalid_transition");
  await appendAudit(env, tenantId, "case.status_changed", principal, "case", caseId, {
    from_status: selected.status,
    to_status: requested,
  });
  return {
    case_id: caseId,
    status: requested,
    updated_at: updatedAt,
    closed_at: requested === "closed" ? updatedAt : null,
  };
}
