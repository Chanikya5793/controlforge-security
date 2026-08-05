export type Severity = "informational" | "low" | "medium" | "high" | "critical";

export interface Env {
  DB: D1Database;
  EVENT_QUEUE: Queue<QueuedEvent>;
  ENVIRONMENT: string;
  ADMIN_TOKEN: string;
  CREDENTIAL_KEK: string;
  AUDIT_HMAC_SECRET: string;
  ACCESS_TEAM_DOMAIN: string;
  ACCESS_AUD: string;
  TRIAGE_PROVIDER: string;
  META_MODEL_API_KEY?: string;
  META_MODEL: string;
  GEMINI_API_KEY?: string;
  GEMINI_MODEL: string;
}

export interface QueuedEvent {
  tenantId: string;
  eventId: string;
  attemptId: string;
}

export interface AuthenticatedPrincipal {
  id: string;
  type: "access_user" | "admin_token" | "collector";
  email?: string;
  tenantId?: string;
  credentialId?: string;
}

export interface StoredEvent {
  tenant_id: string;
  event_id: string;
  event_type: string;
  occurred_at: string;
  received_at: string;
  actor: string;
  source_ip: string | null;
  target: string | null;
  device_id: string | null;
  attributes_json: string;
  payload_sha256: string;
  processed_at: string | null;
  processing_error: string | null;
}

export interface DetectionAlert {
  alertId: string;
  ruleId: string;
  title: string;
  severity: Severity;
  eventId: string;
  actor: string;
  reasons: string[];
  tags: string[];
  createdAt: string;
}

export interface CollectorCredential {
  credential_id: string;
  tenant_id: string;
  secret_ciphertext: string;
  secret_iv: string;
  expires_at: string;
  revoked_at: string | null;
  tenant_status: string;
}

export interface AlertRow {
  tenant_id: string;
  alert_id: string;
  event_id: string;
  rule_id: string;
  title: string;
  severity: Severity;
  actor: string;
  reasons_json: string;
  tags_json: string;
  created_at: string;
}

export interface CaseRow {
  tenant_id: string;
  case_id: string;
  title: string;
  priority: "low" | "medium" | "high" | "critical";
  status: "open" | "investigating" | "contained" | "closed";
  opened_at: string;
  updated_at: string;
  closed_at: string | null;
}
