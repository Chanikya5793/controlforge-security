export type TenantRole = "viewer" | "analyst" | "responder" | "admin";

export type Capability =
  | "view_security_data"
  | "triage_alert"
  | "manage_case"
  | "propose_read_only_action"
  | "propose_active_action"
  | "approve_active_action"
  | "manage_tenant";

const ROLE_CAPABILITIES: Record<TenantRole, ReadonlySet<Capability>> = {
  viewer: new Set(["view_security_data"]),
  analyst: new Set([
    "view_security_data",
    "triage_alert",
    "manage_case",
    "propose_read_only_action",
  ]),
  responder: new Set([
    "view_security_data",
    "triage_alert",
    "manage_case",
    "propose_read_only_action",
    "propose_active_action",
    "approve_active_action",
  ]),
  admin: new Set([
    "view_security_data",
    "triage_alert",
    "manage_case",
    "propose_read_only_action",
    "propose_active_action",
    "approve_active_action",
    "manage_tenant",
  ]),
};

export function isTenantRole(value: string): value is TenantRole {
  return value === "viewer"
    || value === "analyst"
    || value === "responder"
    || value === "admin";
}

export function roleHasCapability(role: TenantRole, capability: Capability): boolean {
  return ROLE_CAPABILITIES[role].has(capability);
}
