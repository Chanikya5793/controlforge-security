import { describe, expect, it } from "vitest";

import { dashboardHtml } from "../src/dashboard";

describe("ControlForge Admin dashboard contract", () => {
  it("ships syntactically valid module script", () => {
    const script = dashboardHtml.match(/<script type="module"[^>]*>([\s\S]*)<\/script>/u)?.[1];

    expect(script).toBeTruthy();
    // eslint-disable-next-line @typescript-eslint/no-implied-eval -- parse-only CSP script test
    expect(() => new Function(`return (async () => {${script ?? ""}\n})`)).not.toThrow();
  });

  it("derives organizations from the authenticated principal", () => {
    expect(dashboardHtml).toContain("request('/v1/me')");
    expect(dashboardHtml).toContain("<select id=\"tenant\"");
    expect(dashboardHtml).not.toContain("placeholder=\"tenant UUID\"");
    expect(dashboardHtml).not.toContain("localStorage");
  });

  it("keeps the product human-governed and exposes device operations", () => {
    expect(dashboardHtml).toContain("Evidence-first SOC");
    expect(dashboardHtml).toContain("Security operations command center");
    expect(dashboardHtml).toContain("Endpoint health");
    expect(dashboardHtml).toContain("/v1/devices?limit=200");
    expect(dashboardHtml).not.toContain("Autonomous SOC");
  });

  it("renders a real recurring-case command center without decorative data", () => {
    expect(dashboardHtml).toContain("Prioritized case queue");
    expect(dashboardHtml).toContain("/v1/case-queue?limit=250");
    expect(dashboardHtml).toContain("historical cases grouped");
    expect(dashboardHtml).toContain("processing_errors");
    expect(dashboardHtml).toContain("pending_events");
    expect(dashboardHtml).toContain("stale_devices");
    expect(dashboardHtml).not.toContain("<canvas");
    expect(dashboardHtml).not.toContain("Math.random");
    expect(dashboardHtml).toContain("/v1/alerts?limit=25");
    expect(dashboardHtml).not.toContain("/v1/alerts?limit=100");
  });

  it("exposes evidence, both replay modes, advisory triage, approvals, and audit honestly", () => {
    expect(dashboardHtml).toContain("Evidence timeline");
    expect(dashboardHtml).toContain("Immutable rule snapshot stored");
    expect(dashboardHtml).toContain("Legacy Cloud alert · rule version and digest unknown");
    expect(dashboardHtml).toContain("Replay current detector");
    expect(dashboardHtml).toContain("Replay original rule");
    expect(dashboardHtml).toContain("currently retained event-time history");
    expect(dashboardHtml).toContain("Request advisory triage");
    expect(dashboardHtml).toContain("Approvals and outcomes");
    expect(dashboardHtml).toContain("Audit lineage");
    expect(dashboardHtml).toContain("Second-human decisions required");
  });

  it("exposes the real case workflow without weakening two-human response", () => {
    expect(dashboardHtml).toContain("Case ownership");
    expect(dashboardHtml).toContain("/v1/case-assignees");
    expect(dashboardHtml).toContain("/assignment");
    expect(dashboardHtml).toContain("Add analyst note");
    expect(dashboardHtml).toContain("Record disposition");
    expect(dashboardHtml).toContain("False-positive reason, when applicable");
    expect(dashboardHtml).toContain('<option value="benign">Benign</option>');
    expect(dashboardHtml).toContain("data-case-transition");
    expect(dashboardHtml).toContain("/transitions");
    expect(dashboardHtml).toContain("/notes");
    expect(dashboardHtml).toContain("/dispositions");
    expect(dashboardHtml).toContain("Propose bounded response");
    expect(dashboardHtml).toContain("/actions");
    expect(dashboardHtml).toContain("Active actions still require approval by a different responder");
    expect(dashboardHtml).toContain("Legacy cases without a semantic key cannot be reopened");
  });

  it("supports analyst filters and readable time semantics", () => {
    for (const control of [
      "case-search",
      "severity-filter",
      "status-filter",
      "source-filter",
      "time-filter",
    ]) expect(dashboardHtml).toContain(`id="${control}"`);
    expect(dashboardHtml).toContain("Intl.RelativeTimeFormat");
    expect(dashboardHtml).toContain("title=\"");
    expect(dashboardHtml).toContain("absoluteTime(value)");
  });

  it("includes the minimum keyboard and announcement accessibility contract", () => {
    expect(dashboardHtml).toContain("Skip to main content");
    expect(dashboardHtml).toContain("role=\"status\" aria-live=\"polite\"");
    expect(dashboardHtml).toContain("role=\"alert\"");
    expect(dashboardHtml).toContain(":focus-visible");
    expect(dashboardHtml).toContain("min-height:44px");
    expect(dashboardHtml).toContain("<form class=\"filters\"");
    expect(dashboardHtml).toContain("<caption>");
    expect(dashboardHtml).toContain("aria-labelledby=\"detail-title\"");
    expect(dashboardHtml).toContain("@media(max-width:780px)");
  });

  it("contains narrow viewports while keeping dense tables independently scrollable", () => {
    expect(dashboardHtml).toContain(
      ".shell,.rail,.workspace,main,section,.split,.split>section,.card,.table-card { min-width:0; max-width:100%; }",
    );
    expect(dashboardHtml).toContain(
      ".table-wrap { display:block; width:100%; max-width:100%; min-width:0; overflow-x:auto;",
    );
    expect(dashboardHtml).toContain("table { width:100%; min-width:850px;");
    expect(dashboardHtml).toContain(
      "@media(max-width:780px) { .shell { grid-template-columns:minmax(0,1fr); }",
    );
    expect(dashboardHtml).toContain(
      "nav { display:flex; width:100%; overflow-x:auto; overscroll-behavior-inline:contain; }",
    );
    expect(dashboardHtml).toContain(".secondary-text { display:block; margin-top:4px; overflow-wrap:anywhere;");
    expect(dashboardHtml).not.toMatch(/body\s*\{[^}]*overflow-x\s*:\s*hidden/u);
  });
});
