import type { Metadata } from 'next';
import type { CSSProperties } from 'react';
import { PageIntro, SiteShell } from '../components';

export const metadata: Metadata = {
  title: 'Security and trust — ControlForge',
  description: 'How ControlForge separates deterministic detection, human authority, endpoint privacy, and release integrity.',
};

const boundaries = [
  ['Detections', 'Deterministic rules decide whether saved evidence becomes a finding. Model output is never the decision boundary.'],
  ['AI assistance', 'Optional and advisory. It must use referenced evidence, pass schema validation, and remain subject to human review.'],
  ['Endpoint response', 'High-impact action requires explicit authority, independent human approval, bounded execution, and audit evidence.'],
  ['Tenant isolation', 'Owners may enter an explicitly selected network. Ordinary administrators remain scoped to their assigned network.'],
  ['Endpoint privacy', 'The native app shows local status and safe support details—not organization cases, raw events, secrets, or analyst rationale.'],
  ['Release integrity', 'Production mode rejects dirty source, the wrong host, missing exact tags, missing signatures, or incomplete notarization.'],
];

export default function SecurityPage() {
  return (
    <SiteShell>
      <PageIntro
        eyebrow="Security and trust"
        title="Boundaries that are visible, testable, and difficult to bypass."
        lede="ControlForge is designed around a simple principle: the system should be able to show why it reached a conclusion and who authorized a consequential action."
      />
      <section className="trust-grid">
        {boundaries.map(([title, body], index) => (
          <article key={title} data-reveal style={{ '--reveal-delay': `${(index % 3) * 80}ms` } as CSSProperties}><i aria-hidden="true" /><h2>{title}</h2><p>{body}</p></article>
        ))}
      </section>
      <section className="claim-boundary" data-reveal>
        <div>
          <p className="kicker light">Current product boundary</p>
          <h2>A signed pilot is a status, not a production claim.</h2>
        </div>
        <div>
          <p>ControlForge currently has a signed and notarized staging package, tested multi-network authorization, passkey administration, endpoint enrollment, and deterministic investigation workflows.</p>
          <p>It does not yet claim general availability, clean-Mac fleet acceptance, enterprise service levels, or autonomous remediation. Those claims stay closed until their evidence exists.</p>
        </div>
      </section>
      <section className="evidence-table-wrap" data-reveal>
        <div className="section-heading compact"><p className="kicker">Release evidence</p><h2>What a downloadable build must carry</h2></div>
        <div className="evidence-table">
          <div><span>Apple assurance</span><strong>Developer ID signature, trusted timestamp, notarization ticket, Gatekeeper acceptance</strong></div>
          <div><span>Source assurance</span><strong>Version, channel, exact commit, tag, dirty state, supported architecture</strong></div>
          <div><span>Artifact assurance</span><strong>Immutable filename, byte size, SHA-256, matching embedded and external manifests</strong></div>
          <div><span>Acceptance assurance</span><strong>Fresh install, first report, upgrade, rollback, and uninstall results kept separate from build tests</strong></div>
        </div>
      </section>
    </SiteShell>
  );
}
