import type { Metadata } from 'next';
import { Arrow, PageIntro, SiteFooter, SiteHeader } from '../components';

export const metadata: Metadata = {
  title: 'ControlForge documentation',
  description: 'Start, administer, connect, verify, and deploy ControlForge with role-specific guidance.',
};

const guides = [
  ['For platform owners', 'Create networks, enter any active network, appoint administrators, and keep authority attributable.', 'Owner guide'],
  ['For network administrators', 'Invite the team, create endpoint accounts, handle reset requests, connect devices, and investigate findings.', 'Admin guide'],
  ['For people using a Mac', 'Sign in, change the initial password, connect this Mac, and understand its latest local report.', 'Mac setup'],
  ['For deployment teams', 'Validate the package, deploy Santa and ControlForge through MDM, preserve identity, and test lifecycle operations.', 'Deployment guide'],
];

export default function DocsPage() {
  return (
    <main>
      <SiteHeader />
      <PageIntro
        eyebrow="Documentation"
        title="Start with the job you need to do."
        lede="ControlForge documentation is organized by responsibility, not by internal module names. Preview documentation is honest about which steps have physical or production evidence."
      />
      <section className="guide-grid">
        {guides.map(([title, body, label], index) => (
          <article key={title}>
            <span className="guide-number">0{index + 1}</span>
            <h2>{title}</h2><p>{body}</p>
            <span className="guide-status">Preview documentation</span>
            <span className="guide-link">{label} <Arrow /></span>
          </article>
        ))}
      </section>
      <section className="docs-start">
        <div><p className="kicker light">A complete first connection</p><h2>From a new account to a verified first report.</h2></div>
        <ol>
          <li><span>1</span><div><strong>Administrator creates the endpoint account</strong><p>The one-time initial password is shown once and delivered directly. No email server is required.</p></div></li>
          <li><span>2</span><div><strong>The Mac user changes the initial password</strong><p>Enrollment remains unavailable until the required first-password step is complete.</p></div></li>
          <li><span>3</span><div><strong>macOS authorizes the installed helper</strong><p>The short-lived grant is bound to that account, network, password revision, and exact device.</p></div></li>
          <li><span>4</span><div><strong>The owner or administrator verifies the first report</strong><p>Connected does not mean healthy. The dashboard keeps reporting, component health, and findings distinct.</p></div></li>
        </ol>
      </section>
      <section className="github-callout">
        <div><p className="kicker">Engineering reference</p><h2>Need the source-level documentation?</h2><p>The repository contains the architecture, threat model, accepted detection subset, deployment runbooks, and current evidence boundaries.</p></div>
        <a className="button button-quiet" href="https://github.com/Chanikya5793/controlforge-security">Open GitHub <Arrow /></a>
      </section>
      <SiteFooter />
    </main>
  );
}
