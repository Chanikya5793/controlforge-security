import Link from 'next/link';
import type { CSSProperties } from 'react';
import { Arrow, ShieldMark, SiteShell } from './components';

const productPrinciples = [
  {
    title: 'Plain language first',
    body: 'See what happened, why it matters, and the next safe step before opening technical evidence.',
  },
  {
    title: 'Evidence stays attached',
    body: 'Every finding keeps its rule, matched facts, device context, case history, and audit lineage.',
  },
  {
    title: 'Humans keep authority',
    body: 'AI may help summarize evidence. It cannot decide detections or independently change an endpoint.',
  },
];

export default function Home() {
  return (
    <SiteShell>
      <section className="hero" id="top">
        <div className="hero-copy">
          <p className="eyebrow"><span /> Signed public pilot for Apple Silicon</p>
          <h1>Mac security your whole team can understand.</h1>
          <p className="hero-lede">
            Know which Macs are reporting, what needs attention, and what to do
            next—without turning every employee into a security analyst.
          </p>
          <div className="hero-actions">
            <a className="button button-primary" href="#product">
              Explore ControlForge <Arrow />
            </a>
            <Link className="button button-quiet" href="/download">
              Download the pilot
            </Link>
          </div>
          <ul className="proof-list" aria-label="Release assurances">
            <li><span>✓</span> Developer ID signed</li>
            <li><span>✓</span> Apple notarized</li>
            <li><span>✓</span> Evidence-first detections</li>
          </ul>
        </div>

        <div className="product-frame" id="product" aria-label="ControlForge dashboard preview">
          <div className="frame-bar">
            <div className="traffic-lights" aria-hidden="true"><i /><i /><i /></div>
            <p><ShieldMark /> ControlForge</p>
            <span className="secure-state"><i /> Connected</span>
          </div>
          <div className="app-shell">
            <aside className="app-nav">
              <p className="nav-label">Network</p>
              <div className="network-switcher"><span>CF</span><b>ControlForge Pilot</b><small>Owner view</small></div>
              <p className="nav-label nav-space">Workspace</p>
              <span className="app-nav-item active"><span>⌂</span> Overview</span>
              <span className="app-nav-item"><span>◇</span> Devices <em>42</em></span>
              <span className="app-nav-item"><span>!</span> Findings <em className="alert-count">3</em></span>
              <span className="app-nav-item"><span>□</span> Cases</span>
              <span className="app-nav-item"><span>◎</span> People</span>
            </aside>
            <div className="app-content">
              <div className="overview-heading">
                <div><p>Sunday, August 30</p><h2>Your network at a glance</h2></div>
                <span className="mock-button">Add a Mac</span>
              </div>
              <div className="posture-card">
                <div className="posture-score"><span>93</span><small>/ 100</small></div>
                <div className="posture-copy"><p className="status-label">Healthy overall</p><h3>Most Macs are reporting normally.</h3><p>Three devices need an administrator&apos;s attention.</p></div>
                <div className="posture-trend"><b>+4</b><span>this week</span></div>
              </div>
              <div className="metric-grid">
                <article><p>Protected Macs</p><strong>42</strong><span className="good">39 reporting now</span></article>
                <article><p>Need attention</p><strong>3</strong><span className="warn">See the next steps</span></article>
                <article><p>Open cases</p><strong>2</strong><span>1 assigned to you</span></article>
              </div>
              <div className="attention-card">
                <div><p className="status-label amber">Needs attention</p><h3>One security component stopped reporting</h3><p>Finance MacBook Pro · Last verified 18 minutes ago</p></div>
                <span className="mock-link">Review evidence <Arrow /></span>
              </div>
            </div>
          </div>
        </div>
      </section>

      <div className="audience-strip" aria-label="Product audiences" data-reveal>
        <p>Built for</p><span>Platform owners</span><i />
        <span>Network administrators</span><i />
        <span>Everyday Mac users</span>
      </div>

      <section className="section experience" id="how-it-works">
        <div className="section-heading" data-reveal>
          <p className="kicker">One product, three clear experiences</p>
          <h2>Right information.<br />Right person. Right time.</h2>
          <p>ControlForge separates platform ownership, network administration, and endpoint setup without losing the evidence connecting them.</p>
        </div>
        <div className="role-grid">
          <article data-reveal style={{ '--reveal-delay': '0ms' } as CSSProperties}>
            <span className="role-index">Platform owner</span>
            <h3>See every network without flattening its boundaries.</h3>
            <p>Create networks, appoint administrators, and move between each network&apos;s devices and cases with one owner identity.</p>
            <div className="mini-network-list">
              <span><i className="network-icon green">CF</i><b>ControlForge Pilot</b><em>42 Macs</em></span>
              <span><i className="network-icon blue">NL</i><b>North Loop Labs</b><em>18 Macs</em></span>
              <span><i className="network-icon amber-bg">ST</i><b>Studio Team</b><em>9 Macs</em></span>
            </div>
          </article>
          <article data-reveal style={{ '--reveal-delay': '90ms' } as CSSProperties}>
            <span className="role-index">Network administrator</span>
            <h3>Run one network with evidence, not guesswork.</h3>
            <p>Connect people and Macs, handle account help, review findings, and preserve a complete audit trail.</p>
            <div className="mini-case">
              <span className="case-severity">High priority</span>
              <b>Security component stopped</b>
              <p>One Mac · 3 evidence items</p>
              <span className="case-action">Review next steps <Arrow /></span>
            </div>
          </article>
          <article data-reveal style={{ '--reveal-delay': '180ms' } as CSSProperties}>
            <span className="role-index">Person using a Mac</span>
            <h3>Understand this Mac without seeing the whole SOC.</h3>
            <p>Sign in, connect the Mac, and get a clear status with the next useful step—never raw organization investigations.</p>
            <div className="mini-mac-status">
              <span className="mac-shield"><ShieldMark /></span>
              <div><small>This Mac at a glance</small><b>Reporting normally</b><p>Last report 2 minutes ago</p></div>
            </div>
          </article>
        </div>
      </section>

      <section className="principles-section">
        <div className="principles-intro" data-reveal>
          <p className="kicker light">Built to be trustworthy</p>
          <h2>Security decisions should survive a second look.</h2>
          <p>ControlForge keeps deterministic detection at the boundary and makes every important claim traceable to saved evidence.</p>
          <Link href="/security">Read the security model <Arrow /></Link>
        </div>
        <div className="principles-list">
          {productPrinciples.map((item, index) => (
            <article key={item.title} data-reveal style={{ '--reveal-delay': `${index * 90}ms` } as CSSProperties}>
              <i aria-hidden="true" /><div><h3>{item.title}</h3><p>{item.body}</p></div>
            </article>
          ))}
        </div>
      </section>

      <section className="download-callout" id="download" data-reveal>
        <div>
          <p className="kicker">ControlForge 0.4 preview</p>
          <h2>Start with one Mac.<br />Prove every step.</h2>
          <p>A clean-source, Apple-signed pilot is available for controlled Apple Silicon testing. See exactly what is verified—and what remains—before installing.</p>
        </div>
        <div className="download-actions">
          <Link className="button button-primary" href="/download">Open the download page <Arrow /></Link>
          <Link href="/docs">Read installation guidance</Link>
        </div>
      </section>
    </SiteShell>
  );
}
