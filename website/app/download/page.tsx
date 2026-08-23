import type { Metadata } from 'next';
import Link from 'next/link';
import { Arrow, PageIntro, SiteFooter, SiteHeader } from '../components';

export const metadata: Metadata = {
  title: 'Download ControlForge for Mac',
  description: 'Download the signed ControlForge preview for Apple Silicon Mac and verify its release evidence.',
};

const releaseFacts = [
  ['Release', '0.4.0 preview'],
  ['Hardware', 'Apple Silicon'],
  ['System', 'macOS 13 or newer'],
  ['Installer', 'Signed and notarized PKG'],
];

export default function DownloadPage() {
  return (
    <main>
      <SiteHeader />
      <PageIntro
        eyebrow="Controlled preview"
        title="Download with the evidence attached."
        lede="ControlForge is preparing its first clean public preview. Every published installer will include an Apple signature, notarization, immutable checksum, source identity, and human-readable release notes."
      />
      <section className="download-panel" data-reveal>
        <div className="release-summary">
          <p className="release-state"><span /> Preview candidate</p>
          <h2>ControlForge for Mac</h2>
          <p className="release-version">Version 0.4.0 · Apple Silicon</p>
          <div className="release-facts">
            {releaseFacts.map(([label, value]) => <div key={label}><span>{label}</span><strong>{value}</strong></div>)}
          </div>
          <button className="button button-disabled" type="button" disabled>
            Clean preview being finalized
          </button>
          <p className="availability-note">The current signed staging candidate is deliberately not offered publicly because its manifest records uncommitted source. We will not disguise that boundary.</p>
        </div>
        <aside className="verification-card">
          <p className="kicker">What must pass before this activates</p>
          <ol>
            <li><span>1</span><div><strong>Clean source</strong><p>Release built from one reviewed commit and preview tag.</p></div></li>
            <li><span>2</span><div><strong>Apple verification</strong><p>Developer ID signature, notarization, stapling, and Gatekeeper.</p></div></li>
            <li><span>3</span><div><strong>Fresh installation</strong><p>Install, connect, report, upgrade, and uninstall on a separate clean Mac.</p></div></li>
            <li><span>4</span><div><strong>Published evidence</strong><p>Manifest, SHA-256, release notes, and supported-system statement.</p></div></li>
          </ol>
        </aside>
      </section>
      <section className="install-steps" data-reveal>
        <div className="section-heading compact">
          <p className="kicker">The installation path</p>
          <h2>One package. No shared device credential.</h2>
          <p>An administrator creates an endpoint account. The person at the Mac installs the verified package, signs in, changes the initial password, and explicitly connects that device.</p>
        </div>
        <div className="step-grid">
          <article><span>01</span><h3>Verify</h3><p>Confirm the published checksum and Apple&apos;s installer assessment.</p></article>
          <article><span>02</span><h3>Install</h3><p>Open the PKG and approve the standard macOS installation prompt.</p></article>
          <article><span>03</span><h3>Connect</h3><p>Use the endpoint account—not an administrator account—to connect the Mac.</p></article>
          <article><span>04</span><h3>Confirm</h3><p>Wait for the first signed report, then verify it in the network dashboard.</p></article>
        </div>
        <div className="inline-callout">
          <div><strong>Planning an organization rollout?</strong><p>Start with a pilot smart group and preserve device identity across upgrades.</p></div>
          <Link href="/docs">Read deployment guidance <Arrow /></Link>
        </div>
      </section>
      <SiteFooter />
    </main>
  );
}
