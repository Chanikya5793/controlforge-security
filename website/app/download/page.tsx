import type { Metadata } from 'next';
import Link from 'next/link';
import { Arrow, PageIntro, SiteShell } from '../components';

export const metadata: Metadata = {
  title: 'Download ControlForge for Mac',
  description: 'Download the signed ControlForge preview for Apple Silicon Mac and verify its release evidence.',
};

const releaseFacts = [
  ['Release', '0.4.0 public pilot'],
  ['Hardware', 'Apple Silicon'],
  ['System', 'macOS 13 or newer'],
  ['Download', '14.8 MB signed PKG'],
];

const releaseBase = '/downloads/0.4.0-pilot-fa34b23';
const checksum = 'e96c42c7865ffe68e1010a1926560089a54342e1745137e23c0e5a7b89ad51be';

export default function DownloadPage() {
  return (
    <SiteShell>
      <PageIntro
        eyebrow="Signed public pilot"
        title="Download with the evidence attached."
        lede="This clean-source Apple Silicon pilot includes its Developer ID signature, notarization, immutable checksum, source identity, and human-readable release notes."
      />
      <section className="download-panel" data-reveal>
        <div className="release-summary">
          <p className="release-state release-live"><span /> Available now</p>
          <h2>ControlForge for Mac</h2>
          <p className="release-version">Version 0.4.0 · staging pilot · Apple Silicon</p>
          <div className="release-facts">
            {releaseFacts.map(([label, value]) => <div key={label}><span>{label}</span><strong>{value}</strong></div>)}
          </div>
          <a className="button button-primary download-button" href={`${releaseBase}/ControlForge-0.4.0.pkg`} download>
            Download signed pilot <Arrow />
          </a>
          <div className="release-links" aria-label="Release evidence downloads">
            <a href={`${releaseBase}/ControlForge-0.4.0.release.json`}>Release manifest</a>
            <a href={`${releaseBase}/SHA256SUMS.txt`}>SHA-256 file</a>
            <a href={`${releaseBase}/RELEASE-NOTES.txt`}>Release notes</a>
          </div>
          <p className="availability-note">This build connects to the staging account service and is intended for a non-critical pilot Mac. It is signed and notarized; clean-Mac lifecycle acceptance and production service levels remain open.</p>
        </div>
        <aside className="verification-card">
          <p className="kicker">Evidence for this exact file</p>
          <ol>
            <li><span>✓</span><div><strong>Clean source</strong><p>Built from commit <code>fa34b23</code> with <code>source_dirty=false</code>.</p></div></li>
            <li><span>✓</span><div><strong>Apple verified</strong><p>Developer ID signed, notarized, stapled, and Gatekeeper accepted.</p></div></li>
            <li><span>✓</span><div><strong>Tests passed</strong><p>557 Python tests and 115 Worker tests passed before signing.</p></div></li>
            <li><span>!</span><div><strong>Pilot boundary</strong><p>Clean-Mac install, upgrade, rollback, and uninstall evidence is still pending.</p></div></li>
          </ol>
        </aside>
      </section>
      <section className="checksum-panel" data-reveal aria-labelledby="verify-download">
        <div>
          <p className="kicker">Verify before opening</p>
          <h2 id="verify-download">One file. One measured identity.</h2>
          <p>After downloading, run <code>shasum -a 256 ControlForge-0.4.0.pkg</code>. The result must match this value exactly.</p>
        </div>
        <code className="checksum-value">{checksum}</code>
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
    </SiteShell>
  );
}
