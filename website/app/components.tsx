import Link from 'next/link';

export const ShieldMark = () => (
  <span className="shield-mark" aria-hidden="true">
    <span />
  </span>
);

export const Arrow = () => <span aria-hidden="true">↗</span>;

export function SiteHeader() {
  return (
    <header className="site-header">
      <Link className="brand" href="/" aria-label="ControlForge home">
        <ShieldMark />
        <span>ControlForge</span>
      </Link>
      <nav aria-label="Primary navigation">
        <Link href="/#product">Product</Link>
        <Link href="/#how-it-works">How it works</Link>
        <Link href="/security">Trust</Link>
        <Link href="/docs">Docs</Link>
      </nav>
      <Link className="header-action" href="/download">
        Get the preview <Arrow />
      </Link>
    </header>
  );
}

export function SiteFooter() {
  return (
    <footer className="site-footer">
      <div className="footer-brand">
        <Link className="brand" href="/"><ShieldMark /><span>ControlForge</span></Link>
        <p>Evidence-first security operations for the Macs people actually use.</p>
      </div>
      <div>
        <p className="footer-label">Product</p>
        <Link href="/#product">Overview</Link>
        <Link href="/download">Download</Link>
        <Link href="/security">Security</Link>
      </div>
      <div>
        <p className="footer-label">Resources</p>
        <Link href="/docs">Documentation</Link>
        <a href="https://github.com/Chanikya5793/controlforge-security">GitHub</a>
        <a href="https://github.com/Chanikya5793/controlforge-security/releases">Release history</a>
      </div>
      <div className="footer-note">
        <p className="footer-label">Current availability</p>
        <strong>Private preview</strong>
        <p>For controlled Apple Silicon Mac pilots. Production readiness is not yet claimed.</p>
      </div>
      <p className="copyright">© 2026 ControlForge. Deterministic detections remain the security decision boundary.</p>
    </footer>
  );
}

export function PageIntro({ eyebrow, title, lede }: { eyebrow: string; title: string; lede: string }) {
  return (
    <section className="page-intro">
      <p className="eyebrow"><span /> {eyebrow}</p>
      <h1>{title}</h1>
      <p>{lede}</p>
    </section>
  );
}
