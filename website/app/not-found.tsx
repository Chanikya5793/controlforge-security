import Link from 'next/link';
import { SiteShell } from './components';

export default function NotFound() {
  return <SiteShell><section className="not-found"><p>404</p><h1>That page is not part of this network.</h1><Link className="button button-primary" href="/">Return home</Link></section></SiteShell>;
}
