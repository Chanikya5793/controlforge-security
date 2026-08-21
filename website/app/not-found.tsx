import Link from 'next/link';
import { SiteFooter, SiteHeader } from './components';

export default function NotFound() {
  return <main><SiteHeader /><section className="not-found"><p>404</p><h1>That page is not part of this network.</h1><Link className="button button-primary" href="/">Return home</Link></section><SiteFooter /></main>;
}
