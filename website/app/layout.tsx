import type { Metadata } from 'next';
import { Bricolage_Grotesque, IBM_Plex_Mono, IBM_Plex_Sans } from 'next/font/google';
import './globals.css';
import { MotionLayer } from './motion-layer';

const display = Bricolage_Grotesque({
  variable: '--font-display',
  subsets: ['latin'],
});

const body = IBM_Plex_Sans({
  variable: '--font-body',
  subsets: ['latin'],
  weight: ['400', '500', '600', '700'],
});

const utility = IBM_Plex_Mono({
  variable: '--font-utility',
  subsets: ['latin'],
  weight: ['400', '500', '600'],
});

export const metadata: Metadata = {
  metadataBase: new URL('https://controlforge.chanakyachowdary.in'),
  title: 'ControlForge — Mac security your whole team can understand',
  description:
    'Know which Macs are reporting, what needs attention, and what to do next with evidence-first security operations.',
  openGraph: {
    title: 'ControlForge',
    description: 'Mac security your whole team can understand.',
    images: [{ url: '/og.png', width: 1731, height: 909, alt: 'ControlForge — Mac security your whole team can understand.' }],
  },
  twitter: {
    card: 'summary_large_image',
    title: 'ControlForge',
    description: 'Mac security your whole team can understand.',
    images: ['/og.png'],
  },
};

export default function RootLayout({
  children,
}: Readonly<{
  children: React.ReactNode;
}>) {
  return (
    <html lang="en">
      <body
        className={`${display.variable} ${body.variable} ${utility.variable} antialiased`}
      >
        <MotionLayer />
        {children}
      </body>
    </html>
  );
}
