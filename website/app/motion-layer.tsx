'use client';

import { useEffect } from 'react';

export function MotionLayer() {
  useEffect(() => {
    const root = document.documentElement;
    root.classList.add('motion-ready');
    const prefersReducedMotion = window.matchMedia('(prefers-reduced-motion: reduce)').matches;
    const revealNodes = Array.from(document.querySelectorAll<HTMLElement>('[data-reveal]'));

    if (prefersReducedMotion) {
      revealNodes.forEach((node) => node.classList.add('is-visible'));
      return () => root.classList.remove('motion-ready');
    }

    const observer = new IntersectionObserver(
      (entries) => {
        entries.forEach((entry) => {
          if (entry.isIntersecting) {
            (entry.target as HTMLElement).classList.add('is-visible');
            observer.unobserve(entry.target);
          }
        });
      },
      { rootMargin: '0px 0px -12% 0px', threshold: 0.08 },
    );
    revealNodes.forEach((node) => observer.observe(node));

    let frame = 0;
    const updateScroll = () => {
      if (frame) return;
      frame = window.requestAnimationFrame(() => {
        const scrollRange = Math.max(document.documentElement.scrollHeight - window.innerHeight, 1);
        root.style.setProperty('--page-progress', String(Math.min(window.scrollY / scrollRange, 1)));
        root.style.setProperty('--hero-shift', String(Math.min(window.scrollY * 0.035, 24)));
        frame = 0;
      });
    };
    updateScroll();
    window.addEventListener('scroll', updateScroll, { passive: true });

    return () => {
      observer.disconnect();
      window.removeEventListener('scroll', updateScroll);
      if (frame) window.cancelAnimationFrame(frame);
      root.classList.remove('motion-ready');
    };
  }, []);

  return (
    <div className="evidence-rail" aria-hidden="true">
      <span>Evidence trace</span>
      <div><i /></div>
      <em>Verified</em>
    </div>
  );
}
