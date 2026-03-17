"use client";

import Link from 'next/link';
import Image from 'next/image';
import { Shield, ArrowRight } from 'lucide-react';

export default function LandingPage() {
  return (
    <main className="relative min-h-screen overflow-hidden bg-white text-[#1e1f23]">
      <Image
        src="/HeroBack.png"
        alt="Hero background"
        fill
        priority
        className="pointer-events-none object-cover opacity-55"
      />
      <div className="pointer-events-none absolute bottom-0 right-0 h-[89vh] w-[52vw] min-w-[320px] max-w-[1120px] z-0">
        <Image
          src="/HeroImage.png"
          alt="Threat detection hero visual"
          fill
          priority
          className="object-contain object-bottom-right"
        />
      </div>
      <div className="pointer-events-none absolute right-[12%] top-[19%] z-20 hidden md:block">
        <article className="float-card-a rotate-[4deg] rounded-2xl border border-rose-200 bg-white/95 px-3 py-2 shadow-[0_10px_24px_rgba(0,0,0,0.14)] backdrop-blur-sm">
          <div className="flex items-center gap-2">
            <Image src="/user2.png" alt="Targeted user" width={54} height={54} className="rounded-full" />
            <div>
              <p className="text-base font-medium leading-none text-rose-500">Targeted User</p>
              <p className="text-[10px] uppercase tracking-wide text-rose-400">Inbox activity</p>
            </div>
          </div>
        </article>
      </div>
      <div className="pointer-events-none absolute right-[22%] top-[52%] z-20 hidden md:block">
        <article className="float-card-b -rotate-[4deg] rounded-2xl border border-rose-200 bg-white/95 px-3 py-2 shadow-[0_10px_24px_rgba(0,0,0,0.14)] backdrop-blur-sm">
          <div className="flex items-center gap-2">
            <Image src="/user1.png" alt="Detected link user" width={54} height={54} className="rounded-full" />
            <div>
              <p className="text-base font-medium leading-none text-rose-500">Link Detected</p>
              <p className="text-[10px] uppercase tracking-wide text-rose-400">External URL</p>
            </div>
          </div>
        </article>
      </div>
      <div className="pointer-events-none absolute inset-0 bg-[radial-gradient(circle_at_20%_0%,rgba(255,255,255,0.78),transparent_45%),radial-gradient(circle_at_85%_20%,rgba(255,255,255,0.6),transparent_38%)]" />

      <div className="relative z-10 mx-auto flex min-h-screen w-full max-w-7xl flex-col px-6 pb-10 pt-6 md:px-10">
        <header className="relative flex items-center justify-between rounded-full border border-white/60 bg-white/35 px-6 py-3 shadow-[0_14px_42px_rgba(15,23,42,0.16)] backdrop-blur-xl">
          <div className="pointer-events-none absolute inset-0 rounded-full bg-gradient-to-r from-white/45 via-white/12 to-white/35" />
          <div className="relative z-10 flex items-center gap-2 text-sm font-semibold text-slate-700">
            <Shield className="h-4 w-4 text-[var(--color-primary)]" />
            AegisAI
          </div>

          <nav className="relative z-10 hidden items-center gap-7 text-sm font-medium text-slate-500 md:flex">
            <Link href="/dashboard" className="transition hover:text-slate-900">Dashboard</Link>
            <Link href="/emails" className="transition hover:text-slate-900">Emails</Link>
            <Link href="/reports" className="transition hover:text-slate-900">Reports</Link>
          </nav>

          <Link href="/scanner" className="relative z-10 rounded-full border border-white/70 bg-white/55 px-4 py-1.5 text-xs font-semibold text-slate-700 shadow-sm transition hover:bg-white/75">
            Open Scanner
          </Link>
        </header>

        <section className="grid flex-1 grid-cols-1 items-center gap-8 py-10 md:grid-cols-2 md:gap-10 md:py-14">
          <div className="space-y-6">
            <h1 className="max-w-xl text-4xl font-bold leading-tight text-[#2a2c32] md:text-6xl md:leading-[1.05]">
              Detect Phishing, Spam & Cyber Threats in Seconds
            </h1>

            <p className="max-w-lg text-lg leading-relaxed text-slate-700">
              Our AI analyzes emails in real time to detect phishing attacks, malicious links, spam campaigns, and suspicious senders before they reach your inbox.
            </p>

            <Link
              href="/dashboard"
              className="inline-flex items-center gap-2 rounded-full bg-black px-8 py-3 text-sm font-bold uppercase tracking-wide text-white shadow-[0_14px_30px_rgba(0,0,0,0.28)] transition hover:bg-slate-900"
            >
              Get Started
              <ArrowRight className="h-4 w-4" />
            </Link>
          </div>

          <div aria-hidden="true" className="hidden md:block" />
        </section>
      </div>
    </main>
  );
}
