"use client";

import Link from 'next/link';
import { Shield, ArrowRight, BarChart3, Mail, FileText } from 'lucide-react';

export default function LandingPage() {
  return (
    <main className="relative min-h-screen overflow-hidden bg-[var(--color-bg-base)] text-slate-900">
      <div className="absolute inset-0 pointer-events-none">
        <div className="absolute -top-24 -left-16 h-72 w-72 rounded-full bg-sky-200/45 blur-3xl" />
        <div className="absolute top-1/2 -translate-y-1/2 right-0 h-80 w-80 rounded-full bg-cyan-200/40 blur-3xl" />
      </div>

      <section className="relative z-10 mx-auto flex min-h-screen w-full max-w-6xl flex-col justify-center px-6 py-16 md:px-12">
        <div className="mb-8 inline-flex w-fit items-center gap-3 rounded-full border border-slate-200 bg-white px-4 py-2 shadow-sm">
          <Shield className="h-4 w-4 text-[var(--color-primary)]" />
          <span className="text-xs font-semibold uppercase tracking-wider text-slate-600">AegisAI Threat Portal</span>
        </div>

        <h1 className="max-w-4xl text-4xl font-bold tracking-tight text-slate-900 md:text-6xl">
          Detect threats early.
          <span className="block text-slate-500">Respond faster with AI-driven intelligence.</span>
        </h1>

        <p className="mt-5 max-w-2xl text-base leading-relaxed text-slate-600 md:text-lg">
          Monitor phishing risk, scan suspicious content, and review security signals from one operational workspace.
        </p>

        <div className="mt-8 flex flex-wrap items-center gap-3">
          <Link
            href="/dashboard"
            className="inline-flex items-center gap-2 rounded-xl bg-slate-900 px-6 py-3 text-sm font-semibold text-white shadow-lg shadow-slate-900/20 transition hover:bg-slate-800"
          >
            Get Started
            <ArrowRight className="h-4 w-4" />
          </Link>

          <Link
            href="/scanner"
            className="inline-flex items-center gap-2 rounded-xl border border-slate-300 bg-white px-6 py-3 text-sm font-semibold text-slate-700 transition hover:bg-slate-50"
          >
            Open Scanner
          </Link>
        </div>

        <div className="mt-12 grid grid-cols-1 gap-4 sm:grid-cols-3">
          <article className="rounded-2xl border border-slate-200 bg-white p-5 shadow-sm">
            <BarChart3 className="mb-3 h-5 w-5 text-blue-500" />
            <h2 className="text-sm font-semibold text-slate-900">Operational Dashboard</h2>
            <p className="mt-1 text-xs leading-relaxed text-slate-500">Track scan trends and risk levels with clear analytics cards.</p>
          </article>

          <article className="rounded-2xl border border-slate-200 bg-white p-5 shadow-sm">
            <Mail className="mb-3 h-5 w-5 text-amber-500" />
            <h2 className="text-sm font-semibold text-slate-900">Email Monitoring</h2>
            <p className="mt-1 text-xs leading-relaxed text-slate-500">Review inbox threats in a fast, Gmail-like triage workflow.</p>
          </article>

          <article className="rounded-2xl border border-slate-200 bg-white p-5 shadow-sm">
            <FileText className="mb-3 h-5 w-5 text-emerald-500" />
            <h2 className="text-sm font-semibold text-slate-900">Incident Reports</h2>
            <p className="mt-1 text-xs leading-relaxed text-slate-500">Inspect findings, explanations, indicators, and recommended actions.</p>
          </article>
        </div>
      </section>
    </main>
  );
}
