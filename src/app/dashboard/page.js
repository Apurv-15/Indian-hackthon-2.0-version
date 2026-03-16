'use client';

import { useEffect, useMemo, useState } from 'react';
import { Activity, AlertTriangle, ShieldAlert, ShieldCheck } from 'lucide-react';
import { getScans } from '../../services/scan-history';

export default function DashboardPage() {
  const [scans, setScans] = useState([]);

  useEffect(() => {
    const loadScans = () => setScans(getScans());
    loadScans();
    window.addEventListener('focus', loadScans);
    return () => window.removeEventListener('focus', loadScans);
  }, []);

  const riskBuckets = useMemo(() => {
    const base = { Safe: 0, Low: 0, Medium: 0, High: 0, Critical: 0 };
    scans.forEach(scan => {
      const level = scan?.result?.riskLevel;
      if (Object.prototype.hasOwnProperty.call(base, level)) {
        base[level] += 1;
      }
    });
    return base;
  }, [scans]);

  const weeklyTrend = useMemo(() => {
    const labels = [];
    const today = new Date();

    for (let i = 6; i >= 0; i -= 1) {
      const date = new Date(today);
      date.setDate(today.getDate() - i);
      labels.push({
        key: date.toISOString().slice(0, 10),
        label: date.toLocaleDateString([], { weekday: 'short' }),
        value: 0,
      });
    }

    scans.forEach(scan => {
      const dateKey = new Date(scan.timestamp).toISOString().slice(0, 10);
      const point = labels.find(item => item.key === dateKey);
      if (point) {
        point.value += 1;
      }
    });

    return labels;
  }, [scans]);

  const total = scans.length;
  const flagged = riskBuckets.High + riskBuckets.Critical;
  const safeRate = total ? Math.round((riskBuckets.Safe / total) * 100) : 0;
  const maxTrend = Math.max(...weeklyTrend.map(point => point.value), 1);

  return (
    <main className="flex-1 h-full overflow-y-auto w-full p-2 md:p-6 z-0">
      <section className="mx-auto max-w-7xl space-y-6">

        <header className="flex items-center justify-between py-1 px-2">
          <div>
            <h1 className="text-2xl md:text-3xl font-semibold text-slate-800 tracking-tight">Dashboard</h1>
            <p className="text-sm text-slate-500">Live security posture from recent scans</p>
          </div>
          <div className="text-right">
            <p className="text-xs uppercase tracking-wider text-slate-400 font-semibold">Total scans</p>
            <p className="text-2xl font-bold text-slate-800">{total}</p>
          </div>
        </header>

        <section className="grid grid-cols-1 md:grid-cols-3 gap-4">
          <article className="rounded-2xl border border-slate-200 bg-white p-5 shadow-[0_8px_30px_rgb(0,0,0,0.04)]">
            <div className="flex items-center justify-between">
              <p className="text-sm text-slate-500 font-medium">High risk alerts</p>
              <ShieldAlert className="w-5 h-5 text-red-500" />
            </div>
            <p className="mt-3 text-3xl font-bold text-slate-900">{flagged}</p>
            <p className="text-xs text-slate-500 mt-1">High + Critical findings</p>
          </article>

          <article className="rounded-2xl border border-slate-200 bg-white p-5 shadow-[0_8px_30px_rgb(0,0,0,0.04)]">
            <div className="flex items-center justify-between">
              <p className="text-sm text-slate-500 font-medium">Safe outcome rate</p>
              <ShieldCheck className="w-5 h-5 text-emerald-500" />
            </div>
            <p className="mt-3 text-3xl font-bold text-slate-900">{safeRate}%</p>
            <p className="text-xs text-slate-500 mt-1">Share of scans marked safe</p>
          </article>

          <article className="rounded-2xl border border-slate-200 bg-white p-5 shadow-[0_8px_30px_rgb(0,0,0,0.04)]">
            <div className="flex items-center justify-between">
              <p className="text-sm text-slate-500 font-medium">Investigations</p>
              <Activity className="w-5 h-5 text-blue-500" />
            </div>
            <p className="mt-3 text-3xl font-bold text-slate-900">{total - riskBuckets.Safe}</p>
            <p className="text-xs text-slate-500 mt-1">Scans requiring analyst review</p>
          </article>
        </section>

        <section className="grid grid-cols-1 xl:grid-cols-2 gap-4">
          <article className="rounded-2xl border border-slate-200 bg-white p-5 shadow-[0_8px_30px_rgb(0,0,0,0.04)]">
            <h2 className="text-base font-semibold text-slate-900">Risk Distribution</h2>
            <p className="text-xs text-slate-500 mb-4">Breakdown across all saved scans</p>

            <div className="space-y-3">
              {Object.entries(riskBuckets).map(([level, value]) => {
                const percent = total ? Math.round((value / total) * 100) : 0;
                return (
                  <div key={level}>
                    <div className="flex items-center justify-between text-xs font-medium text-slate-600 mb-1">
                      <span>{level}</span>
                      <span>{value} ({percent}%)</span>
                    </div>
                    <div className="h-2 rounded-full bg-slate-100 overflow-hidden">
                      <div
                        className={`h-full ${
                          level === 'Safe'
                            ? 'bg-emerald-500'
                            : level === 'Low'
                              ? 'bg-sky-500'
                              : level === 'Medium'
                                ? 'bg-amber-500'
                                : level === 'High'
                                  ? 'bg-orange-500'
                                  : 'bg-red-500'
                        }`}
                        style={{ width: `${percent}%` }}
                      />
                    </div>
                  </div>
                );
              })}
            </div>
          </article>

          <article className="rounded-2xl border border-slate-200 bg-white p-5 shadow-[0_8px_30px_rgb(0,0,0,0.04)]">
            <h2 className="text-base font-semibold text-slate-900">7-Day Trend</h2>
            <p className="text-xs text-slate-500 mb-4">Daily scan volume in the last week</p>

            <div className="h-44 grid grid-cols-7 gap-2 items-end">
              {weeklyTrend.map(point => {
                const barHeight = Math.max(8, Math.round((point.value / maxTrend) * 100));
                return (
                  <div key={point.key} className="flex flex-col items-center gap-2">
                    <div className="w-full rounded-md bg-slate-100 relative overflow-hidden" style={{ height: '110px' }}>
                      <div
                        className="absolute bottom-0 left-0 w-full bg-blue-500 rounded-md"
                        style={{ height: `${barHeight}%` }}
                        title={`${point.value} scans`}
                      />
                    </div>
                    <span className="text-[11px] text-slate-500 font-medium">{point.label}</span>
                  </div>
                );
              })}
            </div>
          </article>
        </section>

        <section className="rounded-2xl border border-slate-200 bg-white p-5 shadow-[0_8px_30px_rgb(0,0,0,0.04)]">
          <h2 className="text-base font-semibold text-slate-900">Recent Activity</h2>
          <p className="text-xs text-slate-500 mb-4">Latest 6 scans from local history</p>

          {total === 0 ? (
            <div className="rounded-xl border border-dashed border-slate-200 p-8 text-center text-sm text-slate-500">
              No scans yet. Use the Scanner page to generate analytics.
            </div>
          ) : (
            <div className="space-y-2">
              {scans.slice(0, 6).map(scan => (
                <div key={scan.id} className="flex items-center justify-between gap-3 p-3 rounded-xl border border-slate-100 hover:bg-slate-50 transition-colors">
                  <div className="min-w-0">
                    <p className="text-sm text-slate-800 font-medium truncate">{scan.input}</p>
                    <p className="text-xs text-slate-500">
                      {new Date(scan.timestamp).toLocaleString()}
                    </p>
                  </div>
                  <span className={`text-xs font-semibold px-2.5 py-1 rounded-full border ${
                    scan.result.riskLevel === 'Safe'
                      ? 'text-emerald-600 bg-emerald-50 border-emerald-200'
                      : scan.result.riskLevel === 'Low'
                        ? 'text-sky-600 bg-sky-50 border-sky-200'
                        : scan.result.riskLevel === 'Medium'
                          ? 'text-amber-600 bg-amber-50 border-amber-200'
                          : scan.result.riskLevel === 'High'
                            ? 'text-orange-600 bg-orange-50 border-orange-200'
                            : 'text-red-600 bg-red-50 border-red-200'
                  }`}
                  >
                    {scan.result.riskLevel}
                  </span>
                </div>
              ))}
            </div>
          )}
        </section>

        {flagged > 0 && (
          <div className="flex items-start gap-3 p-4 rounded-xl border border-red-200 bg-red-50 text-red-700 text-sm">
            <AlertTriangle className="w-4 h-4 shrink-0 mt-0.5" />
            <p>
              You currently have {flagged} high-priority alerts. Review detailed incidents in Reports.
            </p>
          </div>
        )}
      </section>
    </main>
  );
}
