"use client";

import React, { useState, useEffect } from 'react';
import { motion, AnimatePresence } from 'motion/react';
import {
  Shield, ShieldAlert, ShieldCheck, AlertTriangle, FileText,
  Trash2, ChevronDown, ChevronRight, Search, X, Clock,
} from 'lucide-react';
import { getScans, deleteScan, clearScans, ScanRecord } from '../../services/scan-history';

const RISK_CONFIG = {
  Safe:     { color: 'text-[var(--color-safe)]',    bg: 'bg-[var(--color-safe)]/10',    border: 'border-[var(--color-safe)]/30' },
  Low:      { color: 'text-blue-400',               bg: 'bg-blue-400/10',               border: 'border-blue-400/30' },
  Medium:   { color: 'text-[var(--color-warning)]', bg: 'bg-[var(--color-warning)]/10', border: 'border-[var(--color-warning)]/30' },
  High:     { color: 'text-orange-500',             bg: 'bg-orange-500/10',             border: 'border-orange-500/30' },
  Critical: { color: 'text-[var(--color-danger)]',  bg: 'bg-[var(--color-danger)]/10',  border: 'border-[var(--color-danger)]/30' },
} as const;

type RiskFilter = 'All' | keyof typeof RISK_CONFIG;

export default function ReportsPage() {
  const [scans, setScans] = useState<ScanRecord[]>([]);
  const [filter, setFilter] = useState<RiskFilter>('All');
  const [search, setSearch] = useState('');
  const [expandedId, setExpandedId] = useState<string | null>(null);
  const [confirmClear, setConfirmClear] = useState(false);

  useEffect(() => {
    setScans(getScans());
  }, []);

  const filtered = scans
    .filter(s => filter === 'All' || s.result.riskLevel === filter)
    .filter(s =>
      !search ||
      s.input.toLowerCase().includes(search.toLowerCase()) ||
      s.result.threatType.toLowerCase().includes(search.toLowerCase())
    );

  const handleDelete = (id: string) => {
    deleteScan(id);
    setScans(prev => prev.filter(s => s.id !== id));
    if (expandedId === id) setExpandedId(null);
  };

  const handleClearAll = () => {
    clearScans();
    setScans([]);
    setExpandedId(null);
    setConfirmClear(false);
  };

  return (
    <main className="flex-1 flex flex-col h-full overflow-hidden relative">
      <div className="flex-1 overflow-y-auto p-4 md:p-8 lg:p-10">
        <div className="max-w-5xl mx-auto space-y-8">

          {/* Header */}
          <header className="flex flex-col sm:flex-row sm:items-end sm:justify-between gap-4">
            <div className="space-y-1">
              <h2 className="text-3xl font-bold text-white tracking-tight">Reports</h2>
              <p className="text-slate-400">Full history of all threat analyses performed.</p>
            </div>
            {scans.length > 0 && (
              confirmClear ? (
                <div className="flex items-center gap-2">
                  <span className="text-sm text-slate-400">Delete all records?</span>
                  <button onClick={handleClearAll} className="px-3 py-1.5 text-xs font-semibold bg-red-500 hover:bg-red-600 text-white rounded-lg transition-colors">
                    Confirm
                  </button>
                  <button onClick={() => setConfirmClear(false)} className="px-3 py-1.5 text-xs font-semibold bg-white/10 hover:bg-white/20 text-slate-300 rounded-lg transition-colors">
                    Cancel
                  </button>
                </div>
              ) : (
                <button
                  onClick={() => setConfirmClear(true)}
                  className="flex items-center gap-2 px-4 py-2 rounded-lg text-sm font-medium text-red-400 hover:bg-red-500/10 border border-red-500/20 transition-colors"
                >
                  <Trash2 className="w-4 h-4" />
                  Clear All
                </button>
              )
            )}
          </header>

          {/* Search + Filter bar */}
          <div className="glass-panel rounded-2xl p-4 flex flex-col sm:flex-row gap-4">
            <div className="relative flex-1">
              <Search className="absolute left-3 top-1/2 -translate-y-1/2 w-4 h-4 text-slate-500" />
              <input
                value={search}
                onChange={e => setSearch(e.target.value)}
                placeholder="Search by input content or threat type..."
                className="w-full bg-white/5 border border-[var(--color-border)] rounded-lg pl-10 pr-9 py-2.5 text-sm text-slate-200 placeholder-slate-500 focus:outline-none focus:border-[var(--color-primary)]/50 transition-colors"
              />
              {search && (
                <button onClick={() => setSearch('')} className="absolute right-3 top-1/2 -translate-y-1/2 text-slate-500 hover:text-slate-300">
                  <X className="w-4 h-4" />
                </button>
              )}
            </div>
            <div className="flex gap-2 flex-wrap">
              {(['All', 'Safe', 'Low', 'Medium', 'High', 'Critical'] as RiskFilter[]).map(lvl => {
                const isActive = filter === lvl;
                const cfg = lvl !== 'All' ? RISK_CONFIG[lvl] : null;
                return (
                  <button
                    key={lvl}
                    onClick={() => setFilter(lvl)}
                    className={`px-3 py-1.5 rounded-lg text-xs font-medium transition-colors border ${
                      isActive
                        ? lvl === 'All'
                          ? 'bg-[var(--color-primary)]/10 text-[var(--color-primary)] border-[var(--color-primary)]/30'
                          : `${cfg!.bg} ${cfg!.color} ${cfg!.border}`
                        : 'bg-transparent text-slate-400 hover:text-slate-200 border-[var(--color-border)] hover:bg-white/5'
                    }`}
                  >
                    {lvl}
                  </button>
                );
              })}
            </div>
          </div>

          {/* Count */}
          {scans.length > 0 && (
            <p className="text-sm text-slate-500">
              Showing <span className="text-slate-300">{filtered.length}</span> of <span className="text-slate-300">{scans.length}</span> scans
            </p>
          )}

          {/* List */}
          {filtered.length === 0 ? (
            <div className="glass-panel rounded-2xl p-16 flex flex-col items-center justify-center text-center">
              <FileText className="w-12 h-12 text-slate-500 mb-4 opacity-50" />
              <p className="text-slate-300 font-semibold">
                {scans.length === 0 ? 'No reports yet' : 'No results match your filters'}
              </p>
              <p className="text-slate-500 text-sm mt-1">
                {scans.length === 0
                  ? 'Run your first scan from the Scanner page.'
                  : 'Try adjusting your search or filter settings.'}
              </p>
            </div>
          ) : (
            <div className="space-y-3">
              <AnimatePresence initial={false}>
                {filtered.map((scan, i) => {
                  const cfg = RISK_CONFIG[scan.result.riskLevel as keyof typeof RISK_CONFIG];
                  const isExpanded = expandedId === scan.id;
                  return (
                    <motion.div
                      key={scan.id}
                      initial={{ opacity: 0, y: 10 }}
                      animate={{ opacity: 1, y: 0 }}
                      exit={{ opacity: 0, x: -20, height: 0, marginBottom: 0 }}
                      transition={{ delay: Math.min(i * 0.03, 0.3) }}
                      className={`glass-panel rounded-2xl border overflow-hidden ${cfg.border}`}
                    >
                      {/* Row */}
                      <div
                        className="flex items-center gap-4 p-4 cursor-pointer hover:bg-white/5 transition-colors"
                        onClick={() => setExpandedId(isExpanded ? null : scan.id)}
                      >
                        <div className={`w-10 h-10 rounded-xl ${cfg.bg} flex items-center justify-center shrink-0`}>
                          {scan.result.riskLevel === 'Safe'
                            ? <ShieldCheck className={`w-5 h-5 ${cfg.color}`} />
                            : ['High', 'Critical'].includes(scan.result.riskLevel)
                              ? <ShieldAlert className={`w-5 h-5 ${cfg.color}`} />
                              : <AlertTriangle className={`w-5 h-5 ${cfg.color}`} />}
                        </div>
                        <div className="flex-1 min-w-0">
                          <p className="text-sm text-slate-200 truncate font-medium">{scan.input}</p>
                          <div className="flex items-center gap-3 mt-0.5 flex-wrap">
                            <span className="text-xs text-slate-500 flex items-center gap-1">
                              <Clock className="w-3 h-3" />
                              {new Date(scan.timestamp).toLocaleString('en-US', {
                                month: 'short', day: 'numeric', year: 'numeric',
                                hour: '2-digit', minute: '2-digit',
                              })}
                            </span>
                            <span className="text-xs text-slate-400">{scan.result.threatType}</span>
                          </div>
                        </div>
                        <div className="flex items-center gap-2 shrink-0">
                          <span className={`hidden sm:inline-flex text-xs font-semibold px-2.5 py-1 rounded-full border ${cfg.bg} ${cfg.color} ${cfg.border}`}>
                            {scan.result.riskLevel}
                          </span>
                          <span className="text-xs text-slate-500 tabular-nums w-10 text-right">
                            {scan.result.confidenceScore}%
                          </span>
                          <button
                            onClick={e => { e.stopPropagation(); handleDelete(scan.id); }}
                            className="p-1.5 rounded-lg text-slate-500 hover:text-red-400 hover:bg-red-500/10 transition-colors"
                          >
                            <Trash2 className="w-4 h-4" />
                          </button>
                          {isExpanded
                            ? <ChevronDown className="w-4 h-4 text-slate-400" />
                            : <ChevronRight className="w-4 h-4 text-slate-400" />}
                        </div>
                      </div>

                      {/* Expanded details */}
                      <AnimatePresence>
                        {isExpanded && (
                          <motion.div
                            initial={{ height: 0, opacity: 0 }}
                            animate={{ height: 'auto', opacity: 1 }}
                            exit={{ height: 0, opacity: 0 }}
                            transition={{ duration: 0.2 }}
                            className="overflow-hidden border-t border-[var(--color-border)]"
                          >
                            <div className="p-6 space-y-5">
                              <div>
                                <h4 className="text-xs font-semibold text-slate-400 uppercase tracking-wider mb-2">Explanation</h4>
                                <p className="text-sm text-slate-300 leading-relaxed">{scan.result.explanation}</p>
                              </div>
                              <div className="grid grid-cols-1 md:grid-cols-2 gap-6">
                                <div>
                                  <h4 className="text-xs font-semibold text-slate-400 uppercase tracking-wider mb-3 flex items-center gap-2">
                                    <Search className="w-3.5 h-3.5" /> Key Indicators
                                  </h4>
                                  <ul className="space-y-2">
                                    {scan.result.indicators.map((ind, idx) => (
                                      <li key={idx} className="flex items-start gap-2 text-sm text-slate-300">
                                        <ChevronRight className="w-4 h-4 text-[var(--color-primary)] shrink-0 mt-0.5" />
                                        <span>{ind}</span>
                                      </li>
                                    ))}
                                  </ul>
                                </div>
                                <div>
                                  <h4 className="text-xs font-semibold text-slate-400 uppercase tracking-wider mb-3 flex items-center gap-2">
                                    <ShieldCheck className="w-3.5 h-3.5" /> Recommendations
                                  </h4>
                                  <ul className="space-y-2">
                                    {scan.result.recommendations.map((rec, idx) => (
                                      <li key={idx} className="flex items-start gap-2 text-sm text-slate-300">
                                        <span className="w-5 h-5 rounded-full bg-[var(--color-accent)]/10 text-[var(--color-accent)] flex items-center justify-center shrink-0 border border-[var(--color-accent)]/20 text-xs font-bold mt-0.5">
                                          {idx + 1}
                                        </span>
                                        <span>{rec}</span>
                                      </li>
                                    ))}
                                  </ul>
                                </div>
                              </div>
                            </div>
                          </motion.div>
                        )}
                      </AnimatePresence>
                    </motion.div>
                  );
                })}
              </AnimatePresence>
            </div>
          )}
        </div>
      </div>

      {/* Background glows */}
      <div className="absolute top-[-10%] left-[-10%] w-[40%] h-[40%] rounded-full bg-[var(--color-primary)]/5 blur-[120px] pointer-events-none" />
      <div className="absolute bottom-[-10%] right-[-10%] w-[40%] h-[40%] rounded-full bg-[var(--color-accent)]/5 blur-[120px] pointer-events-none" />
    </main>
  );
}
