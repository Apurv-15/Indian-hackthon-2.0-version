'use client';

import { useCallback, useEffect, useState } from 'react';
import EmailCard from '../../components/EmailCard';
import { 
  X, 
  ShieldAlert, 
  ShieldCheck, 
  AlertTriangle, 
  Activity, 
  Search, 
  Info,
  ChevronRight,
  RefreshCw,
  Loader2,
  Database,
  Zap
} from 'lucide-react';
import { motion, AnimatePresence } from 'motion/react';
import {
  getCachedAnalysis,
  setCachedAnalysis,
  deleteCachedAnalysis,
} from '../../services/email-analysis-cache';

const PENDING_ANALYSIS = {
  riskLevel: 'Safe',
  threatType: 'Analyzing...',
  confidenceScore: 0,
  explanation: 'AI agents are analyzing this email...',
  indicators: [],
  recommendations: [],
};

async function analyzeEmail(email) {
  const input = `Subject: ${email.subject}\nFrom: ${email.from}\nContent: ${email.snippet}`;
  const res = await fetch('/api/emails/analyze', {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ input }),
    signal: AbortSignal.timeout(15000),
  });
  if (!res.ok) throw new Error('Analysis failed');
  return res.json();
}

export default function EmailsPage() {
  const [emails, setEmails] = useState([]);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState('');
  const [selectedEmail, setSelectedEmail] = useState(null);
  const [retesting, setRetesting] = useState(false);

  // Fetch emails (metadata only — no AI calls on server)
  const fetchEmails = useCallback(async () => {
    try {
      const res = await fetch('/api/emails', { cache: 'no-store' });
      if (!res.ok) {
        const data = await res.json();
        throw new Error(data.error || 'Failed to fetch emails');
      }
      const data = await res.json();
      const rawEmails = Array.isArray(data) ? data : [];

      // Hydrate each email with cached analysis or mark for async analysis
      const hydrated = rawEmails.map((email) => {
        const cached = getCachedAnalysis(email.id);
        return {
          ...email,
          analysis: cached || PENDING_ANALYSIS,
          _cached: !!cached,
        };
      });

      setEmails(hydrated);
      setError('');

      // Trigger background analysis for uncached emails
      hydrated.forEach((email) => {
        if (!email._cached) {
          analyzeEmail(email)
            .then((analysis) => {
              setCachedAnalysis(email.id, analysis);
              setEmails((prev) =>
                prev.map((e) =>
                  e.id === email.id ? { ...e, analysis, _cached: true } : e
                )
              );
            })
            .catch((err) => {
              console.error(`Analysis failed for ${email.id}:`, err.message);
            });
        }
      });
    } catch (err) {
      setError(err.message || 'Could not load emails');
    } finally {
      setLoading(false);
    }
  }, []);

  useEffect(() => {
    fetchEmails();
    const timer = setInterval(fetchEmails, 60000); // 60s for emails (cached = instant)
    return () => clearInterval(timer);
  }, [fetchEmails]);

  // Retest: delete cache, re-analyze
  const handleRetest = async () => {
    if (!selectedEmail || retesting) return;
    setRetesting(true);
    try {
      deleteCachedAnalysis(selectedEmail.id);
      const analysis = await analyzeEmail(selectedEmail);
      setCachedAnalysis(selectedEmail.id, analysis);
      const updated = { ...selectedEmail, analysis, _cached: true };
      setSelectedEmail(updated);
      setEmails((prev) =>
        prev.map((e) => (e.id === selectedEmail.id ? updated : e))
      );
    } catch (err) {
      console.error('Retest failed:', err.message);
    } finally {
      setRetesting(false);
    }
  };

  const getRiskColor = (level) => {
    switch (level) {
      case 'Safe': return 'text-emerald-500';
      case 'Low': return 'text-blue-400';
      case 'Medium': return 'text-amber-500';
      case 'High': return 'text-orange-500';
      case 'Critical': return 'text-red-500';
      default: return 'text-gray-400';
    }
  };

  const getRiskBg = (level) => {
    switch (level) {
      case 'Safe': return 'bg-emerald-500/10 border-emerald-500/30';
      case 'Low': return 'bg-blue-400/10 border-blue-400/30';
      case 'Medium': return 'bg-amber-500/10 border-amber-500/30';
      case 'High': return 'bg-orange-500/10 border-orange-500/30';
      case 'Critical': return 'bg-red-500/10 border-red-500/30';
      default: return 'bg-gray-400/10 border-gray-400/30';
    }
  };

  const getRiskIcon = (level) => {
    switch (level) {
      case 'Safe': return <ShieldCheck className="w-8 h-8 text-emerald-500" />;
      case 'Low': return <ShieldCheck className="w-8 h-8 text-blue-400" />;
      case 'Medium': return <AlertTriangle className="w-8 h-8 text-amber-500" />;
      case 'High': return <ShieldAlert className="w-8 h-8 text-orange-500" />;
      case 'Critical': return <ShieldAlert className="w-8 h-8 text-red-500" />;
      default: return <AlertTriangle className="w-8 h-8 text-amber-500" />;
    }
  };

  const getRiskEmoji = (level) => {
    switch (level) {
      case 'Safe': return '🟢';
      case 'Low': return '🔵';
      case 'Medium': return '🟡';
      case 'High': return '🟠';
      case 'Critical': return '🔴';
      default: return '⚪';
    }
  };

  const getIndicatorIcon = (indicator) => {
    const lower = indicator.toLowerCase();
    if (lower.startsWith('url analysis')) return '🔗';
    if (lower.startsWith('sender spoofing')) return '👤';
    if (lower.startsWith('content analysis')) return '📝';
    if (lower.startsWith('behavioral threat')) return '⚠️';
    if (lower.startsWith('prompt injection')) return '💉';
    if (lower.startsWith('hidden threat')) return '🕵️';
    return '🔍';
  };

  return (
    <main className="flex-1 h-full overflow-hidden w-full p-2 md:p-6 z-0 flex gap-6">
      <section className="flex-1 overflow-y-auto space-y-6">
        <header className="flex items-center justify-between py-1 px-2">
          <h1 className="text-2xl md:text-3xl font-medium text-slate-800 tracking-tight">
            Inbox
          </h1>
          <p className="text-sm text-slate-500 font-medium">
            {emails.length} conversations
          </p>
        </header>

        {loading && emails.length === 0 && (
          <div className="rounded-[2.5rem] border border-white/50 bg-white p-6 shadow-[0_8px_30px_rgb(0,0,0,0.04)] text-slate-500 flex justify-center items-center py-20 font-medium">
            Loading emails...
          </div>
        )}

        {error && !loading && (
          <div className="mb-6 rounded-2xl border border-red-200 bg-red-50 p-4 text-sm text-red-600 font-medium tracking-wide">
            {error}
          </div>
        )}

        {!loading && !error && emails.length === 0 && (
          <div className="rounded-[2.5rem] border border-white/50 bg-white p-6 shadow-[0_8px_30px_rgb(0,0,0,0.04)] text-slate-500 text-center py-20 font-medium">
            No emails found in the inbox.
          </div>
        )}

        {emails.length > 0 && (
          <section className="rounded-2xl border border-slate-200 bg-white shadow-[0_8px_30px_rgb(0,0,0,0.04)] overflow-hidden pb-8">
            <div className="px-4 py-3 border-b border-slate-200 bg-slate-50 text-xs uppercase tracking-wide text-slate-500 font-semibold">
              Unread
            </div>

            <div className="divide-y divide-slate-100">
              {emails.map((email, index) => (
                <EmailCard
                  key={email.id || index}
                  email={email}
                  onSelect={setSelectedEmail}
                />
              ))}
            </div>
          </section>
        )}
      </section>

      {/* Forensic Intelligence Sidebar */}
      <AnimatePresence>
        {selectedEmail && (
          <motion.aside
            initial={{ opacity: 0, x: 100 }}
            animate={{ opacity: 1, x: 0 }}
            exit={{ opacity: 0, x: 100 }}
            className="w-full max-w-md bg-white border-l border-slate-200 shadow-2xl z-20 flex flex-col h-full overflow-hidden rounded-l-[2.5rem]"
          >
            <header className="p-6 border-b border-slate-100 flex items-start justify-between">
              <div>
                <h2 className="text-xs font-bold uppercase tracking-[0.2em] text-slate-400 mb-1">Forensic Intelligence</h2>
                <h3 className="text-xl font-bold text-slate-800">{selectedEmail.from.split('<')[0]}</h3>
              </div>
              <div className="flex items-center gap-2">
                {/* Retest Button */}
                <button 
                  onClick={handleRetest}
                  disabled={retesting}
                  title="Re-analyze this email"
                  className="p-2 hover:bg-blue-50 rounded-full transition-colors text-blue-500 disabled:opacity-50"
                >
                  {retesting ? (
                    <Loader2 className="w-5 h-5 animate-spin" />
                  ) : (
                    <RefreshCw className="w-5 h-5" />
                  )}
                </button>
                <button 
                  onClick={() => setSelectedEmail(null)}
                  className="p-2 hover:bg-slate-50 rounded-full transition-colors"
                >
                  <X className="w-5 h-5 text-slate-400" />
                </button>
              </div>
            </header>

            <div className="flex-1 overflow-y-auto p-6 space-y-8">
              {/* Cache Status Badge */}
              <div className="flex items-center gap-2">
                {selectedEmail._cached ? (
                  <span className="inline-flex items-center gap-1.5 text-[10px] font-bold uppercase tracking-wider text-emerald-600 bg-emerald-50 border border-emerald-200 px-2.5 py-1 rounded-full">
                    <Database className="w-3 h-3" />
                    Cached Result
                  </span>
                ) : (
                  <span className="inline-flex items-center gap-1.5 text-[10px] font-bold uppercase tracking-wider text-blue-600 bg-blue-50 border border-blue-200 px-2.5 py-1 rounded-full">
                    <Zap className="w-3 h-3" />
                    Live Analysis
                  </span>
                )}
              </div>

              {/* Risk Level Summary */}
              <div className={`rounded-3xl p-6 border ${getRiskBg(selectedEmail.analysis.riskLevel)} bg-white shadow-sm flex flex-col items-center text-center`}>
                {getRiskIcon(selectedEmail.analysis.riskLevel)}
                <h4 className="text-xs font-bold text-slate-400 mt-4 uppercase tracking-widest">Risk Level</h4>
                <p className={`text-3xl font-black mt-1 ${getRiskColor(selectedEmail.analysis.riskLevel)}`}>
                  {getRiskEmoji(selectedEmail.analysis.riskLevel)} {selectedEmail.analysis.riskLevel}
                </p>
                <div className="mt-4 w-full bg-slate-100 rounded-full h-1.5 overflow-hidden">
                  <div 
                    className={`h-full transition-all duration-1000 ${
                      selectedEmail.analysis.riskLevel === 'Safe' ? 'bg-emerald-500' : 
                      selectedEmail.analysis.riskLevel === 'Low' ? 'bg-blue-400' : 
                      selectedEmail.analysis.riskLevel === 'Medium' ? 'bg-amber-500' : 
                      selectedEmail.analysis.riskLevel === 'High' ? 'bg-orange-500' : 'bg-red-500'
                    }`}
                    style={{ width: `${selectedEmail.analysis.confidenceScore}%` }}
                  />
                </div>
                <p className="text-[10px] text-slate-400 mt-2 font-bold uppercase tracking-tighter">
                  {selectedEmail.analysis.confidenceScore}% Confidence Score
                </p>
              </div>

              {/* Detailed Scores */}
              {selectedEmail.analysis.detailedScores && (
                <div className="grid grid-cols-2 gap-2">
                  {[
                    { label: 'Phishing', value: selectedEmail.analysis.detailedScores.phishingProb, color: 'text-red-500' },
                    { label: 'Spam', value: selectedEmail.analysis.detailedScores.spamProb, color: 'text-amber-500' },
                    { label: 'URL Risk', value: selectedEmail.analysis.detailedScores.urlRisk, color: 'text-orange-500' },
                    { label: 'Sentiment', value: selectedEmail.analysis.detailedScores.sentimentScore, color: 'text-purple-500' },
                  ].map((score) => (
                    <div key={score.label} className="bg-slate-50 rounded-xl p-3 border border-slate-100">
                      <p className="text-[10px] font-bold text-slate-400 uppercase tracking-wider">{score.label}</p>
                      <p className={`text-lg font-bold ${score.value > 0.5 ? score.color : 'text-slate-700'}`}>
                        {(score.value * 100).toFixed(0)}%
                      </p>
                    </div>
                  ))}
                </div>
              )}

              {/* Analysis Details */}
              <div className="space-y-6">
                <div>
                  <h4 className="text-xs font-bold text-slate-400 uppercase tracking-widest mb-3 flex items-center gap-2">
                    <Activity className="w-3.5 h-3.5" />
                    Threat Classification
                  </h4>
                  <p className="text-sm font-semibold text-slate-700 bg-slate-50 px-3 py-2 rounded-xl border border-slate-100 inline-block">
                    {selectedEmail.analysis.threatType}
                  </p>
                </div>

                <div>
                  <h4 className="text-xs font-bold text-slate-400 uppercase tracking-widest mb-3 flex items-center gap-2">
                    <Info className="w-3.5 h-3.5" />
                    Explainable Reasoning
                  </h4>
                  <p className="text-sm text-slate-600 leading-relaxed bg-slate-50/50 p-4 rounded-2xl border border-slate-100 mb-6">
                    {selectedEmail.analysis.explanation}
                  </p>

                  <h4 className="text-xs font-bold text-slate-400 uppercase tracking-widest mb-3 flex items-center gap-2">
                    <Search className="w-3.5 h-3.5" />
                    Key Indicators
                  </h4>
                  {selectedEmail.analysis.indicators?.length > 0 ? (
                    <ul className="space-y-3">
                      {selectedEmail.analysis.indicators.map((indicator, idx) => (
                        <li key={idx} className="flex items-start gap-2.5 text-xs text-slate-600 font-medium bg-slate-50/70 border border-slate-100 rounded-xl p-3">
                          <span className="text-base shrink-0 mt-[-1px]">{getIndicatorIcon(indicator)}</span>
                          <span className="leading-relaxed">{indicator}</span>
                        </li>
                      ))}
                    </ul>
                  ) : (
                    <p className="text-sm text-slate-400 italic px-2">
                      No specific behavioral signals detected.
                    </p>
                  )}
                </div>
              </div>

              {/* Recommendations */}
              {selectedEmail.analysis.recommendations?.length > 0 && (
                <div className="pt-4">
                  <h4 className="text-xs font-bold text-slate-400 uppercase tracking-widest mb-4 flex items-center gap-2">
                    <ShieldCheck className="w-3.5 h-3.5" />
                    Recommended Actions
                  </h4>
                  <div className="space-y-3">
                    {selectedEmail.analysis.recommendations.map((rec, idx) => (
                      <div key={idx} className="flex items-start gap-3 p-3 rounded-2xl bg-slate-50 border border-slate-100 text-xs text-slate-700 font-bold">
                        <div className="w-5 h-5 rounded-lg bg-white border border-slate-200 flex items-center justify-center shrink-0 shadow-sm text-sky-600">
                          {idx + 1}
                        </div>
                        {rec}
                      </div>
                    ))}
                  </div>
                </div>
              )}

              {/* Content Preview */}
              <div className="pt-4">
                <h4 className="text-xs font-bold text-slate-400 uppercase tracking-widest mb-4">Original Context</h4>
                <div className="p-4 rounded-2xl bg-slate-50 border border-slate-100 text-xs text-slate-500 italic leading-relaxed">
                  &quot;{selectedEmail.snippet}&quot;
                </div>
              </div>
            </div>
          </motion.aside>
        )}
      </AnimatePresence>
    </main>
  );
}
