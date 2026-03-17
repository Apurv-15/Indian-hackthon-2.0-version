"use client";

import React, { useState, useEffect } from 'react';
import { motion } from 'motion/react';
import {
  Lock, Shield, AlertTriangle, Globe, Mail, Code,
  Image as ImageIcon, Zap, ShieldCheck, Info, CheckCircle2,
} from 'lucide-react';

interface Policy {
  id: string;
  title: string;
  description: string;
  icon: React.ReactNode;
  severity: 'critical' | 'high' | 'medium' | 'low';
  enabledByDefault: boolean;
  tag: string;
}

const POLICIES: Policy[] = [
  {
    id: 'block-phishing',
    title: 'Block Phishing Attempts',
    description: 'Flag URLs and emails exhibiting phishing behaviours such as domain spoofing, typosquatting, and deceptive login forms.',
    icon: <Mail className="w-5 h-5" />,
    severity: 'critical',
    enabledByDefault: true,
    tag: 'Email & URL',
  },
  {
    id: 'malware-url',
    title: 'Malware URL Detection',
    description: 'Cross-reference input URLs against known malware distribution networks and suspicious redirect chains.',
    icon: <Globe className="w-5 h-5" />,
    severity: 'critical',
    enabledByDefault: true,
    tag: 'URL',
  },
  {
    id: 'prompt-injection',
    title: 'Prompt Injection Detection',
    description: 'Identify hidden instructions embedded in text designed to manipulate AI systems and bypass safety mechanisms.',
    icon: <Code className="w-5 h-5" />,
    severity: 'high',
    enabledByDefault: true,
    tag: 'AI Safety',
  },
  {
    id: 'image-stego',
    title: 'Image Steganography Scan',
    description: 'Inspect images for hidden payloads, encoded malware, or steganographic content concealing malicious instructions.',
    icon: <ImageIcon className="w-5 h-5" />,
    severity: 'high',
    enabledByDefault: true,
    tag: 'Image',
  },
  {
    id: 'social-engineering',
    title: 'Social Engineering Detection',
    description: 'Flag communications that use urgency, fear, or authority manipulation to coerce users into unsafe actions.',
    icon: <AlertTriangle className="w-5 h-5" />,
    severity: 'medium',
    enabledByDefault: true,
    tag: 'Behavioral',
  },
  {
    id: 'code-obfuscation',
    title: 'Code Obfuscation Analysis',
    description: 'Detect heavily obfuscated scripts and code snippets that may be concealing malicious logic or exploits.',
    icon: <Zap className="w-5 h-5" />,
    severity: 'medium',
    enabledByDefault: false,
    tag: 'Code',
  },
  {
    id: 'credential-harvesting',
    title: 'Credential Harvesting Alerts',
    description: 'Detect forms, links, and pages designed to illegitimately harvest user credentials.',
    icon: <Lock className="w-5 h-5" />,
    severity: 'critical',
    enabledByDefault: true,
    tag: 'Privacy',
  },
  {
    id: 'safe-browsing',
    title: 'Safe Browsing Verification',
    description: 'Validate URLs against safe browsing heuristics and check domain age, HTTPS support, and suspicious registration patterns.',
    icon: <ShieldCheck className="w-5 h-5" />,
    severity: 'low',
    enabledByDefault: false,
    tag: 'URL',
  },
];

const SEVERITY_CONFIG = {
  critical: { color: 'text-[var(--color-danger)]',  bg: 'bg-[var(--color-danger)]/10',  border: 'border-[var(--color-danger)]/30',  label: 'Critical' },
  high:     { color: 'text-orange-500',             bg: 'bg-orange-500/10',             border: 'border-orange-500/30',             label: 'High' },
  medium:   { color: 'text-[var(--color-warning)]', bg: 'bg-[var(--color-warning)]/10', border: 'border-[var(--color-warning)]/30', label: 'Medium' },
  low:      { color: 'text-blue-400',               bg: 'bg-blue-400/10',               border: 'border-blue-400/30',               label: 'Low' },
} as const;

const STORAGE_KEY = 'aegis_policies';

export default function PoliciesPage() {
  const [enabled, setEnabled] = useState<Record<string, boolean>>(() =>
    Object.fromEntries(POLICIES.map(p => [p.id, p.enabledByDefault]))
  );
  const [saved, setSaved] = useState(false);

  useEffect(() => {
    try {
      const stored = localStorage.getItem(STORAGE_KEY);
      if (stored) setEnabled(prev => ({ ...prev, ...JSON.parse(stored) }));
    } catch {}
  }, []);

  const toggle = (id: string) => {
    setEnabled(prev => ({ ...prev, [id]: !prev[id] }));
    setSaved(false);
  };

  const handleSave = () => {
    try {
      localStorage.setItem(STORAGE_KEY, JSON.stringify(enabled));
      setSaved(true);
      setTimeout(() => setSaved(false), 3000);
    } catch {}
  };

  const enabledCount = Object.values(enabled).filter(Boolean).length;

  return (
    <main className="flex-1 flex flex-col h-full overflow-hidden relative">
      <div className="flex-1 overflow-y-auto p-4 md:p-8 lg:p-10">
        <div className="max-w-4xl mx-auto space-y-8">

          {/* Header */}
          <header className="flex flex-col sm:flex-row sm:items-end sm:justify-between gap-4">
            <div className="space-y-1">
              <h2 className="text-3xl font-bold text-slate-900 tracking-tight">Security Policies</h2>
              <p className="text-slate-600">Configure the detection rules applied during threat analysis.</p>
            </div>
            <motion.button
              onClick={handleSave}
              whileTap={{ scale: 0.97 }}
              className={`flex items-center gap-2 px-5 py-2.5 rounded-lg text-sm font-semibold transition-all ${
                saved
                  ? 'bg-[var(--color-safe)]/20 text-[var(--color-safe)] border border-[var(--color-safe)]/30'
                  : 'bg-[var(--color-primary)] hover:bg-[var(--color-primary-hover)] text-white shadow-lg shadow-indigo-500/25'
              }`}
            >
              {saved ? <CheckCircle2 className="w-4 h-4" /> : <Shield className="w-4 h-4" />}
              {saved ? 'Saved!' : 'Save Changes'}
            </motion.button>
          </header>

          {/* Summary card */}
          <div className="glass-panel rounded-2xl p-5 flex items-center gap-4">
            <div className="w-12 h-12 rounded-xl bg-[var(--color-primary)]/10 flex items-center justify-center shrink-0">
              <Lock className="w-6 h-6 text-[var(--color-primary)]" />
            </div>
            <div className="flex-1">
              <p className="text-slate-900 font-semibold text-lg">
                {enabledCount} of {POLICIES.length} policies active
              </p>
              <p className="text-slate-600 text-sm">These rules guide the AI agents during threat analysis.</p>
            </div>
            <div className="hidden sm:flex items-end gap-1 h-8">
              {POLICIES.map(p => (
                <motion.div
                  key={p.id}
                  animate={{ height: enabled[p.id] ? 32 : 12, opacity: enabled[p.id] ? 1 : 0.3 }}
                  className="w-2 rounded-full bg-[var(--color-primary)]"
                  style={{ height: enabled[p.id] ? 32 : 12 }}
                />
              ))}
            </div>
          </div>

          {/* Info note */}
          <div className="flex items-start gap-3 p-4 rounded-xl bg-indigo-500/5 border border-indigo-500/20 text-sm text-slate-600">
            <Info className="w-4 h-4 text-indigo-500 shrink-0 mt-0.5" />
            <p>
              Policy settings are stored locally on your device and inform the AI analysis prompt context.
              Enterprise deployments support server-side enforcement with audit logging.
            </p>
          </div>

          {/* Policy cards */}
          <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
            {POLICIES.map((policy, i) => {
              const sev = SEVERITY_CONFIG[policy.severity];
              const isEnabled = enabled[policy.id] ?? policy.enabledByDefault;
              return (
                <motion.div
                  key={policy.id}
                  initial={{ opacity: 0, y: 15 }}
                  animate={{ opacity: 1, y: 0 }}
                  transition={{ delay: i * 0.06 }}
                  className={`glass-panel rounded-2xl p-5 border transition-all ${
                    isEnabled
                      ? 'border-[var(--color-border)]'
                      : 'border-[var(--color-border)] opacity-55'
                  }`}
                >
                  <div className="flex items-start gap-3">
                    <div className={`w-10 h-10 rounded-xl ${sev.bg} ${sev.color} flex items-center justify-center shrink-0`}>
                      {policy.icon}
                    </div>
                    <div className="flex-1 min-w-0">
                      <div className="flex items-center gap-2 flex-wrap mb-1">
                        <h3 className="text-sm font-semibold text-slate-900">{policy.title}</h3>
                        <span className={`text-xs px-2 py-0.5 rounded-full border ${sev.bg} ${sev.color} ${sev.border}`}>
                          {sev.label}
                        </span>
                        <span className="text-xs px-2 py-0.5 rounded-full bg-white/5 text-slate-400 border border-[var(--color-border)]">
                          {policy.tag}
                        </span>
                      </div>
                      <p className="text-xs text-slate-600 leading-relaxed">{policy.description}</p>
                    </div>

                    {/* Toggle switch */}
                    <button
                      onClick={() => toggle(policy.id)}
                      aria-label={`Toggle ${policy.title}`}
                      className={`relative shrink-0 w-11 h-6 rounded-full transition-colors ${
                        isEnabled ? 'bg-[var(--color-primary)]' : 'bg-white/10'
                      }`}
                    >
                      <motion.div
                        animate={{ x: isEnabled ? 20 : 2 }}
                        transition={{ type: 'spring', stiffness: 500, damping: 30 }}
                        className="absolute top-1 w-4 h-4 rounded-full bg-white shadow-sm"
                      />
                    </button>
                  </div>
                </motion.div>
              );
            })}
          </div>

        </div>
      </div>

      {/* Background glows */}
      <div className="absolute top-[-10%] left-[-10%] w-[40%] h-[40%] rounded-full bg-[var(--color-primary)]/5 blur-[120px] pointer-events-none" />
      <div className="absolute bottom-[-10%] right-[-10%] w-[40%] h-[40%] rounded-full bg-[var(--color-accent)]/5 blur-[120px] pointer-events-none" />
    </main>
  );
}
