"use client";

import Link from 'next/link';
import { usePathname } from 'next/navigation';
import { Shield, Search, Activity, FileText, Lock } from 'lucide-react';

const navItems = [
  { href: '/',          label: 'Scanner',   icon: Search },
  { href: '/dashboard', label: 'Dashboard', icon: Activity },
  { href: '/reports',   label: 'Reports',   icon: FileText },
  { href: '/policies',  label: 'Policies',  icon: Lock },
];

export default function Sidebar() {
  const pathname = usePathname();

  return (
    <aside className="w-64 border-r border-[var(--color-border)] glass-panel flex-col hidden md:flex z-10 shrink-0">
      {/* Logo */}
      <div className="p-6 flex items-center gap-3 border-b border-[var(--color-border)]">
        <div className="w-10 h-10 rounded-xl bg-gradient-to-br from-[var(--color-primary)] to-indigo-800 flex items-center justify-center shadow-lg shadow-indigo-500/20">
          <Shield className="w-6 h-6 text-white" />
        </div>
        <h1 className="text-xl font-bold tracking-tight text-white">
          Aegis<span className="text-[var(--color-primary)]">AI</span>
        </h1>
      </div>

      {/* Nav */}
      <nav className="flex-1 p-4 space-y-1">
        {navItems.map(({ href, label, icon: Icon }) => {
          const isActive = pathname === href;
          return (
            <Link
              key={href}
              href={href}
              className={`flex items-center gap-3 px-4 py-3 rounded-lg font-medium transition-colors border ${
                isActive
                  ? 'bg-[var(--color-primary)]/10 text-[var(--color-primary)] border-[var(--color-primary)]/20'
                  : 'text-slate-400 hover:text-slate-200 hover:bg-white/5 border-transparent'
              }`}
            >
              <Icon className="w-5 h-5" />
              {label}
            </Link>
          );
        })}
      </nav>

      {/* Engine status */}
      <div className="p-4 border-t border-[var(--color-border)]">
        <div className="glass-panel rounded-lg p-4 text-sm">
          <div className="flex items-center gap-2 mb-2 text-slate-300">
            <Activity className="w-4 h-4 text-[var(--color-accent)]" />
            <span>Engine Status</span>
          </div>
          <div className="flex justify-between items-center">
            <span className="text-slate-400">Gemini 1.5 Pro</span>
            <span className="flex items-center gap-1.5 text-[var(--color-accent)] text-xs font-medium bg-[var(--color-accent)]/10 px-2 py-1 rounded-full">
              <span className="w-1.5 h-1.5 rounded-full bg-[var(--color-accent)] animate-pulse" />
              Online
            </span>
          </div>
        </div>
      </div>
    </aside>
  );
}
