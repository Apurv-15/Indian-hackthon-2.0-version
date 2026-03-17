"use client";

import Link from 'next/link';
import { usePathname } from 'next/navigation';
import { Shield, Search, Activity, FileText, Lock, LogOut, Mail } from 'lucide-react';

const navItems = [
  { href: '/scanner',   label: 'Scanner',   icon: Search },
  { href: '/dashboard', label: 'Dashboard', icon: Activity },
  { href: '/emails',    label: 'Emails',    icon: Mail },
  { href: '/reports',   label: 'Reports',   icon: FileText },
  { href: '/policies',  label: 'Policies',  icon: Lock },
];

export default function Sidebar() {
  const pathname = usePathname();

  return (
    <aside className="w-[260px] h-full bg-[var(--color-sidebar)] rounded-[2.5rem] flex flex-col shadow-2xl overflow-hidden shrink-0 border border-white/5 z-20">
      {/* Logo Section */}
      <div className="p-8 border-b border-white/5 flex items-center gap-4">
        <div className="w-10 h-10 rounded-2xl bg-white flex items-center justify-center shadow-lg">
          <Shield className="w-6 h-6 text-black" />
        </div>
        <div>
          <h1 className="text-lg font-bold text-white tracking-wide">AegisAI</h1>
          <p className="text-[11px] text-zinc-400 capitalize">Threat Portal</p>
        </div>
      </div>

      {/* Navigation Section */}
      <nav className="flex-1 px-4 py-8 space-y-2">
        {navItems.map(({ href, label, icon: Icon }) => {
          const isActive = pathname === href || pathname.startsWith(`${href}/`);
          return (
            <Link
              key={href}
              href={href}
              className={`flex items-center gap-4 px-5 py-3.5 rounded-2xl font-medium transition-all group ${
                isActive
                  ? 'bg-white/10 text-white shadow-sm'
                  : 'text-zinc-500 hover:text-zinc-300 hover:bg-white/5'
              }`}
            >
              <Icon className={`w-5 h-5 transition-colors ${isActive ? 'text-white' : 'group-hover:text-zinc-300'}`} />
              <span className="text-sm tracking-wide">{label}</span>
            </Link>
          );
        })}
      </nav>

      {/* User Profile / Footer Section */}
      <div className="p-4 mt-auto mb-4 space-y-2">
        <div className="flex items-center gap-3 px-5 py-4 bg-white/5 rounded-2xl border border-white/5">
          <div className="w-10 h-10 rounded-full bg-slate-800 flex items-center justify-center text-white font-bold text-sm border border-white/10 shrink-0">
            JD
          </div>
          <div className="flex flex-col min-w-0">
            <span className="text-sm font-semibold text-white truncate">Jacob Jones</span>
            <span className="text-[10px] text-zinc-500 truncate">jacob@aegisai.com</span>
          </div>
        </div>
        
        <button className="w-full flex items-center gap-3 px-5 py-3 text-zinc-500 hover:text-white transition-colors group">
          <LogOut className="w-5 h-5 group-hover:translate-x-0.5 transition-transform" />
          <span className="text-sm font-medium">Safe Exit</span>
        </button>
      </div>
    </aside>
  );
}
