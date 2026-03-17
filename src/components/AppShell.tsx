"use client";

import { usePathname } from 'next/navigation';
import Sidebar from './Sidebar';

export default function AppShell({ children }: { children: React.ReactNode }) {
  const pathname = usePathname();

  if (pathname === '/') {
    return (
      <div className="min-h-screen bg-[var(--color-bg-base)] text-slate-900">
        {children}
      </div>
    );
  }

  return (
    <div className="flex h-screen overflow-hidden bg-[var(--color-bg-base)] text-slate-900 p-4 md:p-5 gap-5">
      <Sidebar />
      <main className="flex-1 h-full overflow-hidden relative z-10 transition-all rounded-[2.5rem] bg-transparent">
        {children}
      </main>
    </div>
  );
}
