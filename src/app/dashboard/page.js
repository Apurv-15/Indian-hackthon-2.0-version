'use client';

import { useCallback, useEffect, useState } from 'react';
import EmailCard from '../../components/EmailCard';

export default function DashboardPage() {
  const [emails, setEmails] = useState([]);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState('');

  const fetchEmails = useCallback(async () => {
    try {
      const res = await fetch('/api/emails', { cache: 'no-store' });
      if (!res.ok) {
        const data = await res.json();
        throw new Error(data.error || 'Failed to fetch emails');
      }
      const data = await res.json();
      setEmails(Array.isArray(data) ? data : []);
      setError('');
    } catch (err) {
      setError(err.message || 'Could not load emails');
    } finally {
      setLoading(false);
    }
  }, []);

  useEffect(() => {
    fetchEmails();
    const timer = setInterval(fetchEmails, 10000);
    return () => clearInterval(timer);
  }, [fetchEmails]);

  return (
    <main className="flex-1 h-full overflow-y-auto bg-gradient-to-b from-slate-950 via-slate-900 to-slate-950 px-4 py-8 md:px-8">
      <section className="mx-auto max-w-6xl">
        <header className="mb-8 rounded-2xl border border-slate-700/70 bg-slate-900/60 p-6 shadow-xl shadow-black/20">
          <h1 className="text-3xl font-bold text-white">Incoming Threat Emails</h1>
          <p className="mt-2 text-sm text-slate-300">
            Monitoring Gmail inbox in near real-time. Refresh interval: 10 seconds.
          </p>
        </header>

        {loading && (
          <div className="rounded-2xl border border-slate-700/70 bg-slate-900/60 p-6 text-slate-300">
            Loading emails...
          </div>
        )}

        {error && !loading && (
          <div className="mb-6 rounded-2xl border border-red-500/40 bg-red-500/10 p-4 text-sm text-red-300">
            {error}
          </div>
        )}

        {!loading && !error && emails.length === 0 && (
          <div className="rounded-2xl border border-slate-700/70 bg-slate-900/60 p-6 text-slate-300">
            No emails found in the inbox.
          </div>
        )}

        <div className="grid grid-cols-1 gap-4 md:grid-cols-2 xl:grid-cols-3">
          {emails.map((email, index) => (
            <EmailCard
              key={`${email.time}-${index}`}
              email={email}
            />
          ))}
        </div>
      </section>
    </main>
  );
}
