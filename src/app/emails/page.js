'use client';

import { useCallback, useEffect, useState } from 'react';
import EmailCard from '../../components/EmailCard';

export default function EmailsPage() {
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
    <main className="flex-1 h-full overflow-y-auto w-full p-2 md:p-6 z-0">
      <section className="mx-auto max-w-7xl space-y-6">

        <header className="flex items-center justify-between py-1 px-2">
          <h1 className="text-2xl md:text-3xl font-medium text-slate-800 tracking-tight">
            Inbox
          </h1>
          <p className="text-sm text-slate-500 font-medium">
            {emails.length} conversations
          </p>
        </header>

        {loading && (
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

        {!loading && !error && emails.length > 0 && (
          <section className="rounded-2xl border border-slate-200 bg-white shadow-[0_8px_30px_rgb(0,0,0,0.04)] overflow-hidden pb-8">
            <div className="px-4 py-3 border-b border-slate-200 bg-slate-50 text-xs uppercase tracking-wide text-slate-500 font-semibold">
              Unread
            </div>

            <div className="divide-y divide-slate-100">
              {emails.map((email, index) => (
                <EmailCard
                  key={`${email.time}-${index}`}
                  email={email}
                />
              ))}
            </div>
          </section>
        )}
      </section>
    </main>
  );
}
