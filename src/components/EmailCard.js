export default function EmailCard({ email }) {
  return (
    <article className="rounded-2xl border border-slate-700/70 bg-slate-900/60 p-5 shadow-lg shadow-black/20 transition hover:border-slate-500/80 hover:bg-slate-900/80">
      <p className="text-xs uppercase tracking-wide text-slate-400">Sender</p>
      <p className="mt-1 text-sm font-semibold text-slate-100 break-all">{email.from}</p>

      <p className="mt-4 text-xs uppercase tracking-wide text-slate-400">Subject</p>
      <p className="mt-1 text-base font-semibold text-white">{email.subject}</p>

      <p className="mt-4 text-xs uppercase tracking-wide text-slate-400">Preview</p>
      <p className="mt-1 text-sm leading-relaxed text-slate-300">{email.snippet}</p>

      <div className="mt-5 border-t border-slate-700/70 pt-3">
        <p className="text-xs uppercase tracking-wide text-slate-400">Time received</p>
        <p className="mt-1 text-sm text-slate-200">
          {new Date(email.time).toLocaleString()}
        </p>
      </div>
    </article>
  );
}
