export default function EmailCard({ email }) {
  return (
    <article className="rounded-[2.5rem] border border-white/50 bg-white p-6 shadow-[0_8px_30px_rgb(0,0,0,0.04)] transition hover:shadow-[0_12px_40px_rgb(0,0,0,0.06)] flex flex-col h-full">
      <p className="text-xs uppercase tracking-wider text-slate-400 font-bold mb-1">Sender</p>
      <p className="text-sm font-semibold text-slate-800 break-all">{email.from}</p>

      <p className="mt-4 text-xs uppercase tracking-wide text-slate-500 font-semibold">Subject</p>
      <p className="mt-1 text-base font-bold text-slate-800">{email.subject}</p>

      <p className="mt-4 text-xs uppercase tracking-wide text-slate-500 font-semibold">Preview</p>
      <p className="mt-1 text-sm leading-relaxed text-slate-600 line-clamp-3">{email.snippet}</p>

      <div className="mt-5 border-t border-slate-100 pt-4 relative">
        <p className="text-[10px] uppercase tracking-wide text-slate-400 font-semibold">Time received</p>
        <p className="mt-1 text-xs text-slate-500 font-medium">
          {new Date(email.time).toLocaleString()}
        </p>
      </div>
    </article>
  );
}
