import { Star } from 'lucide-react';

function formatTime(isoTime) {
  const date = new Date(isoTime);
  if (Number.isNaN(date.getTime())) {
    return '';
  }

  return date.toLocaleTimeString([], {
    hour: '2-digit',
    minute: '2-digit',
  });
}

export default function EmailCard({ email }) {
  return (
    <article className="group grid grid-cols-[auto_auto_minmax(140px,1fr)_minmax(0,2.6fr)_auto] items-center gap-3 px-3 py-2 border-b border-slate-200 bg-white hover:bg-slate-50 transition-colors text-sm">
      <input
        type="checkbox"
        aria-label={`Select email from ${email.from}`}
        className="h-4 w-4 rounded border-slate-300 text-blue-600 focus:ring-blue-500"
      />

      <button
        type="button"
        aria-label="Star email"
        className="text-slate-300 hover:text-amber-500 transition-colors"
      >
        <Star className="w-4 h-4" />
      </button>

      <p className="font-semibold text-slate-800 truncate pr-2">{email.from}</p>

      <p className="min-w-0 truncate text-slate-700">
        <span className="font-semibold text-slate-900">{email.subject}</span>
        <span className="text-slate-400 px-1">-</span>
        <span className="text-slate-500">{email.snippet}</span>
      </p>

      <time className="text-xs font-medium text-slate-500 whitespace-nowrap pl-2">
        {formatTime(email.time)}
      </time>
    </article>
  );
}
