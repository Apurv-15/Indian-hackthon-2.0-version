import { Star, ShieldAlert, ShieldCheck, AlertTriangle } from 'lucide-react';

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

export default function EmailCard({ email, onSelect }) {
  const risk = email.analysis?.riskLevel || 'Safe';
  
  const getRiskIcon = (level) => {
    switch (level) {
      case 'Safe': return <ShieldCheck className="w-4 h-4 text-emerald-500" />;
      case 'Low': return <ShieldCheck className="w-4 h-4 text-blue-500" />;
      case 'Medium': return <AlertTriangle className="w-4 h-4 text-amber-500" />;
      case 'High':
      case 'Critical': return <ShieldAlert className="w-4 h-4 text-red-500" />;
      default: return null;
    }
  };

  const getRiskColor = (level) => {
    switch (level) {
      case 'Safe': return 'bg-emerald-50 text-emerald-700 border-emerald-100';
      case 'Low': return 'bg-blue-50 text-blue-700 border-blue-100';
      case 'Medium': return 'bg-amber-50 text-amber-700 border-amber-100';
      case 'High':
      case 'Critical': return 'bg-red-50 text-red-700 border-red-100';
      default: return 'bg-slate-50 text-slate-700 border-slate-100';
    }
  };

  return (
    <article 
      onClick={() => onSelect(email)}
      className="group grid grid-cols-[auto_auto_minmax(140px,1.2fr)_minmax(0,2.6fr)_auto_auto] items-center gap-3 px-4 py-3 border-b border-slate-200 bg-white hover:bg-slate-50 transition-all cursor-pointer text-sm"
    >
      <input
        type="checkbox"
        onClick={(e) => e.stopPropagation()}
        aria-label={`Select email from ${email.from}`}
        className="h-4 w-4 rounded border-slate-300 text-blue-600 focus:ring-blue-500"
      />

      <button
        type="button"
        onClick={(e) => e.stopPropagation()}
        aria-label="Star email"
        className="text-slate-300 hover:text-amber-500 transition-colors"
      >
        <Star className="w-4 h-4" />
      </button>

      <p className="font-semibold text-slate-800 truncate pr-2">{email.from}</p>

      <p className="min-w-0 flex flex-col gap-1">
        <span className="truncate text-slate-700">
          <span className="font-semibold text-slate-900">{email.subject}</span>
          <span className="text-slate-400 px-1">-</span>
          <span className="text-slate-500">{email.snippet}</span>
        </span>
        {email.analysis?.indicators?.length > 0 && (
          <span className="flex gap-2 overflow-hidden items-center mt-1">
            {email.analysis.indicators.slice(0, 2).map((indicator, idx) => (
              <span key={idx} className="text-[9px] font-bold text-slate-400 bg-slate-100 px-1.5 py-0.5 rounded border border-slate-200 uppercase tracking-tighter truncate max-w-[150px]">
                {indicator}
              </span>
            ))}
            {email.analysis.indicators.length > 2 && (
              <span className="text-[9px] font-bold text-slate-300">
                +{email.analysis.indicators.length - 2} more signals
              </span>
            )}
            <span className="text-[9px] text-slate-400 italic font-medium ml-1 truncate">
              {email.analysis.explanation}
            </span>
          </span>
        )}
      </p>

      <div className={`flex items-center gap-1.5 px-2 py-0.5 rounded-full border text-[10px] font-bold uppercase tracking-wider ${getRiskColor(risk)}`}>
        {getRiskIcon(risk)}
        {risk}
      </div>

      <time className="text-xs font-medium text-slate-500 whitespace-nowrap pl-2">
        {formatTime(email.time)}
      </time>
    </article>
  );
}
