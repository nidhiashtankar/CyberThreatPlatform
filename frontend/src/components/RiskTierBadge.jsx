import React from 'react';

export default function RiskTierBadge({ tier, score }) {
  const t = (tier || 'Low').toLowerCase();

  const styles = {
    critical: 'bg-red-100 text-red-800 border-red-300 font-bold',
    high: 'bg-orange-100 text-orange-800 border-orange-300 font-semibold',
    medium: 'bg-amber-100 text-amber-800 border-amber-300 font-medium',
    low: 'bg-emerald-100 text-emerald-800 border-emerald-300 font-medium',
  };

  const currentStyle = styles[t] || styles.low;

  return (
    <span
      className={`inline-flex items-center gap-1.5 px-3 py-1 rounded-md text-xs border ${currentStyle}`}
    >
      <span>{tier} Risk</span>
      {score !== undefined && (
        <span className="font-mono bg-white/70 px-1.5 py-0.2 rounded text-[11px] shadow-2xs">
          {score}
        </span>
      )}
    </span>
  );
}
