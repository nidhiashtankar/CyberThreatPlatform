import React from 'react';

export default function SeverityBadge({ severity }) {
  const sev = (severity || 'low').toLowerCase();

  const styles = {
    critical: 'bg-red-50 text-red-700 border-red-200 ring-1 ring-red-400/30',
    high: 'bg-orange-50 text-orange-700 border-orange-200 ring-1 ring-orange-400/30',
    medium: 'bg-amber-50 text-amber-700 border-amber-200 ring-1 ring-amber-400/30',
    low: 'bg-blue-50 text-blue-700 border-blue-200 ring-1 ring-blue-400/30',
  };

  const currentStyle = styles[sev] || styles.low;

  return (
    <span
      className={`inline-flex items-center px-2.5 py-0.5 rounded-full text-xs font-semibold uppercase tracking-wider border ${currentStyle}`}
    >
      <span className={`w-1.5 h-1.5 rounded-full mr-1.5 ${
        sev === 'critical' ? 'bg-red-500' :
        sev === 'high' ? 'bg-orange-500' :
        sev === 'medium' ? 'bg-amber-500' : 'bg-blue-500'
      }`} />
      {severity}
    </span>
  );
}
