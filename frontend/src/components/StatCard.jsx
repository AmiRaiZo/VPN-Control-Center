import React from 'react'

export default function StatCard({ label, value, unit, accent = 'text-signal', sub }) {
  return (
    <article className="app-card orange-line min-h-[118px] overflow-hidden p-4 sm:p-5">
      <div className="metric-label font-semibold">{label}</div>
      <div className="mt-3 flex items-baseline gap-1.5">
        <span className={`font-data text-2xl font-black tracking-tight sm:text-3xl ${accent}`}>{value}</span>
        {unit && <span className="text-xs font-medium text-muted">{unit}</span>}
      </div>
      {sub && <div className="mt-2 text-[11px] leading-5 text-muted">{sub}</div>}
    </article>
  )
}
