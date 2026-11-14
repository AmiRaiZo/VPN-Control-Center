import React from 'react'
import { Area, AreaChart, CartesianGrid, ResponsiveContainer, Tooltip, XAxis, YAxis } from 'recharts'

export default function BandwidthChart({ data, gridColor, textColor, tooltipBackground }) {
  return (
    <ResponsiveContainer width="100%" height={300}>
      <AreaChart data={data} margin={{ top: 8, right: 8, left: -18, bottom: 0 }}>
        <defs>
          <linearGradient id="rxFill" x1="0" y1="0" x2="0" y2="1"><stop offset="0%" stopColor="#ff6c00" stopOpacity=".42"/><stop offset="100%" stopColor="#ff6c00" stopOpacity="0"/></linearGradient>
          <linearGradient id="txFill" x1="0" y1="0" x2="0" y2="1"><stop offset="0%" stopColor="#38bdf8" stopOpacity=".18"/><stop offset="100%" stopColor="#38bdf8" stopOpacity="0"/></linearGradient>
        </defs>
        <CartesianGrid stroke={gridColor} strokeDasharray="3 3" vertical />
        <XAxis dataKey="time" stroke={textColor} tickLine={false} axisLine={false} fontSize={9} minTickGap={28}/>
        <YAxis stroke={textColor} tickLine={false} axisLine={false} fontSize={9} tickFormatter={value => `${value}`} />
        <Tooltip
          contentStyle={{ background: tooltipBackground, border: `1px solid ${gridColor}`, borderRadius: 10, fontSize: 11, boxShadow: '0 18px 40px rgba(0,0,0,.24)' }}
          labelStyle={{ color: textColor }}
          formatter={(value, name) => [`${Number(value).toFixed(2)} Mbps`, name.toUpperCase()]}
        />
        <Area type="monotone" dataKey="rx" stroke="#ff6c00" strokeWidth={2.5} fill="url(#rxFill)" activeDot={{ r: 4, fill: '#ff6c00', stroke: '#fff', strokeWidth: 2 }} isAnimationActive={false} />
        <Area type="monotone" dataKey="tx" stroke="#38bdf8" strokeWidth={2} fill="url(#txFill)" activeDot={{ r: 3 }} isAnimationActive={false} />
      </AreaChart>
    </ResponsiveContainer>
  )
}
