import React, { useMemo } from 'react'
import { isoToJalaali, jalaaliToIso, jalaaliMonthLength, todayJalaali, toFaDigits, JALALI_MONTHS } from '../jalali'

const selectClass =
  'field min-w-0 flex-1 !px-2 font-data text-center'

/**
 * انتخاب‌گر تاریخ شمسی با سه select (روز/ماه/سال). مقدار ورودی/خروجی همیشه
 * رشته‌ی میلادی "YYYY-MM-DD" است (دقیقاً مثل input type=date) تا نیازی به
 * تغییر جایی که این مقدار ذخیره/ارسال می‌شود نباشد؛ فقط نمایش شمسی است.
 */
export default function JalaliDatePicker({ value, onChange, className = '', allowEmpty = true, emptyLabel = 'بدون تاریخ (نامحدود)' }) {
  const hasValue = !!value
  const j = useMemo(() => isoToJalaali(value) || todayJalaali(), [value])
  const currentJy = todayJalaali().jy

  const years = useMemo(() => {
    const arr = []
    for (let y = currentJy - 1; y <= currentJy + 6; y++) arr.push(y)
    return arr
  }, [currentJy])

  const dayCount = useMemo(() => jalaaliMonthLength(j.jy, j.jm), [j.jy, j.jm])
  const days = useMemo(() => Array.from({ length: dayCount }, (_, i) => i + 1), [dayCount])

  const update = (part) => {
    const next = { ...j, ...part }
    const maxDay = jalaaliMonthLength(next.jy, next.jm)
    if (next.jd > maxDay) next.jd = maxDay
    onChange(jalaaliToIso(next.jy, next.jm, next.jd))
  }

  return (
    <div className={className}>
      {allowEmpty && (
        <label className="mb-2.5 flex cursor-pointer items-center gap-2 rounded-lg border border-border bg-surface2/60 px-3 py-2.5 text-xs text-muted transition hover:border-signal/35 hover:text-ink">
          <input
            type="checkbox"
            checked={!hasValue}
            onChange={(e) => (e.target.checked ? onChange(null) : update({}))}
            className="h-4 w-4 rounded border-border"
          />
          {emptyLabel}
        </label>
      )}
      {hasValue && (
        <div className="flex gap-2 rounded-xl border border-border bg-surface2/40 p-2" dir="ltr">
          <select aria-label="Year" className={selectClass} value={j.jy} onChange={(e) => update({ jy: Number(e.target.value) })}>
            {years.map((y) => (
              <option key={y} value={y}>{toFaDigits(y)}</option>
            ))}
          </select>
          <select aria-label="Month" className={selectClass} value={j.jm} onChange={(e) => update({ jm: Number(e.target.value) })}>
            {JALALI_MONTHS.map((name, idx) => (
              <option key={idx} value={idx + 1}>{name}</option>
            ))}
          </select>
          <select aria-label="Day" className={selectClass} value={j.jd} onChange={(e) => update({ jd: Number(e.target.value) })}>
            {days.map((d) => (
              <option key={d} value={d}>{toFaDigits(d)}</option>
            ))}
          </select>
        </div>
      )}
    </div>
  )
}
