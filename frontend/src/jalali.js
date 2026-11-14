import jalaali from 'jalaali-js'

const FA_DIGITS = ['۰', '۱', '۲', '۳', '۴', '۵', '۶', '۷', '۸', '۹']

export const JALALI_MONTHS = [
  'فروردین', 'اردیبهشت', 'خرداد', 'تیر', 'مرداد', 'شهریور',
  'مهر', 'آبان', 'آذر', 'دی', 'بهمن', 'اسفند',
]

export function toFaDigits(input) {
  return String(input).replace(/[0-9]/g, (d) => FA_DIGITS[d])
}

function pad2(n) {
  return String(n).padStart(2, '0')
}

/** "YYYY-MM-DD" (میلادی) -> {jy, jm, jd} */
export function isoToJalaali(isoDate) {
  if (!isoDate) return null
  const [gy, gm, gd] = isoDate.split('-').map(Number)
  if (!gy || !gm || !gd) return null
  return jalaali.toJalaali(gy, gm, gd)
}

/** {jy, jm, jd} -> "YYYY-MM-DD" (میلادی، برای ارسال به بک‌اند) */
export function jalaaliToIso(jy, jm, jd) {
  const { gy, gm, gd } = jalaali.toGregorian(Number(jy), Number(jm), Number(jd))
  return `${gy}-${pad2(gm)}-${pad2(gd)}`
}

/** "YYYY-MM-DD" میلادی -> رشته‌ی نمایشی شمسی مثل «۱۴۰۵/۰۵/۲۰» */
export function formatJalaliDate(isoDate) {
  const j = isoToJalaali(isoDate)
  if (!j) return ''
  return toFaDigits(`${j.jy}/${pad2(j.jm)}/${pad2(j.jd)}`)
}

/** "YYYY-MM-DD" میلادی -> رشته‌ی نمایشی شمسی با نام ماه، مثل «۲۰ مرداد ۱۴۰۵» */
export function formatJalaliDateLong(isoDate) {
  const j = isoToJalaali(isoDate)
  if (!j) return ''
  return `${toFaDigits(j.jd)} ${JALALI_MONTHS[j.jm - 1]} ${toFaDigits(j.jy)}`
}

export function todayJalaali() {
  const now = new Date()
  return jalaali.toJalaali(now.getFullYear(), now.getMonth() + 1, now.getDate())
}

export function jalaaliMonthLength(jy, jm) {
  return jalaali.jalaaliMonthLength(Number(jy), Number(jm))
}
