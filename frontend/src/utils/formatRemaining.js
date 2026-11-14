// نمایش زمان باقی‌مانده‌ی لایسنس با حذف واحدهای صفرِ ابتدایی:
// - اگر روز > 0: روز و ساعت و دقیقه هر سه نشان داده می‌شوند
//   (مثلاً "12 روز و 3 ساعت و 23 دقیقه باقی‌مانده").
// - اگر روز == 0 ولی ساعت > 0: فقط ساعت و دقیقه نشان داده می‌شوند
//   ("12 ساعت و 23 دقیقه باقی‌مانده")، دیگر "0 روز" نوشته نمی‌شود.
// - اگر روز == 0 و ساعت == 0: فقط دقیقه نشان داده می‌شود
//   ("23 دقیقه باقی‌مانده")، دیگر "0 روز" و "0 ساعت" نوشته نمی‌شوند.
// یعنی واحدهای صفرِ سمت چپ (بزرگ‌تر) حذف می‌شوند، ولی از اولین واحد
// غیرصفر به بعد، همه‌ی واحدهای کوچک‌تر (حتی اگر صفر باشند) نشان داده می‌شوند
// (مثلاً "5 روز و 0 ساعت و 12 دقیقه").
export function formatRemainingParts(days, hours, minutes) {
  const hasDays = typeof days === 'number'
  const hasHours = typeof hours === 'number'
  const hasMinutes = typeof minutes === 'number'

  if (hasDays && days > 0) {
    const parts = [{ value: days, unit: 'days' }]
    if (hasHours) parts.push({ value: hours, unit: 'hours' })
    if (hasMinutes) parts.push({ value: minutes, unit: 'minutes' })
    return parts
  }

  if (hasHours && hours > 0) {
    const parts = [{ value: hours, unit: 'hours' }]
    if (hasMinutes) parts.push({ value: minutes, unit: 'minutes' })
    return parts
  }

  if (hasMinutes) return [{ value: minutes, unit: 'minutes' }]

  if (hasHours) return [{ value: hours, unit: 'hours' }]

  if (hasDays) return [{ value: days, unit: 'days' }]

  return []
}

const UNIT_KEY = { days: 'daysShort', hours: 'hoursShort', minutes: 'minutesShort' }

// t: تابع ترجمه‌ی همان i18n که کامپوننت‌ها استفاده می‌کنند
export function formatRemainingText(days, hours, minutes, t) {
  const and = t('remainingAnd')
  return formatRemainingParts(days, hours, minutes)
    .map(({ value, unit }) => `${value} ${t(UNIT_KEY[unit])}`)
    .join(` ${and} `)
}
