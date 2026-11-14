const LOWER = 'abcdefghijklmnopqrstuvwxyz'
const UPPER = 'ABCDEFGHIJKLMNOPQRSTUVWXYZ'
const DIGITS = '0123456789'
// توجه: کاراکتر # عمداً حذف شده — در فایل /etc/ppp/chap-secrets (که رمز
// L2TP/PPTP از آن خوانده می‌شود) کاراکتر # شروع‌کننده‌ی کامنت است و هرچه
// بعد از آن در همان خط بیاید نادیده گرفته می‌شود و رمز آن کاربر خراب می‌شود.
const SYMBOLS = '!@$%^&*_-'

function pick(chars) {
  return chars[Math.floor(Math.random() * chars.length)]
}

function shuffle(str) {
  const arr = str.split('')
  for (let i = arr.length - 1; i > 0; i--) {
    const j = Math.floor(Math.random() * (i + 1))
    ;[arr[i], arr[j]] = [arr[j], arr[i]]
  }
  return arr.join('')
}

// یوزرنیم تصادفی: فقط انگلیسی (حروف بزرگ/کوچک + عدد)، مطابق قوانین بک‌اند
// (^[A-Za-z0-9_.-]+$) - همیشه با یک حرف شروع می‌شود.
export function generateRandomUsername(length = 8) {
  let out = pick(LOWER)
  const pool = LOWER + UPPER + DIGITS
  for (let i = 1; i < length; i++) out += pick(pool)
  return out
}

// پسورد تصادفی: حداقل یک حرف بزرگ، یک حرف کوچک، یک عدد و یک نماد؛ فقط انگلیسی.
export function generateRandomPassword(length = 12) {
  let out = pick(UPPER) + pick(LOWER) + pick(DIGITS) + pick(SYMBOLS)
  const pool = LOWER + UPPER + DIGITS + SYMBOLS
  for (let i = out.length; i < length; i++) out += pick(pool)
  return shuffle(out)
}
