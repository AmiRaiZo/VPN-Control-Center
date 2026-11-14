# گزارش بازبینی و اصلاح VPN Panel 2.3.242

تاریخ بازبینی: 2026-07-28

## دامنه

- ۱۶۹۹ فایل در بستهٔ اولیه، حدود ۴۷ مگابایت
- FastAPI/MySQL، React/Vite، نصب و آپدیت Ubuntu
- ۶۴ اسکریپت shell و ۱۲۷ فایل تست Python
- مدیریت کاربران/ادمین‌ها، لایسنس، Telegram، Nodeها، backup/restore و
  پروتکل‌های L2TP، PPTP، OpenVPN، SSTP، IKEv2، OpenConnect، VMess و VLESS

## مشکلات پیدا و اصلاح‌شده

1. **بحرانی — API key واقعی لایسنس داخل ZIP بود.** کلید از `install.sh` و
   `.env.example` حذف و دریافت امن از environment اجباری شد. چون کلید قبلاً
   منتشر شده، باید در License Console لغو و کلید جدید ساخته شود.
2. **بحرانی — نصب unattended رمز `admin` داشت.** در نبود `ADMIN_PASS` اکنون
   رمز تصادفی قوی ساخته و فقط در پایان نصب یک‌بار نمایش داده می‌شود.
3. **بالا — اسرار updater در command line بودند.** URL/API key/license key
   از آرگومان‌های `systemd-run` حذف و به فایل موقت 0600 زیر `/run` منتقل شدند.
4. **بالا — ۳۲ رکورد آسیب‌پذیری در dependencyهای Python.** cryptography،
   FastAPI/Starlette، multipart، dotenv، requests و Paramiko ارتقا یافتند و
   `python-jose`/`ecdsa` با PyJWT جایگزین شد.
5. **بالا — ۵ آسیب‌پذیری npm و lockfile غیرقابل‌استفاده خارج از محیط build.**
   Vite، Router و Recharts ارتقا یافتند و lockfile فقط با registry عمومی npm
   بازسازی شد.
6. **بالا — سورس فرانت‌اند قابل build نبود.** `Protocols.jsx` هم import و هم
   تعریف محلی `Icon` داشت؛ تعارض رفع شد و build تولیدی Vite با ۷۰۰ ماژول کامل شد.
7. **بالا — fallback ساخت فرانت‌اند همیشه به مسیر اشتباه می‌رفت.** خروجی Vite
   از `dist-build` به `dist` همگام شد تا مسیر recovery نصب واقعاً کار کند.
8. **متوسط — crash در وضعیت ربات تلگرام.** تابع `can_view_all_users` در scope
   نبود و برای بعضی ادمین‌ها `NameError` می‌داد؛ import اصلاح شد.
9. **متوسط — ربات کنترل بدون chat ID قابل فعال‌شدن بود.** اعتبارسنجی chat ID
   اضافه شد.
10. **متوسط — نسخه‌های API/UI/cache و checksumها متفاوت بودند.** همه روی
    2.3.242/23242 همگام و هر دو manifest فرانت‌اند و ریشه بازسازی شدند.
11. **متوسط — صفحهٔ خالی در تعویض route و دانلود بی‌دلیل افکت ورود در موبایل.**
    fallback قابل‌مشاهده، lazy Login و lazy animationهای دسکتاپ اضافه شد.
12. **متوسط — آیکن refresh بریده می‌شد.** path داخل viewBox متعادل شد.
13. **متوسط — SHA-1 برای tagهای rule Xray.** به SHA-256 تغییر کرد.
14. **متوسط — تست‌ها `sys.modules` واقعی را با stub جایگزین می‌کردند.**
    آلودگی collection رفع و تست‌های asset نسبت به نسخهٔ فعال پویا شدند.
15. **پایین — کد مرده و importهای بلااستفاده.** خطاهای Ruff نوع F/E9 در
    کد production پاک شدند.

## اعتبارسنجی انجام‌شده

- `python compileall`: موفق
- Ruff روی کد production (`F` و `E9`): بدون خطا
- syntax تمام اسکریپت‌های shell: موفق
- build تولیدی Vite 8: موفق
- syntax تمام chunkهای JavaScript فعال: موفق
- checksum و active asset graph فرانت‌اند: موفق (۱۰۰۳ فایل)
- تست‌های نسخه‌های 2.32xx و اصلاحات 2.3.242: ۱۰۶ تست موفق
- تست‌های بالا به‌همراه مجموعهٔ کامل Xray: ۱۵۱ تست موفق
- اسکن Bandit: تنها هشدار High مربوط به کاراکتر راست‌به‌چپ فارسی در متن
  Telegram است و مسیر اجرایی/تزریق کد نیست.

## موارد باز و محدودیت‌ها

- `npm audit` هنوز دو هشدار High برای React Router 7.18.1 در **RSC mode**
  گزارش می‌کند. این پروژه SPA است و RSC/SSR/Server Actions ندارد؛ نسخهٔ
  اصلاح‌شده‌ای که هم‌زمان همهٔ advisoryها را حل کند در زمان بازبینی منتشر
  نشده بود. پس از انتشار نسخهٔ upstream، Router دوباره ارتقا داده شود.
- تعداد زیادی تست تاریخی `v231xx` شمارهٔ asset یا رفتار همان نسخهٔ قدیمی را
  hard-code کرده‌اند و با نسخه‌های جدیدتر تناقض دارند. تست‌های فعال/current
  سبز هستند؛ اجرای کل پوشه ۴۸۸ موفق، ۸۹ ناموفق و ۱ skipped داشت. مجموعهٔ
  legacy باید به‌مرور به fixtureهای version-agnostic منتقل یا archive شود.
- هشدارهای `datetime.utcnow()` برای سازگاری آیندهٔ Python باقی مانده‌اند؛
  Python 3.10/3.12 فعلی را متوقف نمی‌کنند، ولی مهاجرت سراسری به datetimeهای
  timezone-aware برای نسخهٔ بعدی توصیه می‌شود.
- سرویس‌های واقعی VPN، systemd، Nginx، MySQL، firewall، SSH Node و اتصال
  Telegram در این محیط container قابل اجرای end-to-end نبودند. پیش از rollout
  عمومی، یک نصب staging روی Ubuntu و smoke test هر پروتکل لازم است.
- proxy محیط بازبینی هنگام دانلود دوبارهٔ wheelهای Python قطع شد؛ نسخه‌های
  امن در `requirements.txt` پین و ناسازگاری metadata برطرف شد، اما ساخت venv
  کاملاً تازه با همین نسخه‌ها باید در smoke test staging تکرار شود.

## اقدامات لازم برای مالک پروژه

1. API key لایسنسِ قبلی را فوراً revoke/rotate کن.
2. ZIP را ابتدا روی سرور staging نصب/آپدیت کن و اتصال هر پروتکل را تست کن.
3. advisoryهای React Router را پیگیری و در اولین نسخهٔ اصلاح‌شده ارتقا بده.
