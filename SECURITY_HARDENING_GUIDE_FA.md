# راهنمای امن‌سازی و لایسنس‌محور کردن VPN Panel

این راهنما برای نسخه‌ی `2.3.192` نوشته شده است. هدف آن کم‌کردن ریسک سرقت کد، دورزدن لایسنس، افشای رمزها و دست‌کاری بکاپ یا بسته‌ی آپدیت است.

> هیچ نرم‌افزاری که روی سرور مشتری با دسترسی `root` اجرا شود «غیرقابل‌کپی یا غیرقابل‌کرک» نیست. مالک `root` در نهایت می‌تواند فایل، حافظه و ترافیک همان ماشین را بررسی کند. طراحی درست، هزینه‌ی مهندسی معکوس و دورزدن را زیاد می‌کند، کلیدهای اصلی را از بسته‌ی مشتری خارج نگه می‌دارد و امکان ابطال/ردیابی را فراهم می‌کند.

## ۱. اصلاحات امنیتی اعمال‌شده در 2.3.192

- توکن کامل Node Agent فقط برای سوپرادمین قابل دریافت یا تعویض است.
- PSK نود از پاسخ ادمین‌هایی که دسترسی L2TP/IPsec ندارند حذف می‌شود.
- کد کامل لایسنس فقط به سوپرادمین نمایش داده می‌شود.
- رمز SSH نودها با `DATA_ENCRYPTION_KEY` مستقل رمز می‌شود؛ کلید JWT دیگر کلید رمزگذاری داده نیست.
- اتصال SSH کلید میزبان را در اولین اتصال ثبت می‌کند و هر تغییر بعدی را رد می‌کند.
- بکاپ کامل با `AES-256-GCM` رمز و احراز اصالت می‌شود؛ پسوند جدید `.vpnbackup` است.
- واردکردن بکاپ محدودیت حجم فشرده و بازشده دارد و در برابر Gzip Bomb متوقف می‌شود.
- ورود، ثبت‌نام، بررسی لایسنس داخلی و فعال‌سازی لایسنس Rate Limit دارند.
- مصرف هم‌زمان یک لایسنس داخلی با Update اتمیک دیتابیس جلوگیری می‌شود.
- CORS پیش‌فرض same-origin است و `*` همراه credential پذیرفته نمی‌شود.
- خطای ناشناخته با شناسه‌ی Incident برمی‌گردد و متن Exception داخلی به مرورگر نشت نمی‌کند.
- اجرای Production بدون آدرس/کلید API سرور لایسنس Fail-Closed است.
- مقادیر `change-me` و کلیدهای کوتاه، Startup را متوقف می‌کنند.

## ۲. مدیریت Secretها

فایل زیر باید مالک `root:nogroup` و سطح دسترسی `0640` داشته باشد:

```bash
sudo chown root:nogroup /opt/vpn-panel/backend/.env
sudo chmod 0640 /opt/vpn-panel/backend/.env
```

چهار Secret مستقل نگه دار:

```dotenv
JWT_SECRET=<64 hex>
INTERNAL_API_TOKEN=<64 hex>
DATA_ENCRYPTION_KEY=<64 hex>
BACKUP_ENCRYPTION_KEY=<64 hex>
```

برای ساخت دستی:

```bash
openssl rand -hex 32
```

کار هر کلید:

- `JWT_SECRET`: امضای نشست‌های ادمین.
- `INTERNAL_API_TOKEN`: احراز هویت Hookهای محلی VPN.
- `DATA_ENCRYPTION_KEY`: رمز SSH و Secretهای ذخیره‌شده در دیتابیس.
- `BACKUP_ENCRYPTION_KEY`: رمزگشایی فایل‌های `.vpnbackup`.

یک کلید را برای چند کاربرد استفاده نکن. کلیدها را داخل Git، فایل ZIP، JavaScript، Docker image عمومی یا پیام تلگرام قرار نده.

### کلید بازیابی بکاپ

نصاب آن را در مسیر زیر با مجوز `0600` ذخیره می‌کند:

```text
/root/.vpn-panel/backup-recovery-key.txt
```

همین مقدار را در یک Password Manager یا حافظه‌ی آفلاین نگهداری کن. اگر کل سرور از بین برود و این کلید فقط روی همان سرور بوده باشد، بکاپ رمزگذاری‌شده قابل بازیابی نیست.

## ۳. تنظیم Production فقط با لایسنس

روی سرور مشتری:

```dotenv
LICENSE_SERVER_URL=https://license.example.com:9999
LICENSE_API_KEY=<panel-specific-api-key>
LICENSE_FAIL_CLOSED=true
LICENSE_ALLOW_UNLICENSED_DEVELOPMENT=false
```

در این وضعیت:

- نبودن تنظیمات سرور لایسنس باعث توقف Startup می‌شود.
- خطای بررسی محلی، پنل را باز نمی‌گذارد.
- بدون کد لایسنس معتبر، APIهای مدیریتی و سرویس‌های VPN قفل می‌شوند.
- فقط Health، Login و صفحه‌ی فعال‌سازی برای رفع قفل در دسترس می‌مانند.

حالت بدون لایسنس فقط برای توسعه‌ی محلی است:

```dotenv
LICENSE_ALLOW_UNLICENSED_DEVELOPMENT=true
```

این گزینه نباید در بسته یا سرور مشتری فعال شود.

## ۴. معماری پیشنهادی لایسنس امضاشده

برای مقاوم‌تر شدن در برابر جعل پاسخ سرور، از امضای نامتقارن استفاده کن:

1. روی License Server یک جفت کلید `Ed25519` بساز.
2. **Private Key فقط روی License Server** بماند.
3. فقط Public Key داخل پنل مشتری قرار بگیرد.
4. License Server یک Lease کوتاه‌عمر صادر کند، مثلاً:

```json
{
  "license_id": "LIC-...",
  "instance_id": "sha256:...",
  "features": ["vpn", "nodes", "backup"],
  "issued_at": 1784890000,
  "expires_at": 1784893600,
  "nonce": "random-challenge"
}
```

5. سرور لایسنس، JSON canonical را با Private Key امضا کند.
6. پنل با Public Key، امضا، `expires_at`، `instance_id` و `nonce` را بررسی کند.
7. Lease کوتاه باشد؛ مثلاً ۳۰ تا ۶۰ دقیقه. Grace آفلاین محدود و ثبت‌شده باشد.
8. لیست ابطال و `license_generation` داشته باش تا با Reset لایسنس، Leaseهای قدیمی معتبر نمانند.

مزیت: مهاجم با دیدن Public Key نمی‌تواند Lease معتبر جدید بسازد.

### شناسه‌ی نصب مناسب

فقط MAC Address یا CPU serial استفاده نکن؛ در VM ناپایدار است. ترکیب زیر مناسب‌تر است:

```text
SHA-256(
  /etc/machine-id
  + installation_uuid_generated_once
  + normalized_public_server_identity
)
```

`installation_uuid` را یک‌بار در `/var/lib/vpn-panel/instance-id` با مجوز `0600` بساز. برای انتقال رسمی سرور، Reset/Transfer لایسنس در License Console داشته باش.

## ۵. API Key ثابت را داخل همه‌ی ZIPها نگذار

بهتر است هر نصب یک API Key یا Bootstrap Token کوتاه‌عمر مخصوص خودش بگیرد:

1. مشتری کد لایسنس را وارد می‌کند.
2. پنل با یک Bootstrap Token یک‌بارمصرف ثبت می‌شود.
3. License Server برای همان `instance_id` یک API credential اختصاصی صادر می‌کند.
4. Credential با `DATA_ENCRYPTION_KEY` ذخیره می‌شود.
5. Bootstrap Token بلافاصله باطل می‌شود.

اگر یک API Key مشترک در همه‌ی بسته‌ها باشد، با افشای یک ZIP همه‌ی نصب‌ها آن کلید را خواهند داشت؛ حتی اگر خود لایسنس‌ها جدا باشند.

## ۶. سخت‌تر کردن سرقت کد

### منطق حساس را سمت سرور خودت نگه دار

موثرترین روش این است که منطق ارزشمند مثل صدور لایسنس، امضای Lease، سیاست Featureها، ابطال و اعتبارسنجی پرداخت فقط روی سرور خودت باشد. چیزی که به مشتری تحویل داده نشده، مستقیماً قابل کپی نیست.

### Backend را به باینری تبدیل کن

برای انتشار تجاری می‌توانی نسخه‌ی Production بک‌اند را با `Nuitka` یا بخش‌های حساس را با `Cython` کامپایل کنی. نمونه‌ی آزمایشی:

```bash
python -m pip install nuitka ordered-set zstandard
python -m nuitka \
  --standalone \
  --follow-imports \
  --python-flag=no_docstrings \
  --remove-output \
  --output-dir=build/nuitka \
  backend/app/main.py
```

FastAPI و importهای پویا نیاز به تنظیم Plugin/Include دارند؛ خروجی را قبل از انتشار روی Ubuntuهای هدف تست کن. کامپایل، کد را غیرقابل‌سرقت نمی‌کند؛ فقط مهندسی معکوس را سخت‌تر می‌کند.

### Frontend را Secret-free فرض کن

هر چیزی که در JavaScript مرورگر باشد قابل مشاهده است. در Frontend این موارد را قرار نده:

- API Secret
- Private signing key
- Backup key
- SSH credential
- منطق نهایی تأیید لایسنس

Minify/Obfuscate فقط سرعت خواندن را کم می‌کند و مرز امنیتی نیست.

## ۷. امضای بسته‌ی آپدیت

SHA-256 فقط خرابی را تشخیص می‌دهد؛ هرکس که بتواند ZIP و metadata را عوض کند می‌تواند SHA جدید هم بسازد. برای زنجیره‌ی انتشار:

1. در CI فایل ZIP نهایی را بساز.
2. SHA-256 آن را حساب کن.
3. متادیتای شامل hash، channel و timestamp را با Private Key انتشار امضا کن.
4. Public Key انتشار داخل updater باشد.
5. updater قبل از Extract، امضای metadata و سپس SHA فایل را بررسی کند.
6. کلید Private انتشار فقط در CI امن/HSM باشد.

هرگز دستور Shell یا URL آپدیت را فقط بر اساس پاسخ JSON امضانشده اجرا نکن.

## ۸. بکاپ امن

- بکاپ کامل شامل دیتابیس، PSK، PKI، گواهی‌ها، تنظیمات پنل و بکاپ نودهاست؛ بنابراین همیشه Secret محسوب می‌شود.
- تنها فایل `.vpnbackup` رمزگذاری‌شده را به تلگرام/فضای ابری بفرست.
- کلید رمزگشایی را کنار فایل بکاپ ذخیره نکن.
- حداقل ماهی یک Restore آزمایشی روی سرور ایزوله انجام بده.
- بعد از Restore، Token نودها، Sessionها و credentialهای حساس را Rotate کن.
- Legacy backup import را بعد از مهاجرت کامل خاموش کن:

```dotenv
ALLOW_LEGACY_UNENCRYPTED_BACKUP_IMPORT=false
```

## ۹. SSH نودها

حالت پیشنهادی:

```dotenv
SSH_HOST_KEY_POLICY=tofu
SSH_KNOWN_HOSTS_PATH=/var/lib/vpn-panel/ssh_known_hosts
```

در اولین اتصال، Fingerprint را جداگانه با کنسول ارائه‌دهنده‌ی سرور مقایسه کن. تغییر ناگهانی Host Key می‌تواند نشانه‌ی تعویض سرور یا MITM باشد و نباید خودکار پذیرفته شود.

## ۱۰. CORS و Reverse Proxy

برای پنلی که Frontend و API روی یک دامنه‌اند:

```dotenv
CORS_ALLOWED_ORIGINS=
```

برای Frontend جدا، فقط Origin دقیق:

```dotenv
CORS_ALLOWED_ORIGINS=https://panel.example.com
CORS_ALLOW_CREDENTIALS=true
```

از `*` با credential استفاده نکن. در Nginx نیز TLS، HSTS پس از اطمینان از HTTPS دائمی، محدودیت حجم Upload و Rate Limit لایه‌ی دوم تنظیم کن.

## ۱۱. Systemd Hardening پیشنهادی

بعد از تست سازگاری، به unit بک‌اند اضافه کن:

```ini
NoNewPrivileges=true
PrivateTmp=true
ProtectHome=true
ProtectKernelTunables=true
ProtectKernelModules=true
ProtectControlGroups=true
RestrictSUIDSGID=true
LockPersonality=true
RestrictRealtime=true
```

چون پنل برای نوشتن کانفیگ VPN و اجرای `systemctl` دسترسی سطح بالا لازم دارد، `ProtectSystem=strict` را بدون طراحی Helper جداگانه فعال نکن. معماری بهتر این است که API با کاربر محدود اجرا شود و یک Helper کوچک Root فقط فرمان‌های allowlist‌شده را اجرا کند.

## ۱۲. Logging و Incident Response

- Secret، Password، PSK و License Key کامل را Log نکن.
- برای خطای 500 فقط Incident ID به کاربر بده و Stack Trace را در Journal نگه دار.
- لاگ‌ها را Rotate و دسترسی آن‌ها را محدود کن.
- برای Login ناموفق، تغییر لایسنس، Restore، دریافت Token نود و تغییر PSK Audit Log ثبت کن.
- Alert برای تغییر SSH Host Key، چند 401/429، Restore و غیرفعال‌شدن لایسنس بساز.

## ۱۳. چک‌لیست قبل از انتشار

```bash
# Python syntax
python -m compileall -q backend/app

# Shell syntax
bash -n install/install.sh
bash -n install/update.sh

# پیدا کردن placeholder یا secret مشکوک
rg -n 'change-me|BEGIN (RSA|PRIVATE) KEY|API_KEY=' .

# کنترل دسترسی فایل‌ها روی سرور
stat -c '%a %U:%G %n' \
  /opt/vpn-panel/backend/.env \
  /var/lib/vpn-panel/ssh_known_hosts \
  /root/.vpn-panel/backup-recovery-key.txt

# تست بکاپ رمزگذاری‌شده و دست‌کاری‌شده
pytest -q backend/tests -k 'backup or security or license or node'
```

در CI علاوه بر Unit Test، سناریوهای زیر را اجرا کن:

- لایسنس معتبر/منقضی/سرور لایسنس قطع/Grace تمام‌شده
- دو درخواست هم‌زمان مصرف لایسنس داخلی
- تغییر یک بایت از بکاپ AES-GCM
- Gzip Bomb
- ادمین محدود برای Token نود، PSK و License Key
- تغییر SSH Host Key
- Restore تمام نودهای آنلاین و گزارش نود آفلاین
- بسته‌ی آپدیت با امضای غلط و hash غلط

## ۱۴. کارهایی که به‌تنهایی امنیت ایجاد نمی‌کنند

- فقط Obfuscate کردن JavaScript
- مخفی‌کردن مسیر API
- Base64 کردن Secret
- قرار دادن Private Key داخل باینری مشتری
- فقط مقایسه‌ی نسخه یا نام فایل ZIP
- License check کاملاً محلی و بدون امضای سرور
- ادعای «غیرقابل‌کرک»

امنیت واقعی از لایه‌های مستقل می‌آید: لایسنس امضاشده و کوتاه‌عمر، Secretهای جدا، کمترین دسترسی، بکاپ AEAD، بسته‌ی آپدیت امضاشده، Audit Log، Rate Limit و نگه‌داشتن منطق اصلی روی زیرساخت خودت.
