# مرکز کنترل VPN

سامانهٔ مدیریت چند پنل `vpn-ui` با Backend مبتنی بر FastAPI، ربات تلگرام و زیرساخت مالی و عملیاتی قابل توسعه.

## وضعیت انتشار

نسخهٔ فعلی `0.1.0` و در مرحلهٔ توسعه است. در این نسخه Adapter اولیهٔ API پنل، مدیریت Session Cookie، رعایت Base Path، کنترل پاسخ JSON و تشخیص `success:false` پیاده‌سازی شده است. هنوز سیستم فروش، پرداخت، کیف پول، نمایندگی، پنل وب، ربات کامل، مانیتورینگ تاریخی، بکاپ قابل‌بازیابی و گردش‌کارهای عملیاتی کامل نشده‌اند. این نسخه را محصول آمادهٔ استفاده تجاری تلقی نکنید.

## نکات مهم API

- احراز هویت با Cookie واقعی `vpn-ui` انجام می‌شود؛ API Key فرضی وجود ندارد.
- هر اتصال پنل باید Cookie Jar مستقل داشته باشد.
- POSTها با فرم URL Encoded ارسال می‌شوند و `settings` مقدار JSON رشته‌ای است.
- برای مسیرهای API هدر `X-Requested-With: XMLHttpRequest` ارسال می‌شود.
- پاسخ HTTP 200 با `success:false` خطا محسوب می‌شود.
- در صورت نیاز به 2FA، مقدار `obj.twoFactorRequired` بررسی می‌شود و کد در `twoFactorCode` ارسال خواهد شد.
- `totalGB` در مدل کلاینت پنل، با وجود نامش، بایت است.
- `expiryTime` زمان Unix بر حسب میلی‌ثانیه است.
- `enable=true` باید هنگام ساخت کلاینت صریح باشد.

فهرست پروتکل‌های شناسایی‌شده در API Reference شامل L2TP، PPTP، OpenVPN، OpenConnect، SSTP، IKEv2، WireGuard-C، AmneziaWG، GRE، MTProto، SSH، AnyTLS، TUIC، NaiveProxy، VMess، VLESS، Trojan، Shadowsocks و Hysteria است. پشتیبانی کامل عملیاتی از هر پروتکل نیازمند Adapter کانفیگ و تست اختصاصی است.

## راه‌اندازی توسعه

```bash
python3.12 -m venv .venv
source .venv/bin/activate
pip install -e '.[dev]'
cp .env.example .env
uvicorn vpn_manager.main:app --app-dir src --host 127.0.0.1 --port 8080
pytest -q
```

## نصب Ubuntu

```bash
curl -fsSL https://raw.githubusercontent.com/AmiRaiZo/VPN-Control-Center/main/install.sh | sudo bash
```

نصب‌کننده روی Ubuntu 24.04 و ترمینال تعاملی اجرا می‌شود، سورس را در `/opt/vpn-control-center` دریافت می‌کند، وابستگی‌ها را نصب می‌کند و Token ربات را به‌صورت مخفی می‌پرسد. سپس Token را با Telegram `getMe` اعتبارسنجی می‌کند، شناسه عددی مدیر اصلی را می‌گیرد، تنظیمات را با مجوز `0600` ذخیره می‌کند و سرویس `vpn-manager-bot` را فعال می‌کند. توکن را در خود دستور یا URL قرار ندهید.

مشاهده لاگ ربات:

```bash
sudo journalctl -u vpn-manager-bot -f
```

فرمان‌های فعلی ربات `/start` و `/admin` هستند. قابلیت‌های فروش و مدیریت سرویس هنوز پیاده‌سازی نشده‌اند. این نصب‌کننده سرویس API یا دیتابیس را راه‌اندازی نمی‌کند.

## منابع رسمی

- https://github.com/Sir-MmD/vpn-ui/blob/main/api-reference.md
- https://github.com/Sir-MmD/vpn-ui/blob/main/README_FA.md

