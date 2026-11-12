# VPN Control Center

سامانهٔ مدیریت چندپنلی برای کسب‌وکار VPN با اتصال مستقیم به API رسمی `Sir-MmD/vpn-ui`.

> وضعیت فعلی: **نسخهٔ توسعه‌ای 0.1.0**. این مخزن پایهٔ اتصال پنل و یک Telegram polling bot اولیه را فراهم می‌کند؛ ربات فعلاً مدیر اصلی را شناسایی و وضعیت اولیه را اعلام می‌کند. فروش، دفترکل مالی، نمایندگی، تیکتینگ، داشبورد وب و گردش‌کارهای تجاری هنوز پیاده‌سازی نشده‌اند. تا پیش از تست یکپارچگی با پنل واقعی و درگاه پرداخت واقعی، این نسخه را برای فروش زنده به کار نگیرید.

## اتصال به vpn-ui

Adapter با Session Cookie به نام `vpn-ui` کار می‌کند، Base Path را رعایت می‌کند، درخواست‌های POST را Form URL Encoded می‌فرستد و `success:false` را حتی در پاسخ HTTP 200 شکست محسوب می‌کند. هدر `X-Requested-With` برای API ارسال می‌شود. هر نمونهٔ `VpnUiClient` یک Cookie Jar مستقل دارد.

احراز هویت طبق API Reference با `POST /login` و فیلدهای `username` و `password` انجام می‌شود. در صورت نیاز مدیر به 2FA، پاسخ `success:false` همراه `obj.twoFactorRequired=true` تشخیص داده شده و ورود باید با `twoFactorCode` تکرار شود. Cookie با نام `vpn-ui` نگهداری و از `GET /logout` برای خروج استفاده می‌شود.

پروتکل‌های شناسایی‌شده در API Reference: `l2tp`, `pptp`, `openvpn`, `openconnect`, `sstp`, `ikev2`, `wg-c`, `awg`, `gre`, `mtproto`, `ssh`, `anytls`, `tuic`, `naive`, `vmess`, `vless`, `trojan`, `shadowsocks`, `hysteria`. وجود نام پروتکل به معنی پشتیبانی کامل چرخهٔ ساخت کانفیگ و تمدید آن در این نسخه نیست.

نکات داده‌ای API: `totalGB` در ورودی کلاینت بر حسب **بایت** است؛ `expiryTime` بر حسب Unix milliseconds است. ایجاد کلاینت باید `enable=true` را صریح بفرستد.

## توسعه محلی

```bash
python3.12 -m venv .venv
source .venv/bin/activate
pip install -e '.[dev]'
cp .env.example .env
uvicorn vpn_manager.main:app --app-dir src --host 127.0.0.1 --port 8080
pytest -q
```

## نصب یک‌خطی روی Ubuntu Server

Ubuntu 24.04 LTS و Python 3.12 پیشنهاد می‌شود. در ترمینال SSH تعاملی اجرا کنید:

```bash
curl -fsSL https://raw.githubusercontent.com/AmiRaiZo/VPN-Control-Center/main/install.sh | sudo bash
```

نصب‌کننده سورس را در `/opt/vpn-control-center` دریافت می‌کند، وابستگی‌ها را نصب می‌کند، Token را بدون نمایش روی صفحه می‌گیرد و با Telegram `getMe` اعتبارسنجی می‌کند. سپس شناسه عددی مدیر اصلی را دریافت می‌کند، هر دو مقدار را در `.env` با مجوز `0600` ذخیره و سرویس `vpn-manager-bot` را فعال می‌کند. Token را در دستور نصب یا URL قرار ندهید. برای مشاهده لاگ:

```bash
sudo journalctl -u vpn-manager-bot -f
```

ربات فعلی فرمان‌های `/start` و `/admin` را دارد و دسترسی را فقط برای شناسه‌های مدیر پیکربندی‌شده می‌پذیرد؛ ماژول فروش هنوز وجود ندارد. این نصب‌کننده دیتابیس یا سرویس API را راه‌اندازی نمی‌کند و تنظیمات Firewall و SSH را تغییر نمی‌دهد.

## مستندات مرجع

- [vpn-ui API Reference](https://github.com/Sir-MmD/vpn-ui/blob/main/api-reference.md)
- [vpn-ui README فارسی](https://github.com/Sir-MmD/vpn-ui/blob/main/README_FA.md)
- [vpn-ui README](https://github.com/Sir-MmD/vpn-ui/blob/main/README.md)

