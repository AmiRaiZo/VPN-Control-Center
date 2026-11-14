#!/bin/bash
###############################################################################
# IKEv2/IPsec (EAP-MSCHAPv2) infrastructure setup.
#
# این اسکریپت یک conn جدید و مستقل به‌نام «IKEv2-MSCHAPv2» به strongSwan
# (که از قبل توسط install.sh برای L2TP/IPsec نصب شده) اضافه می‌کند. کاملاً
# جدا از conn L2TP-PSK است: L2TP از PSK مشترک استفاده می‌کند، این یکی از
# سرتیفیکیت سرور (leftauth=pubkey) + یوزرنیم/پسورد هر کاربر با
# EAP-MSCHAPv2 (rightauth=eap-mschapv2). کلاینت نیازی به سرتیفیکیت خودش
# ندارد - فقط باید سرتیفیکیت CA سرور را trust کند (دقیقاً مثل اکثر
# سرویس‌های تجاری IKEv2).
#
# idempotent است: هم از install.sh/update.sh و هم مستقیم قابل اجراست.
# اجرای مجدد فقط گواهی/کانفیگ را ترمیم/به‌روز می‌کند، از صفر نمی‌سازد.
#
# Usage: sudo bash setup_ikev2.sh [--force]
###############################################################################
set -e

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
if [ -r "$SCRIPT_DIR/apt_preflight.sh" ]; then
  # shellcheck source=apt_preflight.sh
  source "$SCRIPT_DIR/apt_preflight.sh"
fi

if [ "$EUID" -ne 0 ]; then
  echo "Please run this script as root (sudo bash setup_ikev2.sh)"
  exit 1
fi

FORCE=0
[ "$1" = "--force" ] && FORCE=1

CERT_DIR="/etc/ipsec.d"
SERVER_CERT="${CERT_DIR}/certs/ikev2-server-cert.pem"
SERVER_KEY="${CERT_DIR}/private/ikev2-server-key.pem"
CA_CERT="${CERT_DIR}/cacerts/ikev2-ca-cert.pem"
IKEV2_SUBNET="10.10.11"

if ! command -v ipsec >/dev/null 2>&1 && ! command -v strongswan >/dev/null 2>&1; then
  echo "[*] strongSwan not found - installing (should already be present from install.sh)..."
  if [ "${SKIP_APT_UPDATE:-0}" != "1" ]; then vpn_panel_apt_get update; fi
  vpn_panel_install_packages strongswan strongswan-pki libcharon-extra-plugins libstrongswan-extra-plugins
fi

detect_public_ip() {
  local ip=""
  local url
  for url in "https://ifconfig.me" "https://icanhazip.com" "https://api.ipify.org"; do
    ip=$(curl -s -f -4 --max-time 5 "$url" 2>/dev/null | tr -d '[:space:]')
    if [[ "$ip" =~ ^[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}$ ]]; then
      echo "$ip"
      return
    fi
  done
  hostname -I 2>/dev/null | awk '{print $1}'
}

# ---------------------------------------------------------------------------
# گواهی سرور: اگر Let's Encrypt از قبل (برای دامنه‌ی اختصاصی پروتکل‌ها یا
# دامنه‌ی پنل) موجود باشد همان استفاده می‌شود؛ وگرنه یک CA + گواهی سرور
# self-signed با SAN صحیح (IP + hostname) ساخته می‌شود - دقیقاً همان الگوی
# setup_sstp.sh، چون بدون SAN بعضی کلاینت‌ها (از جمله ویندوز/iOS) گواهی را
# رد می‌کنند.
# ---------------------------------------------------------------------------
# ---------------------------------------------------------------------------
# بعضی گواهی‌های جدید Let's Encrypt (مثل زنجیره‌ی "YR"/"YE" برای کوتاه‌مدت‌ها)
# به یک ریشه‌ی جدید ختم می‌شوند که هنوز در trust store همه‌ی دستگاه‌ها
# (خصوصاً موبایل) نیست - ولی آن ریشه‌ی جدید معمولاً توسط "ISRG Root X1"
# قدیمی و گسترده‌تر cross-sign شده است. این تابع آدرس AIA (CA Issuers) را از
# آخرین گواهی داخل chain.pem می‌خواند، آن گواهی cross-signed را می‌گیرد و به
# همان فایل اضافه می‌کند - در نتیجه strongSwan این گواهی اضافه را هم در
# CERT payload می‌فرستد و کلاینت می‌تواند تا "ISRG Root X1" (که از قبل
# trusted است) زنجیره را کامل کند، بدون نیاز به import دستی روی هر دستگاه.
# اگر شبکه/AIA در دسترس نباشد، بی‌صدا رد می‌شود (idempotent، بدون شکست کل اسکریپت).
# ---------------------------------------------------------------------------
fetch_cross_signed_issuer() {
  local chain_file="$1" aia_url cross_cert
  [ -f "$chain_file" ] || return 0
  command -v curl >/dev/null 2>&1 || return 0
  aia_url=$(openssl x509 -in "$chain_file" -noout -text 2>/dev/null \
    | grep -A1 "CA Issuers" | grep "URI:" | tail -1 | sed 's/.*URI://')
  [ -n "$aia_url" ] || return 0
  cross_cert=$(curl -fsS --max-time 5 "$aia_url" 2>/dev/null | openssl x509 -inform DER -outform PEM 2>/dev/null)
  if [ -n "$cross_cert" ] && ! grep -qF "$(echo "$cross_cert" | sed -n '2p')" "$chain_file" 2>/dev/null; then
    echo "$cross_cert" >> "$chain_file"
  fi
}

ensure_ikev2_cert() {
  local public_ip regen_needed=0
  public_ip=$(detect_public_ip)

  mkdir -p "${CERT_DIR}/certs" "${CERT_DIR}/private" "${CERT_DIR}/cacerts"

  # اگر قبلاً از Settings > SSL برای IKEv2 یک دامنه‌ی اختصاصی ست شده (یعنی
  # install/setup_ikev2_ssl.sh اجرا شده و مارکر زیر را نوشته)، همان گواهی
  # را دست نخورده نگه می‌داریم. عمداً هیچ پوشه‌ی دیگری زیر
  # /etc/letsencrypt/live را حدس نمی‌زنیم - این سرور می‌تواند چند دامنه‌ی
  # دیگر (دامنه‌ی خودِ پنل، ساب‌دامین و ...) هم داشته باشد که هیچ ربطی به
  # IKEv2 ندارند؛ گرفتن کورکورانه‌ی «اولین پوشه‌ای که پیدا شد» باعث می‌شد
  # گواهی دامنه‌ی پنل به‌جای گواهی IKEv2 نصب شود و اتصال بشکند.
  IKEV2_DOMAIN_MARKER="${CERT_DIR}/.ikev2-ssl-domain"
  if [ -f "$IKEV2_DOMAIN_MARKER" ] && [ "$FORCE" != "1" ]; then
    IKEV2_DOMAIN=$(cat "$IKEV2_DOMAIN_MARKER" 2>/dev/null | tr -d '[:space:]')
    LE_LIVE_DIR="/etc/letsencrypt/live/${IKEV2_DOMAIN}"
    if [ -n "$IKEV2_DOMAIN" ] && [ -f "$LE_LIVE_DIR/cert.pem" ]; then
      # قبلاً اینجا فقط "return 0" بود - یعنی به صرف وجود مارکر، هیچ‌وقت
      # وضعیت واقعی ipsec.d چک/ترمیم نمی‌شد. مشکل: اگر یک بار (مثلاً قبل از
      # این‌که دامنه اصلاً تنظیم شود، یا بعد از یک renewal ناقص) یک CA
      # self-signed قدیمی در cacerts جا مانده باشد، یا cert/key داخل ipsec.d
      # با نسخه‌ی فعلی LIVE_DIR هم‌گام نباشند (مثلاً از یک بکاپ قدیمی
      # restore شده)، این مسیر هیچ‌وقت آن را پاک/ترمیم نمی‌کرد و charon
      # همچنان با گواهی/CA کهنه بالا می‌آمد - دقیقاً همان چیزی که در لاگ
      # AUTH_FAILED با "sending cert request for CN=...self-signed CA" دیده
      # می‌شود. راه‌حل: هر بار (idempotent و کم‌هزینه، فقط چند تا cp/rm) از
      # روی LIVE_DIR دوباره سینک کن و cacerts را از هر CA خودامضای قدیمی
      # پاک کن - دقیقاً همان کاری که deploy hook هنگام تمدید انجام می‌دهد،
      # منتها اینجا در هر اجرای install.sh/update.sh هم تضمین می‌شود.
      # نکته‌ی مهم درباره‌ی اعتمادسازی زنجیره: کپی fullchain.pem به SERVER_CERT
      # به‌تنهایی کافی نیست - strongSwan فقط اولین گواهی داخل فایل leftcert
      # را به‌عنوان end-entity cert در پیام IKE_AUTH می‌فرستد، نه بقیه‌ی
      # زنجیره را (این چیزی بود که قبلاً اشتباه فرض کرده بودم). برای اینکه
      # CA میانی («intermediate»، اینجا Let's Encrypt "YE2"/"YR2") واقعاً در
      # پیام CERT فرستاده شود، باید در /etc/ipsec.d/cacerts/ باشد - strongSwan
      # زنجیره‌ی اعتماد را از آنجا می‌سازد. بدون این، کلاینت‌های موبایل که
      # سخت‌گیرانه validate می‌کنند (و AIA را هم نمی‌توانند وسط handshake
      # fetch کنند) با خطای بی‌صدای "no issuer certificate found" /
      # AUTH_FAILED رد می‌شوند - این دقیقاً چیزی بود که در لاگ کلاینت strongSwan
      # Android دیده شد.
      cp "${LE_LIVE_DIR}/fullchain.pem" "$SERVER_CERT"
      cp "${LE_LIVE_DIR}/privkey.pem" "$SERVER_KEY"
      chmod 600 "$SERVER_KEY"
      rm -f "${CERT_DIR}"/cacerts/*.pem
      if [ -f "${LE_LIVE_DIR}/chain.pem" ]; then
        cp "${LE_LIVE_DIR}/chain.pem" "${CERT_DIR}/cacerts/letsencrypt-chain.pem"
        fetch_cross_signed_issuer "${CERT_DIR}/cacerts/letsencrypt-chain.pem"
      fi

      # نکته: -modulus فقط برای RSA معنی دارد؛ روی کلید/گواهی ECDSA خطا
      # می‌دهد (یا خروجی خالی) و می‌تواند هشدار غلط "مودولوس یکی نیست" بدهد.
      # مقایسه‌ی کلید عمومی (pubkey) هم برای RSA هم ECDSA درست کار می‌کند.
      CERT_MODULUS=$(openssl x509 -noout -pubkey -in "$SERVER_CERT" 2>/dev/null | openssl md5)
      KEY_MODULUS=$(openssl pkey -pubout -in "$SERVER_KEY" 2>/dev/null | openssl md5)
      if [ "$CERT_MODULUS" != "$KEY_MODULUS" ]; then
        echo "[!] هشدار: cert.pem و privkey.pem داخل ${LE_LIVE_DIR} جفتِ هم نیستند" >&2
        echo "    (مودولوس یکی نیست) - گواهی نصب‌شده احتمالاً کار نمی‌کند." >&2
        echo "    'certbot certificates -d ${IKEV2_DOMAIN}' را چک کنید." >&2
      fi

      echo "[*] دامنه‌ی اختصاصی IKEv2 ($IKEV2_DOMAIN) از قبل تنظیم شده - از LIVE_DIR دوباره سینک/ترمیم شد."
      echo "[*] برای صدور/تعویض دامنه از install/setup_ikev2_ssl.sh استفاده کنید، نه این اسکریپت."
      return 3
    else
      echo "[!] مارکر دامنه‌ی IKEv2 ($IKEV2_DOMAIN) پیدا شد ولی گواهی Let's Encrypt آن دیگر موجود نیست - بازگشت به گواهی self-signed."
    fi
  fi

  # ---------------------------------------------------------------------------
  # خودتشخیصی دامنه: مارکر .ikev2-ssl-domain فقط وقتی نوشته می‌شود که کسی واقعاً
  # از install/setup_ikev2_ssl.sh یا Settings > SSL برای IKEv2 در پنل استفاده
  # کرده باشد. دیده شد که ممکن است یک گواهی Let's Encrypt برای زیردامنه‌ی
  # ikev2.* (مثلاً از یک تلاش قبلی که کامل ثبت نشده، یا صدور دستی) در
  # /etc/letsencrypt/live از قبل موجود باشد، ولی چون آن جریان کامل اجرا نشده
  # مارکر هیچ‌وقت نوشته نشده - نتیجه: setup_ikev2.sh هر بار (حتی با
  # install.sh/update.sh) کورکورانه گواهی self-signed می‌ساخت، در حالی که یک
  # گواهی دامنه‌ی معتبر و آماده همون کنار دست بود. اینجا (فقط وقتی مارکر
  # اصلاً وجود نداشت - نه در حالت --force) پوشه‌های زیر /etc/letsencrypt/live
  # را برای الگوی ikev2.* می‌گردیم؛ اگر دقیقاً یکی پیدا شد (و cert.pem دارد)،
  # به‌جای ساخت self-signed همان را خودکار adopt می‌کنیم - دقیقاً همان کاری
  # که setup_ikev2_ssl.sh با اجرای دستی انجام می‌داد.
  if [ ! -f "$IKEV2_DOMAIN_MARKER" ] && [ "$FORCE" != "1" ] && [ -d /etc/letsencrypt/live ]; then
    AUTO_MATCHES=()
    for d in /etc/letsencrypt/live/ikev2.*; do
      [ -f "${d}/cert.pem" ] && AUTO_MATCHES+=("$(basename "$d")")
    done
    if [ "${#AUTO_MATCHES[@]}" = "1" ]; then
      AUTO_DOMAIN="${AUTO_MATCHES[0]}"
      AUTO_LIVE_DIR="/etc/letsencrypt/live/${AUTO_DOMAIN}"
      echo "[*] هیچ مارکر دامنه‌ای برای IKEv2 ثبت نشده بود، ولی یک گواهی"
      echo "    Let's Encrypt آماده برای ${AUTO_DOMAIN} پیدا شد - به‌جای"
      echo "    self-signed، همین را خودکار نصب می‌کنیم."
      # همان دلیل بالا (نیاز به گذاشتن CA میانی در cacerts/ ، نه فقط توی leftcert) اینجا هم اعمال می‌شود.
      cp "${AUTO_LIVE_DIR}/fullchain.pem" "$SERVER_CERT"
      cp "${AUTO_LIVE_DIR}/privkey.pem" "$SERVER_KEY"
      chmod 600 "$SERVER_KEY"
      rm -f "${CERT_DIR}"/cacerts/*.pem
      if [ -f "${AUTO_LIVE_DIR}/chain.pem" ]; then
        cp "${AUTO_LIVE_DIR}/chain.pem" "${CERT_DIR}/cacerts/letsencrypt-chain.pem"
        fetch_cross_signed_issuer "${CERT_DIR}/cacerts/letsencrypt-chain.pem"
      fi
      echo "$AUTO_DOMAIN" > "$IKEV2_DOMAIN_MARKER"

      CERT_MODULUS=$(openssl x509 -noout -pubkey -in "$SERVER_CERT" 2>/dev/null | openssl md5)
      KEY_MODULUS=$(openssl pkey -pubout -in "$SERVER_KEY" 2>/dev/null | openssl md5)
      if [ "$CERT_MODULUS" != "$KEY_MODULUS" ]; then
        echo "[!] هشدار: cert.pem و privkey.pem داخل ${AUTO_LIVE_DIR} جفتِ هم نیستند." >&2
      fi
      return 3
    elif [ "${#AUTO_MATCHES[@]}" -gt 1 ]; then
      echo "[!] چند گواهی ikev2.* همزمان پیدا شد (${AUTO_MATCHES[*]}) - انتخاب"
      echo "    خودکار مبهم است. یکی را دستی از Settings > SSL برای IKEv2 در"
      echo "    پنل انتخاب کنید تا مارکر درست نوشته شود."
    fi
  fi

  if [ -f "$SERVER_CERT" ] && [ "$FORCE" != "1" ]; then
    if ! openssl x509 -in "$SERVER_CERT" -noout -ext subjectAltName 2>/dev/null | grep -q "IP Address\|DNS"; then
      echo "[*] گواهی موجود فاقد SAN است - در حال ساخت دوباره..."
      regen_needed=1
    elif [ -n "$public_ip" ] && ! openssl x509 -in "$SERVER_CERT" -noout -ext subjectAltName 2>/dev/null | grep -q "$public_ip"; then
      echo "[*] گواهی موجود IP فعلی سرور ($public_ip) را در SAN ندارد - در حال ساخت دوباره..."
      regen_needed=1
    fi
  else
    regen_needed=1
  fi

  if [ "$regen_needed" = "1" ]; then
    echo "[*] Generating self-signed CA + server certificate (IP: ${public_ip:-N/A}, DNS: $(hostname))..."
    local san="DNS:$(hostname)"
    [ -n "$public_ip" ] && san="IP:${public_ip},${san}"

    ipsec pki --gen --type rsa --size 4096 --outform pem > "${CERT_DIR}/private/ikev2-ca-key.pem" 2>/dev/null \
      || openssl genrsa -out "${CERT_DIR}/private/ikev2-ca-key.pem" 4096
    chmod 600 "${CERT_DIR}/private/ikev2-ca-key.pem"

    ipsec pki --self --ca --lifetime 3650 \
      --in "${CERT_DIR}/private/ikev2-ca-key.pem" \
      --dn "CN=VPN Panel IKEv2 CA" \
      --outform pem > "$CA_CERT" 2>/dev/null

    # نکته: کلید سرور عمداً 2048-bit است، نه 4096 مثل CA. یک گواهی leaf
    # 4096-bit باعث می‌شود پیام IKE_AUTH (که شامل گواهی است) بزرگ‌تر از یک
    # پکت UDP بشود و charon مجبور شود آن را IKE-fragment کند (EF(1/2)،
    # EF(2/2)). بسیاری از فایروال‌ها/NATهای بین‌راهی (مخصوصاً شبکه‌های
    # موبایل) این fragmentهای IKEv2 را درست عبور نمی‌دهند - نتیجه دقیقاً
    # همان چیزی است که در لاگ دیده می‌شود: سرور IKE_AUTH را می‌فرستد ولی
    # کلاینت هیچ‌وقت جواب نمی‌دهد و بعد از timeout "half open IKE_SA" حذف
    # می‌شود. RSA 2048 استاندارد صنعتی برای گواهی leaf است و معمولاً کل
    # پیام را زیر سقف fragmentation نگه می‌دارد.
    ipsec pki --gen --type rsa --size 2048 --outform pem > "$SERVER_KEY" 2>/dev/null
    chmod 600 "$SERVER_KEY"

    ipsec pki --pub --in "$SERVER_KEY" --type rsa \
      | ipsec pki --issue --lifetime 3650 \
        --cacert "$CA_CERT" \
        --cakey "${CERT_DIR}/private/ikev2-ca-key.pem" \
        --dn "CN=${public_ip:-$(hostname)}" \
        --san "${public_ip:-$(hostname)}" \
        --san "$(hostname)" \
        --flag serverAuth --flag ikeIntermediate \
        --outform pem > "$SERVER_CERT" 2>/dev/null

    return 2
  fi
  echo "[*] گواهی IKEv2 معتبر است و نیازی به ساخت دوباره نیست."
  return 0
}

# توجه: ensure_ikev2_cert عمداً 0/2/3 برمی‌گرداند (نه فقط 0=موفق).
# زیر set -e، فراخوانی مستقیم یک تابع که چیزی جز 0 برگرداند باعث خروج
# فوری کل اسکریپت می‌شود - دقیقاً همان چیزی که در لاگ دیده شد: بعد از
# "return 3" هیچ خط دیگری اجرا نمی‌شد و conn هیچ‌وقت به ipsec.conf اضافه
# نمی‌شد. با set +e/-e دور فراخوانی، مقدار بازگشتی را بدون کشتن اسکریپت
# می‌گیریم.
set +e
ensure_ikev2_cert
cert_changed=$?
set -e

# leftid باید دقیقاً با CN/SAN گواهی نصب‌شده یکی باشد، وگرنه احراز هویت سرور
# (leftauth=pubkey) با AUTH_FAILED رد می‌شود. اگر دامنه‌ی اختصاصی IKEv2 از
# Settings > SSL برای IKEv2 تنظیم شده (مارکر زیر)، leftid باید همان دامنه
# باشد؛ در غیر این صورت (گواهی self-signed) از hostname استفاده می‌شود.
IKEV2_DOMAIN_MARKER="${CERT_DIR}/.ikev2-ssl-domain"
if [ -f "$IKEV2_DOMAIN_MARKER" ]; then
  IKEV2_LEFTID=$(cat "$IKEV2_DOMAIN_MARKER" 2>/dev/null | tr -d '[:space:]')
fi
[ -z "$IKEV2_LEFTID" ] && IKEV2_LEFTID="$(hostname)"

# ---------------------------------------------------------------------------
# افزودن conn IKEv2-MSCHAPv2 به /etc/ipsec.conf (idempotent - قبل از افزودن
# اگر بلوک قبلی وجود دارد حذفش می‌کنیم تا دوباره‌نویسی تمیز باشد).
# ---------------------------------------------------------------------------
if [ ! -f /etc/ipsec.conf ]; then
  echo "[!] /etc/ipsec.conf پیدا نشد - این اسکریپت باید بعد از نصب اصلی پنل (که strongSwan/L2TP را نصب می‌کند) اجرا شود." >&2
  exit 1
fi

IKEV2_RIGHTDNS="8.8.8.8,1.1.1.1"
if grep -q "^conn IKEv2-MSCHAPv2" /etc/ipsec.conf; then
  existing_rightdns=$(awk '
    /^conn IKEv2-MSCHAPv2/{inside=1; next}
    /^conn[[:space:]]+/{inside=0}
    inside && /^[[:space:]]*rightdns[[:space:]]*=/{sub(/^[^=]*=/, ""); gsub(/[[:space:]]/, ""); print; exit}
  ' /etc/ipsec.conf)
  [ -n "$existing_rightdns" ] && IKEV2_RIGHTDNS="$existing_rightdns"
  python3 - << 'PYEOF'
import re
path = "/etc/ipsec.conf"
with open(path) as f:
    content = f.read()
content = re.sub(r"\nconn IKEv2-MSCHAPv2\n(?:[ \t].*\n)*", "\n", content)
with open(path, "w") as f:
    f.write(content)
PYEOF
fi

cat >> /etc/ipsec.conf << EOF

conn IKEv2-MSCHAPv2
    keyexchange=ikev2
    left=%defaultroute
    leftid=@${IKEV2_LEFTID}
    leftauth=pubkey
    leftcert=ikev2-server-cert.pem
    leftsendcert=always
    leftsubnet=0.0.0.0/0
    right=%any
    rightauth=eap-mschapv2
    rightsourceip=${IKEV2_SUBNET}.10-${IKEV2_SUBNET}.250
    rightdns=${IKEV2_RIGHTDNS}
    eap_identity=%identity
    # همان رفع‌مشکل NAT-T که conn L2TP-PSK از install.sh دارد (اغلب سرورهای
    # ابری پشت نوعی NAT مجازی هستند؛ بدون این، فاز IKE/IPsec می‌تواند
    # بی‌صدا شکست بخورد و کلاینت موبایل فقط یک خطای عمومی «Unsuccessful» یا
    # تایم‌اوت کامل ببیند - این conn قبلاً این خط را نداشت چون بعد از
    # L2TP-PSK و جدا از آن اضافه می‌شود؛ configure_vpn_protocols.sh هم چون
    # چک «آیا forceencaps=yes از قبل جایی در فایل هست» را روی کل فایل انجام
    # می‌داد (نه هر conn جداگانه)، بعد از این‌که L2TP-PSK آن را داشت هیچ‌وقت
    # این conn را هم اصلاح نمی‌کرد.
    forceencaps=yes
    # مشاهده‌شده با کلاینت موبایل: کلاینت توی IKE_SA_INIT پرچم FRAG_SUP را
    # اعلام می‌کند (یعنی می‌گوید fragmentation در سطح IKE را ساپورت دارد)،
    # سرور هم IKE_AUTH response را (چون از fragment_size پیش‌فرض 1280 بزرگ‌تر
    # است) به ۲ تکه می‌شکند و هر دو را می‌فرستد - ولی کلاینت هیچ‌وقت پاسخ
    # نمی‌دهد و بعد از timeout نیمه‌باز SA پاک می‌شود. این یعنی پیاده‌سازی
    # reassembly این کلاینت خاص (یا یک NAT/فایروال شبکه‌ی موبایل بین راه) با
    # چند پکت UDP fragment پشت‌سرهم روی همان ۴-tuple مشکل دارد - یک باگ/
    # ناسازگاری شناخته‌شده در بعضی کلاینت‌های IKEv2 موبایل. با fragmentation=no
    # این conn دیگر هیچ‌وقت IKE-level fragment نمی‌فرستد؛ در عوض یک پیام کامل
    # (بزرگ‌تر از MTU معمولی) می‌فرستد که fragmentation آن به IP/کرنل سپرده
    # می‌شود - که شبکه‌های موبایل معمولاً باهاش بهتر کنار می‌آیند تا
    # fragmentation سطح IKE.
    fragmentation=no
    dpdaction=clear
    dpddelay=35s
    rekey=no
    auto=add
EOF

# ---------------------------------------------------------------------------
# ipsec.secrets: خط سرتیفیکیت سرور (RSA) اضافه می‌شود اگر از قبل نیست. کاربران
# EAP جداگانه توسط بک‌اند پنل (vpn_manager.sync_ikev2_secrets) در همین فایل،
# داخل یک بلوک auto-generated جدا، مدیریت می‌شوند - این اسکریپت به آن بلوک
# دست نمی‌زند.
# ---------------------------------------------------------------------------
touch /etc/ipsec.secrets
if ! grep -q "ikev2-server-key.pem" /etc/ipsec.secrets; then
  # این خط باید بالای فایل باشد (قبل از هر بلوک EAP)، وگرنه استفاده نمی‌شود.
  sed -i "1i : RSA ikev2-server-key.pem" /etc/ipsec.secrets
fi
chmod 600 /etc/ipsec.secrets

# ---------------------------------------------------------------------------
# ری‌استارت مطمئن: صرفاً «systemctl restart» گاهی charon را واقعاً نمی‌کشد
# (زیرپردازه‌ی starter است؛ اگر starter نیمه‌جان باشد restart می‌تواند موفق
# گزارش شود بدون اینکه charon واقعاً عوض شود) - دقیقاً همان چیزی که باعث
# می‌شد بعد از تعویض گواهی، charon قدیمی هنوز با CA/گواهی کش‌شده‌ی قبلی سرِ
# کار بماند و AUTH_FAILED بدهد. اینجا pid قبل/بعد را می‌گیریم و اگر عوض
# نشده بود، صراحتاً SIGTERM/SIGKILL دستی می‌فرستیم و دوباره start می‌زنیم.
OLD_CHARON_PID=$(pgrep -x charon | head -n1)
systemctl restart strongswan-starter 2>/dev/null || systemctl restart strongswan 2>/dev/null || ipsec restart 2>/dev/null || true
sleep 2
NEW_CHARON_PID=$(pgrep -x charon | head -n1)
if [ -n "$OLD_CHARON_PID" ] && [ -n "$NEW_CHARON_PID" ] && [ "$OLD_CHARON_PID" = "$NEW_CHARON_PID" ]; then
  echo "[!] pid charon بعد از restart عوض نشد - کشتن دستی و بالا آوردن دوباره..."
  systemctl stop strongswan-starter 2>/dev/null || systemctl stop strongswan 2>/dev/null || ipsec stop 2>/dev/null || true
  for _ in 1 2 3 4 5 6 7 8; do
    pgrep -x charon >/dev/null 2>&1 || break
    sleep 1
  done
  pkill -TERM -x charon 2>/dev/null || true
  sleep 2
  pkill -KILL -x charon 2>/dev/null || true
  sleep 1
  systemctl start strongswan-starter 2>/dev/null || systemctl start strongswan 2>/dev/null || ipsec start 2>/dev/null || true
  sleep 2
fi

# ---------------------------------------------------------------------------
# NAT برای ساب‌نت IKEv2 (مثل L2TP/SSTP) تا کلاینت‌های وصل‌شده به اینترنت
# دسترسی داشته باشند.
# ---------------------------------------------------------------------------
NET_IFACE=$(ip route | grep default | awk '{print $5}' | head -n1)
sysctl -w net.ipv4.ip_forward=1 >/dev/null
grep -q '^net.ipv4.ip_forward=1' /etc/sysctl.conf || echo 'net.ipv4.ip_forward=1' >> /etc/sysctl.conf

iptables -t nat -C POSTROUTING -s ${IKEV2_SUBNET}.0/24 -o "${NET_IFACE}" -j MASQUERADE 2>/dev/null || \
  iptables -t nat -A POSTROUTING -s ${IKEV2_SUBNET}.0/24 -o "${NET_IFACE}" -j MASQUERADE
iptables -C FORWARD -s ${IKEV2_SUBNET}.0/24 -m comment --comment "vpnpanel-ikev2-forward-out" -j ACCEPT 2>/dev/null || \
  iptables -A FORWARD -s ${IKEV2_SUBNET}.0/24 -m comment --comment "vpnpanel-ikev2-forward-out" -j ACCEPT
iptables -C FORWARD -d ${IKEV2_SUBNET}.0/24 -m conntrack --ctstate ESTABLISHED,RELATED \
  -m comment --comment "vpnpanel-ikev2-forward-in" -j ACCEPT 2>/dev/null || \
  iptables -A FORWARD -d ${IKEV2_SUBNET}.0/24 -m conntrack --ctstate ESTABLISHED,RELATED \
    -m comment --comment "vpnpanel-ikev2-forward-in" -j ACCEPT
iptables -t mangle -C FORWARD -s ${IKEV2_SUBNET}.0/24 -p tcp --tcp-flags SYN,RST SYN \
  -j TCPMSS --clamp-mss-to-pmtu 2>/dev/null || \
  iptables -t mangle -A FORWARD -s ${IKEV2_SUBNET}.0/24 -p tcp --tcp-flags SYN,RST SYN \
    -j TCPMSS --clamp-mss-to-pmtu
netfilter-persistent save >/dev/null 2>&1 || true

echo ""
echo "=============================================================="
echo " IKEv2/IPsec (EAP-MSCHAPv2) infrastructure is up."
echo "   - Ports:    udp/500 (IKE) + udp/4500 (NAT-T) - shared with L2TP"
echo "   - Subnet:   ${IKEV2_SUBNET}.0/24"
echo "   - Auth:     username/password (EAP-MSCHAPv2) - managed by the panel"
echo "   - CA cert:  ${CA_CERT} (clients must trust this to connect without"
echo "               a warning; if you set up a real domain/SSL for IKEv2"
echo "               from Settings, clients trust it automatically instead)"
echo "   - Service:  systemctl status strongswan-starter"
if [ "$cert_changed" = "2" ]; then
  echo ""
  echo "[!] A new self-signed certificate was generated. Existing IKEv2"
  echo "    clients may need to re-trust ${CA_CERT}."
fi
if [ "$cert_changed" = "3" ]; then
  echo ""
  echo "[*] Domain certificate for IKEv2 was re-synced/repaired from"
  echo "    Let's Encrypt (${IKEV2_LEFTID}) and any stale self-signed CA"
  echo "    in cacerts was cleared - no client action needed."
fi
echo "=============================================================="
