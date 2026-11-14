import React from 'react'
import { Icon } from '../components/icons.jsx'
import TelegramDeliverySettings from '../components/TelegramDeliverySettings.jsx'
import { getRole } from '../permissions.js'
import { useLang } from '../i18n/dashboardLang.jsx'

const COPY = {
  fa: {
    title: 'اعلان‌ها و بکاپ تلگرام',
    subtitle: 'ارسال اعلان‌های پنل و بکاپ‌های زمان‌بندی‌شده با Bot API؛ مدیریت فروش و اشتراک‌ها در ربات مستقل VPN Control Center انجام می‌شود.',
    badge: 'اعلان و پشتیبان‌گیری',
    restricted: 'این بخش فقط برای سوپرادمین قابل دسترسی است.',
  },
  en: {
    title: 'Telegram Notifications & Backups',
    subtitle: 'Send panel notifications and scheduled backups through the Telegram Bot API. Sales and subscription management run in the independent VPN Control Center bot.',
    badge: 'Notifications & backups',
    restricted: 'This section is available to superadmins only.',
  },
}

export default function TelegramBot() {
  const { lang, dir } = useLang()
  const words = COPY[lang] || COPY.fa
  const superadmin = getRole() === 'superadmin'

  return (
    <div className="space-y-6" dir={dir} data-feature="telegram-notifications-backups">
      <header>
        <div className="mb-2 inline-flex items-center gap-2 rounded-full border border-signal/35 bg-signal/10 px-3 py-1 text-[10px] font-extrabold text-signal">
          <Icon name="telegram" size={14} />
          {words.badge}
        </div>
        <h1 className="page-heading">{words.title}</h1>
        <p className="page-subtitle max-w-3xl">{words.subtitle}</p>
      </header>
      {superadmin ? (
        <TelegramDeliverySettings />
      ) : (
        <div className="rounded-xl border border-border bg-surface/70 p-5 text-sm text-muted">
          {words.restricted}
        </div>
      )}
    </div>
  )
}
