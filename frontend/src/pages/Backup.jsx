import React, { createContext, useContext, useEffect, useRef, useState } from 'react'
import * as ReactDOM from 'react-dom'
import api from '../api'
import { useUI } from '../components/ui/UIProvider.jsx'
import { markUpdateSuccess } from '../updateNotice.js'
import { useLang as useGlobalLang } from '../i18n/dashboardLang.jsx'
import SectionTabs from '../components/SectionTabs.jsx'

// -----------------------------------------------------------------------
// زبان صفحه‌ی بکاپ: این صفحه (شامل مودال آپدیت) از همان کلید مشترک زبان
// پنل (dashboardLang) استفاده می‌کند تا با بقیه‌ی صفحات هماهنگ بماند -
// سوییچ زبان در هر صفحه، در همه‌ی صفحات دیگر هم اعمال می‌شود.
// -----------------------------------------------------------------------

const STRINGS = {
  fa: {
    pageTitle: 'بکاپ',
    pageSubtitle: 'بکاپ کامل کاربران، ادمین‌ها، پروتکل‌ها، گواهی‌ها، نودها و تنظیمات محلی هر نود',
    tabsAria: 'بخش‌های بکاپ و به‌روزرسانی',
    tabBackups: 'بکاپ‌ها',
    tabUpdates: 'به‌روزرسانی',
    tabTelegram: 'تلگرام',

    backupHeading: 'بکاپ و وارد کردن',
    exportErr: 'خطا در دریافت فایل بکاپ',
    exportDegraded: 'فایل ذخیره شد، اما بکاپ کامل نیست؛ حداقل یکی از نودها یا فایل‌های ضروری در دسترس نبود. هشدارهای فایل را بررسی کنید و تا رفع مشکل از آن برای بازیابی دقیق استفاده نکنید.',
    importConfirmTitle: 'وارد کردن بکاپ',
    importConfirmMsg:
      'این عملیات «بازیابی دقیق» است: اطلاعات فعلی این پنل با محتوای بکاپ کامل جایگزین می‌شود؛ ' +
      'ادمین‌ها و رمزهای ورود، کاربران و رمزها، حجم مصرفی و محدودیت‌ها، پروتکل‌های انتخاب‌شده، ' +
      'تنظیمات و گواهی‌های پروتکل‌ها، برندینگ و بکاپ محلی نودها عیناً برمی‌گردند. ' +
      'سرویس‌های VPN ری‌استارت می‌شوند و ورود فعلی شما ممکن است پایان یابد. فقط روی فایل بکاپ کامل ادامه دهید.',
    importConfirmBtn: 'وارد کردن',
    exportingBusy: 'در حال ساخت فایل بکاپ...',
    importingBusy: 'در حال وارد کردن بکاپ و همگام‌سازی با سرویس‌های VPN...',
    importSuccess: 'بکاپ وارد شد',
    importErr: 'فایل بکاپ نامعتبر است یا وارد کردن آن ناموفق بود',
    resAdmins: 'ادمین‌ها:',
    resUsers: 'یوزرهای VPN:',
    resBannedIps: 'آی‌پی‌های مسدود:',
    resAdded: 'اضافه شد،',
    resSkipped: 'تکراری رد شد',
    resPki: 'PKI و سرتیفیکیت‌های OpenVPN:',
    resPkiRestored: 'بازیابی شد (فایل‌های .ovpn قدیمی کار می‌کنند)',
    resNotInBackup: 'در این بکاپ نبود',
    resPsk: 'رمز مشترک L2TP/IPsec:',
    resRestored: 'بازیابی شد',
    resSettings: 'تنظیمات پنل:',
    resValuesRestored: 'مقدار بازیابی شد',
    resExtraPorts: 'پورت‌های اضافه‌ی OpenVPN:',
    resRuntime: 'فایل‌های دقیق تنظیمات/گواهی‌ها:',
    resRuntimeFiles: 'فایل بازیابی شد',
    resNodes: 'بکاپ محلی نودها:',
    resNodesRestored: 'نود بازیابی شد،',
    resNodesFailed: 'ناموفق',
    resExactMode: 'حالت بازیابی:',
    resExactReplace: 'جایگزینی دقیق کل پنل',
    btnExportBasic: 'بکاپ اطلاعاتی (بدون تنظیمات)',
    btnExportBasicBusy: 'در حال ساخت فایل...',
    btnExportFull: 'بکاپ کامل پنل و نودها',
    btnImport: 'وارد کردن فایل بکاپ',
    btnImportBusy: 'در حال وارد کردن...',

    updateHeading: 'آپدیت پنل',
    checkingLatest: 'در حال بررسی آخرین نسخه...',
    checkErrDefault: 'بررسی آپدیت ناموفق بود',
    currentVersion: 'نسخه‌ی فعلی این سرور:',
    unknown: 'نامشخص',
    latestVersion: 'آخرین نسخه‌ی موجود:',
    newVersionAvailable: 'یک نسخه‌ی جدید موجود است',
    upToDate: 'پنل شما به‌روز است',
    btnRecheck: 'بررسی مجدد',
    btnUpdating: 'در حال آپدیت...',
    btnAlreadyLatest: 'همین الان این نسخه نصب است',
    btnGetUpdate: 'دریافت و اعمال آپدیت',

    updateModalTitle: 'آپدیت پنل',
    updateModalConfirmMsg:
      'آخرین نسخه‌ی پنل دانلود و جایگزین نسخه‌ی فعلی می‌شود. کاربرها، دیتابیس، سرتیفیکیت‌های OpenVPN، ' +
      'رمز مشترک L2TP/IPsec و تمام تنظیمات دست‌نخورده می‌مانند. در حین آپدیت (چند دقیقه)، پنل ممکن است ' +
      'چند لحظه در دسترس نباشد.',
    updateModalCurrent: 'نسخه‌ی فعلی:',
    updateModalNew: 'نسخه‌ی جدید:',
    updateModalStart: 'شروع آپدیت',
    updateModalCancel: 'انصراف',
    updateModalRunningNote: 'لطفاً این پنجره را نبندید و از این صفحه خارج نشوید تا آپدیت تمام شود.',
    updateModalSuccessTitle: 'آپدیت با موفقیت انجام شد',
    updateModalSuccessMsg: 'پنل به آخرین نسخه به‌روزرسانی شد.',
    updateModalNotesTitle: 'توضیحات این نسخه',
    updateModalDone: 'تمام',
    updateModalFailedTitle: 'آپدیت ناموفق بود',
    updateLogDetails: 'جزئیات آخرین خطا',
    updateModalClose: 'بستن',
    updateModalDontShowAgain: 'دیگه این خطا را نشان نده',
    startErrDefault: 'شروع آپدیت ناموفق بود',
    timeoutErr: 'زمان زیادی از شروع آپدیت گذشته و وضعیت مشخص نیست. صفحه را رفرش کنید یا از طریق SSH وضعیت را بررسی کنید.',
    startingUpdate: 'در حال شروع آپدیت...',
    updatingDefault: 'در حال آپدیت...',
    updateApiRestarting: 'سرویس پنل موقتاً در حال راه‌اندازی مجدد است؛ آپدیت در پس‌زمینه ادامه دارد...',
    updateTerminalTitle: 'VPN PANEL UPDATE CMD — /opt/vpn-panel/update.log',
    updateTerminalSubtitle: 'مراحل و خروجی واقعی آپدیت سرور',
    updateTerminalReady: '$ آماده برای شروع آپدیت...\n$ با زدن «شروع آپدیت» خروجی زنده اینجا نمایش داده می‌شود.',
    updateCopyLogBtn: 'کپی لاگ',
    updateCopyErrorBtn: 'کپی ارور',
    updateCopiedBtn: 'کپی شد ✓',
    updateCopyFailed: 'کپی لاگ ناموفق بود',

    enabled: 'فعال',
    disabled: 'غیرفعال',

    telegramHeading: 'اتصال به تلگرام',
    botTokenLabel: 'توکن ربات (Bot Token)',
    logChannelHeading: 'تنظیم کانال لاگ',
    testLogBtn: 'ارسال پیام تست به کانال لاگ',
    connLogHeading: 'لاگ اتصال/قطع‌اتصال کاربران',
    testConnLogBtn: 'ارسال پیام تست به کانال اتصالات',
    backupChannelHeading: 'تنظیم کانال بکاپ',
    backupIntervalLabel: 'تعیین تایم برای ارسال بکاپ (هر چند ساعت یک‌بار)',
    backupServerPasswordLabel: 'رمز سرور در پیام بکاپ',
    backupServerPasswordPlaceholder: 'یک‌بار وارد کنید؛ خالی بماند یعنی بدون تغییر',
    backupServerPasswordHint: 'لینوکس رمز فعلی SSH را قابل بازیابی نمی‌کند؛ این مقدار رمزگذاری‌شده ذخیره و فقط همراه بکاپ تلگرام ارسال می‌شود.',
    backupServerPasswordConfigured: 'رمز سرور ذخیره شده است.',
    backupServerPasswordClear: 'پاک‌کردن رمز ذخیره‌شده',
    lastSent: 'آخرین ارسال:',
    sendBackupNowBtn: 'ارسال بکاپ همین الان',
    saveTelegramBtn: 'ذخیره‌ی تنظیمات تلگرام',
    savingBtn: 'در حال ذخیره...',
    savingBusy: 'در حال ذخیره‌ی تنظیمات تلگرام...',
    telegramSaved: 'تنظیمات تلگرام ذخیره شد',
    telegramSaveErr: 'خطا در ذخیره‌ی تنظیمات',
    testMsgBusy: 'در حال ارسال پیام تست...',
    testLogSent: 'پیام تست به کانال لاگ ارسال شد',
    testConnLogSent: 'پیام تست به کانال اتصالات ارسال شد',
    testMsgErr: 'ارسال پیام تست ناموفق بود',
    sendBackupBusy: 'در حال ساخت و ارسال فایل بکاپ به تلگرام...',
    backupSentToTelegram: 'فایل بکاپ به کانال بکاپ ارسال شد',
    backupSendErr: 'ارسال بکاپ ناموفق بود',
    loadingTelegram: 'در حال بارگذاری تنظیمات تلگرام...',
    logChatPlaceholder: '-1001234567890 یا @my_log_channel',
    connLogChatPlaceholder: 'خالی = همان کانال لاگ اصلی',
    backupChatPlaceholder: '-1001234567890 یا @my_backup_channel',
    controlHeading: 'ربات کنترل کامل پنل',
    controlChatLabel: 'آیدی چت کنترل',
    controlChatPlaceholder: 'مثلاً 123456789 یا -1001234567890',
    controlAllowedUsersLabel: 'شناسه عددی مدیران مجاز ربات',
    controlAllowedUsersPlaceholder: 'مثلاً 123456789,987654321',
    controlHint: 'در چت خصوصی، اگر این فیلد خالی باشد فقط صاحب همان چت مجاز است. برای گروه یا کانال می‌توانید شناسه عددی مدیران را وارد کنید؛ اگر خالی باشد فقط ادمین‌های همان گروه اجازه کنترل دارند. ربات می‌تواند کاربر بسازد و مدیریت کند، آی‌پی را بن/رفع‌بن کند، پروتکل‌ها را کنترل کند، وضعیت نودها را ببیند و بکاپ فوری بفرستد.',
    testControlBtn: 'ارسال پیام تست ربات کنترل',
    testControlSent: 'پیام تست ربات کنترل ارسال شد',
  },

  en: {
    pageTitle: 'Backup',
    pageSubtitle: 'Full backup of users, admins, protocols, certificates, nodes, and each node’s local settings',
    tabsAria: 'Backup and update sections',
    tabBackups: 'Backups',
    tabUpdates: 'Updates',
    tabTelegram: 'Telegram',

    backupHeading: 'Backup & Import',
    exportErr: 'Failed to get the backup file',
    exportDegraded: 'The file was saved, but the full backup is degraded because a node or required file was unavailable. Review its warnings and do not use it for exact restore until the issue is fixed.',
    importConfirmTitle: 'Import Backup',
    importConfirmMsg:
      'This is an exact disaster restore: the current panel state will be replaced by the full backup. ' +
      'Admins and login passwords, VPN users and passwords, usage and limits, selected protocols, protocol settings and certificates, ' +
      'branding, and each node’s local backup will be restored. VPN services will restart and your current login may end. ' +
      'Continue only with a full backup.',
    importConfirmBtn: 'Import',
    exportingBusy: 'Building backup file...',
    importingBusy: 'Importing backup and syncing with VPN services...',
    importSuccess: 'Backup imported',
    importErr: 'The backup file is invalid or import failed',
    resAdmins: 'Admins:',
    resUsers: 'VPN users:',
    resBannedIps: 'Banned IPs:',
    resAdded: 'added,',
    resSkipped: 'duplicates skipped',
    resPki: 'PKI & OpenVPN certificates:',
    resPkiRestored: 'Restored (old .ovpn files still work)',
    resNotInBackup: 'Not included in this backup',
    resPsk: 'L2TP/IPsec shared secret:',
    resRestored: 'Restored',
    resSettings: 'Panel settings:',
    resValuesRestored: 'values restored',
    resExtraPorts: 'Extra OpenVPN ports:',
    resRuntime: 'Exact config/certificate files:',
    resRuntimeFiles: 'files restored',
    resNodes: 'Node-local backups:',
    resNodesRestored: 'nodes restored,',
    resNodesFailed: 'failed',
    resExactMode: 'Restore mode:',
    resExactReplace: 'Exact full replacement',
    btnExportBasic: 'Data backup (without settings)',
    btnExportBasicBusy: 'Building file...',
    btnExportFull: 'Full panel & nodes backup',
    btnImport: 'Import backup file',
    btnImportBusy: 'Importing...',

    updateHeading: 'Panel Update',
    checkingLatest: 'Checking for the latest version...',
    checkErrDefault: 'Failed to check for updates',
    currentVersion: "This server's current version:",
    unknown: 'Unknown',
    latestVersion: 'Latest available version:',
    newVersionAvailable: 'A new version is available',
    upToDate: 'Your panel is up to date',
    btnRecheck: 'Check again',
    btnUpdating: 'Updating...',
    btnAlreadyLatest: 'This version is already installed',
    btnGetUpdate: 'Get & apply update',

    updateModalTitle: 'Panel Update',
    updateModalConfirmMsg:
      'The latest panel version will be downloaded and will replace the current one. Users, the database, ' +
      'OpenVPN certificates, the L2TP/IPsec shared secret, and all settings remain untouched. The panel may be ' +
      'briefly unavailable during the update (a few minutes).',
    updateModalCurrent: 'Current version:',
    updateModalNew: 'New version:',
    updateModalStart: 'Start update',
    updateModalCancel: 'Cancel',
    updateModalRunningNote: "Please don't close this window or leave this page until the update finishes.",
    updateModalSuccessTitle: 'Update completed successfully',
    updateModalSuccessMsg: 'The panel has been updated to the latest version.',
    updateModalNotesTitle: "What's new in this version",
    updateModalDone: 'Done',
    updateModalFailedTitle: 'Update failed',
    updateLogDetails: 'Last error details',
    updateModalClose: 'Close',
    updateModalDontShowAgain: "Don't show this error again",
    startErrDefault: 'Failed to start the update',
    timeoutErr: 'It has been a while since the update started and the status is unclear. Refresh the page or check the status via SSH.',
    startingUpdate: 'Starting update...',
    updatingDefault: 'Updating...',
    updateApiRestarting: 'The panel service is restarting temporarily; the update is still running in the background...',
    updateTerminalTitle: 'VPN PANEL UPDATE CMD — /opt/vpn-panel/update.log',
    updateTerminalSubtitle: 'Live server update stages and output',
    updateTerminalReady: '$ Ready to start the update...\n$ Click “Start update” to stream the live output here.',
    updateCopyLogBtn: 'Copy log',
    updateCopyErrorBtn: 'Copy error',
    updateCopiedBtn: 'Copied ✓',
    updateCopyFailed: 'Failed to copy update log',

    enabled: 'Enabled',
    disabled: 'Disabled',

    telegramHeading: 'Telegram Connection',
    botTokenLabel: 'Bot Token',
    logChannelHeading: 'Log channel setup',
    testLogBtn: 'Send test message to log channel',
    connLogHeading: 'User connect/disconnect log',
    testConnLogBtn: 'Send test message to connections channel',
    backupChannelHeading: 'Backup channel setup',
    backupIntervalLabel: 'Backup send interval (every N hours)',
    backupServerPasswordLabel: 'Server password in backup message',
    backupServerPasswordPlaceholder: 'Enter once; leave blank to keep the saved value',
    backupServerPasswordHint: 'Linux cannot recover the current SSH password. This value is encrypted at rest and sent only with Telegram backups.',
    backupServerPasswordConfigured: 'A server password is saved.',
    backupServerPasswordClear: 'Clear saved password',
    lastSent: 'Last sent:',
    sendBackupNowBtn: 'Send backup now',
    saveTelegramBtn: 'Save Telegram settings',
    savingBtn: 'Saving...',
    savingBusy: 'Saving Telegram settings...',
    telegramSaved: 'Telegram settings saved',
    telegramSaveErr: 'Failed to save settings',
    testMsgBusy: 'Sending test message...',
    testLogSent: 'Test message sent to the log channel',
    testConnLogSent: 'Test message sent to the connections channel',
    testMsgErr: 'Failed to send test message',
    sendBackupBusy: 'Building and sending the backup file to Telegram...',
    backupSentToTelegram: 'Backup file sent to the backup channel',
    backupSendErr: 'Failed to send backup',
    loadingTelegram: 'Loading Telegram settings...',
    logChatPlaceholder: '-1001234567890 or @my_log_channel',
    connLogChatPlaceholder: 'Empty = same as the main log channel',
    backupChatPlaceholder: '-1001234567890 or @my_backup_channel',
    controlHeading: 'Full Panel Control Bot',
    controlChatLabel: 'Control chat ID',
    controlChatPlaceholder: 'e.g. 123456789 or -1001234567890',
    controlAllowedUsersLabel: 'Allowed Telegram user IDs',
    controlAllowedUsersPlaceholder: 'e.g. 123456789,987654321',
    controlHint: 'In a private chat, leaving this empty authorizes only that chat owner. In groups you may list numeric Telegram user IDs; when empty, only that group’s Telegram administrators are allowed. The bot can manage users, bans, protocols, nodes and backups.',
    testControlBtn: 'Send control bot test',
    testControlSent: 'Control bot test sent',
  },
}

const LangContext = createContext({ lang: 'fa', dir: 'rtl', t: (k) => STRINGS.fa[k] ?? k })
function useLang() {
  return useContext(LangContext)
}

function downloadBlob(res) {
  const disposition = res.headers['content-disposition'] || ''
  const match = disposition.match(/filename="?([^"]+)"?/)
  const filename = match ? match[1] : `vpn-panel-backup-${Date.now()}.json`

  const url = window.URL.createObjectURL(new Blob([res.data], { type: 'application/json' }))
  const a = document.createElement('a')
  a.href = url
  a.download = filename
  document.body.appendChild(a)
  a.click()
  a.remove()
  window.URL.revokeObjectURL(url)
}


function BackupCard() {
  const { lang, dir, t } = useLang()
  const { confirm, withBusy, notify } = useUI()
  const fileInputRef = useRef(null)
  const [exportingBasic, setExportingBasic] = useState(false)
  const [exportingFull, setExportingFull] = useState(false)
  const [importing, setImporting] = useState(false)
  const [error, setError] = useState('')
  const [result, setResult] = useState(null)

  const doExport = async (includeSettings) => {
    setError('')
    const setBusy = includeSettings ? setExportingFull : setExportingBasic
    setBusy(true)
    try {
      const res = await withBusy(t('exportingBusy'), async () => {
        const { data: started } = await api.post('/backup/export/start', null, {
          params: { include_settings: includeSettings },
        })
        const jobId = started?.job_id
        if (!jobId) throw new Error('backup job id missing')
        const deadline = Date.now() + 30 * 60 * 1000
        while (Date.now() < deadline) {
          await new Promise((resolve) => window.setTimeout(resolve, 1200))
          const { data: status } = await api.get(`/backup/export/status/${jobId}`, {
            params: { _: Date.now() },
            skipInstantCache: true,
          })
          if (status?.state === 'failed') throw new Error(status?.message || 'backup failed')
          if (status?.state === 'success') {
            return api.get(`/backup/export/download/${jobId}`, {
              responseType: 'blob',
              timeout: 0,
              skipInstantCache: true,
            })
          }
        }
        throw new Error('backup generation timeout')
      }, { dir })
      downloadBlob(res)
      if (includeSettings && String(res.headers?.['x-backup-complete'] || '').toLowerCase() === 'false') {
        setError(t('exportDegraded'))
      }
    } catch (err) {
      setError(err?.response?.data?.detail || err?.message || t('exportErr'))
    } finally {
      setBusy(false)
    }
  }

  const pickFile = () => {
    setError('')
    setResult(null)
    fileInputRef.current?.click()
  }

  const onFileChosen = async (e) => {
    const file = e.target.files?.[0]
    e.target.value = '' // برای اینکه انتخاب دوباره‌ی همان فایل هم بعداً کار کند
    if (!file) return

    const ok = await confirm({
      title: t('importConfirmTitle'),
      message: t('importConfirmMsg'),
      confirmLabel: t('importConfirmBtn'),
      dir,
    })
    if (!ok) return

    setImporting(true)
    setError('')
    setResult(null)
    try {
      const formData = new FormData()
      formData.append('file', file)
      const { data } = await withBusy(t('importingBusy'), () =>
        api.post('/backup/import', formData, {
          params: { restore_mode: 'replace', restore_nodes: true },
          headers: { 'Content-Type': 'multipart/form-data' },
        }), { dir }
      )
      setResult(data)
      notify?.({ type: 'success', message: t('importSuccess'), dir })
    } catch (err) {
      setError(err.response?.data?.detail || t('importErr'))
    } finally {
      setImporting(false)
    }
  }

  const allWarnings = [...(result?.cert_errors || []), ...(result?.warnings || [])]

  return (
    <div className="panel-section p-5 space-y-4">
      <div>
        <div className="text-sm font-bold text-ink">{t('backupHeading')}</div>
      </div>

      {error && <div className="bg-danger/10 border border-danger/30 text-danger text-sm rounded-lg px-3 py-2">{error}</div>}

      {result && (
        <div className="bg-surface2 border border-border rounded-lg p-3 text-xs text-ink leading-6 space-y-1">
          {result.restore_mode === 'replace' && (
            <div>{t('resExactMode')} <span className="text-signal font-bold">{t('resExactReplace')}</span></div>
          )}
          <div>{t('resAdmins')} <span className="font-data text-signal">{result.admins_imported}</span> {t('resAdded')} <span className="font-data text-muted">{result.admins_skipped}</span> {t('resSkipped')}</div>
          <div>{t('resUsers')} <span className="font-data text-signal">{result.users_imported}</span> {t('resAdded')} <span className="font-data text-muted">{result.users_skipped}</span> {t('resSkipped')}</div>
          <div>{t('resBannedIps')} <span className="font-data text-signal">{result.banned_ips_imported}</span> {t('resAdded')} <span className="font-data text-muted">{result.banned_ips_skipped}</span> {t('resSkipped')}</div>
          <div>
            {t('resPki')}{' '}
            {result.pki_restored
              ? <span className="text-signal font-bold">{t('resPkiRestored')}</span>
              : <span className="text-muted">{t('resNotInBackup')}</span>}
          </div>
          <div>
            {t('resPsk')}{' '}
            {result.ipsec_psk_restored
              ? <span className="text-signal font-bold">{t('resRestored')}</span>
              : <span className="text-muted">{t('resNotInBackup')}</span>}
          </div>
          {typeof result.settings_imported === 'number' && result.settings_imported > 0 && (
            <>
              <div>{t('resSettings')} <span className="font-data text-signal">{result.settings_imported}</span> {t('resValuesRestored')}</div>
              <div>{t('resExtraPorts')} <span className="font-data text-signal">{result.openvpn_ports_imported}</span> {t('resAdded')} <span className="font-data text-muted">{result.openvpn_ports_skipped}</span> {t('resSkipped')}</div>
            </>
          )}
          {typeof result.runtime_files_restored === 'number' && (
            <div>{t('resRuntime')} <span className="font-data text-signal">{result.runtime_files_restored}</span> {t('resRuntimeFiles')}</div>
          )}
          {typeof result.nodes_restored === 'number' && (result.nodes_restored > 0 || result.nodes_restore_failed > 0) && (
            <div>{t('resNodes')} <span className="font-data text-signal">{result.nodes_restored}</span> {t('resNodesRestored')} <span className="font-data text-danger">{result.nodes_restore_failed || 0}</span> {t('resNodesFailed')}</div>
          )}
          {allWarnings.length > 0 && (
            <div className="text-danger pt-1">
              {allWarnings.map((msg, i) => (<div key={i}>⚠ {msg}</div>))}
            </div>
          )}
        </div>
      )}

      <div className="flex flex-col gap-2">
        <div className="flex flex-col sm:flex-row gap-2">
          <button
            onClick={() => doExport(false)}
            disabled={exportingBasic || exportingFull}
            className="flex-1 bg-signal text-bg font-bold rounded-lg py-2.5 text-sm hover:opacity-90 disabled:opacity-50"
          >
            {exportingBasic ? t('btnExportBasicBusy') : t('btnExportBasic')}
          </button>
          <button
            onClick={() => doExport(true)}
            disabled={exportingBasic || exportingFull}
            className="flex-1 bg-surface2 border border-border text-ink font-bold rounded-lg py-2.5 text-sm hover:bg-surface disabled:opacity-50"
          >
            {exportingFull ? t('btnExportBasicBusy') : t('btnExportFull')}
          </button>
        </div>
        <button
          onClick={pickFile}
          disabled={importing}
          className="w-full bg-surface2 border border-border text-ink font-bold rounded-lg py-2.5 text-sm hover:bg-surface disabled:opacity-50"
        >
          {importing ? t('btnImportBusy') : t('btnImport')}
        </button>
        <input ref={fileInputRef} type="file" accept="application/json,.json,.gz,application/gzip" className="hidden" onChange={onFileChosen} />
      </div>
    </div>
  )
}

// چند بار پشت‌سرهم پولینگ وضعیت آپدیت اجازه داریم قبل از این‌که تسلیم شویم و
// به کاربر بگوییم دستی چک کند. هر تیک ۱.۵ ثانیه است، پس ۴۰۰ تیک ≈ ۱۰ دقیقه -
// بیشتر از timeout شش‌دقیقه‌ای مرحله اصلی آپدیت.
const UPDATE_POLL_MS = 1500
const UPDATE_MAX_TICKS = 400
const UPDATE_LOCK_ID = 'vpnpanel-update-interaction-lock'

// -----------------------------------------------------------------------
// پنجره‌ی آپدیت: دقیقاً مثل مودال ساخت/ویرایش کاربر (overlay تیره + کارت
// وسط صفحه) اما تا وقتی آپدیت در حال اجراست نه با کلیک روی پس‌زمینه و نه
// با دکمه‌ی × بسته می‌شود. فقط وقتی آپدیت تمام (موفق) شد دکمه‌ی Done ظاهر
// می‌شود؛ با زدن آن صفحه رفرش کامل شده و به داشبورد برمی‌گردد. اگر آپدیت
// شکست بخورد، اجازه‌ی بستن مودال داده می‌شود تا کاربر گیر نیفتد.
// -----------------------------------------------------------------------
function UpdateModal({ info, running, progress, percent, updateError, onStart, onClose, onDone, onDismissError, onCopyLog }) {
  const { dir, t } = useLang()
  const terminalRef = useRef(null)
  const [copying, setCopying] = useState(false)
  const [copied, setCopied] = useState(false)
  const finishedOk = !running && progress?.state === 'success'
  const failed = !running && !!updateError
  const canClose = !running
  const consoleText = progress?.log_tail || (!running && !failed && !finishedOk ? t('updateTerminalReady') : '')

  useEffect(() => {
    if (terminalRef.current) terminalRef.current.scrollTop = terminalRef.current.scrollHeight
  }, [consoleText])

  // Render the update flow directly under <body>, outside Layout's stacking
  // contexts. During an update we use three independent protections so the
  // sidebar/header/content cannot be activated even on browsers with partial
  // `inert` support: root inertness, capture-phase event blocking, and a fixed
  // interaction shield directly below the update dialog.
  useEffect(() => {
    const html = document.documentElement
    const body = document.body
    const root = document.getElementById('root')
    const previousOverflow = body.style.overflow
    const previousRootPointerEvents = root?.style.pointerEvents || ''
    const previousAriaHidden = root?.getAttribute('aria-hidden')
    const previousInert = root ? Boolean(root.inert) : false
    const listenerOptions = { capture: true, passive: false }
    body.style.overflow = 'hidden'

    let interactionLock = document.getElementById(UPDATE_LOCK_ID)
    if (running) {
      html.classList.add('vpnpanel-update-locked')
      body.classList.add('vpnpanel-blocking-modal-open')
      if (root) {
        root.inert = true
        root.style.pointerEvents = 'none'
        root.setAttribute('aria-hidden', 'true')
      }
      if (!interactionLock) {
        interactionLock = document.createElement('div')
        interactionLock.id = UPDATE_LOCK_ID
        interactionLock.setAttribute('aria-hidden', 'true')
        interactionLock.setAttribute('role', 'presentation')
        document.body.appendChild(interactionLock)
      }
    }

    const isInsideUpdate = (target) => {
      const overlay = document.getElementById('vpnpanel-update-flow')
      return Boolean(overlay && target instanceof Node && overlay.contains(target))
    }
    const blockOutside = (event) => {
      if (!running || isInsideUpdate(event.target)) return
      if (event.cancelable) event.preventDefault()
      event.stopPropagation()
      if (typeof event.stopImmediatePropagation === 'function') event.stopImmediatePropagation()
    }
    const onKeyDown = (event) => {
      if (event.key === 'Escape' && canClose) {
        event.preventDefault()
        onClose()
        return
      }
      blockOutside(event)
    }
    const onFocusIn = (event) => {
      if (!running || isInsideUpdate(event.target)) return
      blockOutside(event)
      const overlay = document.getElementById('vpnpanel-update-flow')
      const focusTarget = overlay?.querySelector('button:not([disabled]), [tabindex]:not([tabindex="-1"])') || overlay
      focusTarget?.focus?.({ preventScroll: true })
    }

    const blockedEvents = ['pointerdown', 'mousedown', 'touchstart', 'touchmove', 'click', 'dblclick', 'contextmenu', 'wheel', 'dragstart', 'drop', 'submit']
    blockedEvents.forEach((name) => document.addEventListener(name, blockOutside, listenerOptions))
    document.addEventListener('keydown', onKeyDown, true)
    document.addEventListener('focusin', onFocusIn, true)

    return () => {
      blockedEvents.forEach((name) => document.removeEventListener(name, blockOutside, listenerOptions))
      document.removeEventListener('keydown', onKeyDown, true)
      document.removeEventListener('focusin', onFocusIn, true)
      document.getElementById(UPDATE_LOCK_ID)?.remove()
      html.classList.remove('vpnpanel-update-locked')
      body.classList.remove('vpnpanel-blocking-modal-open')
      body.style.overflow = previousOverflow
      if (root) {
        root.inert = previousInert
        root.style.pointerEvents = previousRootPointerEvents
        if (previousAriaHidden === null) root.removeAttribute('aria-hidden')
        else root.setAttribute('aria-hidden', previousAriaHidden)
      }
    }
  }, [running, canClose, onClose])

  const copyConsole = async () => {
    setCopying(true)
    setCopied(false)
    try {
      await onCopyLog(failed)
      setCopied(true)
      window.setTimeout(() => setCopied(false), 1800)
    } catch {
      // onCopyLog already shows a user-facing error toast.
    } finally {
      setCopying(false)
    }
  }

  return ReactDOM.createPortal(
    <div
      id="vpnpanel-update-flow"
      className="glass-terminal-overlay modal-viewport fixed inset-0 p-2 sm:p-5"
      style={{ zIndex: 2147483647, pointerEvents: 'auto' }}
      tabIndex={-1}
      role="dialog"
      aria-modal="true"
      aria-label={t('updateModalTitle')}
      onMouseDown={(event) => {
        if (event.target === event.currentTarget && canClose) onClose()
      }}
    >
      <div
        dir={dir}
        className="glass-terminal-modal modal-dialog-shell rounded-2xl w-full max-w-5xl overflow-hidden flex flex-col"
        onMouseDown={(event) => event.stopPropagation()}
      >
        <div className="modal-sticky-header">
          <div>
            <h2 className="font-bold text-sm">{t('updateModalTitle')}</h2>
            <p className="text-[11px] text-muted mt-1">{progress?.message || t('updateTerminalSubtitle')}</p>
          </div>
          {canClose && <button type="button" onClick={onClose} className="modal-close-button">✕</button>}
        </div>

        <div className="modal-scroll-body p-4 sm:p-5 space-y-4">
          {!running && !finishedOk && !failed && (
            <>
              <p className="text-xs text-muted leading-relaxed">{t('updateModalConfirmMsg')}</p>
              <div className="grid grid-cols-1 sm:grid-cols-2 gap-2 text-xs">
                <div className="bg-surface2 border border-border rounded-xl p-3">{t('updateModalCurrent')} <span className="font-data text-ink">{info?.current_version || t('unknown')}</span></div>
                <div className="bg-signal/5 border border-signal/25 rounded-xl p-3">{t('updateModalNew')} <span className="font-data text-signal">{info?.latest_version || t('unknown')}</span></div>
              </div>
            </>
          )}

          {(running || finishedOk || failed) && (
            <div className="space-y-2">
              <div className="flex items-center justify-between text-xs">
                <span className={failed ? 'text-danger font-bold' : finishedOk ? 'text-signal font-bold' : 'text-muted'}>
                  {failed ? t('updateModalFailedTitle') : finishedOk ? t('updateModalSuccessTitle') : (progress?.message || t('updatingDefault'))}
                </span>
                <span className="font-data text-ink">{Math.max(0, Math.min(100, percent))}%</span>
              </div>
              <div className="w-full h-2.5 bg-surface2 border border-border rounded-full overflow-hidden">
                <div
                  className={`h-full transition-all duration-500 ${failed ? 'bg-danger' : 'bg-signal'}`}
                  style={{ width: `${Math.max(running ? 3 : 0, Math.min(100, percent))}%` }}
                />
              </div>
            </div>
          )}

          <div className="glass-terminal-frame rounded-xl overflow-hidden" dir="ltr">
            <div className="glass-terminal-bar h-10 px-3 flex items-center justify-between">
              <div className="flex items-center gap-1.5">
                <span className="w-2.5 h-2.5 rounded-full bg-danger/80" />
                <span className="w-2.5 h-2.5 rounded-full bg-amber/80" />
                <span className="w-2.5 h-2.5 rounded-full bg-signal/100" />
                <span className="ms-2 text-[10px] text-white/45 font-mono">{t('updateTerminalTitle')}</span>
              </div>
              {(running || failed || finishedOk) && (
                <button
                  type="button"
                  onClick={copyConsole}
                  disabled={copying}
                  className="rounded-lg border border-white/10 bg-white/5 px-2.5 py-1 text-[10px] font-bold text-white/70 hover:bg-white/10 disabled:opacity-50"
                >
                  {copied ? t('updateCopiedBtn') : copying ? '...' : failed ? t('updateCopyErrorBtn') : t('updateCopyLogBtn')}
                </button>
              )}
            </div>
            <pre
              ref={terminalRef}
              className={`glass-terminal-screen h-[340px] sm:h-[430px] overflow-auto whitespace-pre-wrap break-words p-4 font-mono ${failed ? 'glass-terminal-screen--error' : ''}`}
            >{consoleText || '$ '}</pre>
          </div>

          {running && (
            <div className="flex items-center gap-2 bg-amber/10 border border-amber/30 text-amber rounded-xl px-3 py-2 text-xs leading-relaxed">
              <span className="w-4 h-4 rounded-full border-2 border-amber/40 border-t-amber animate-spin shrink-0" />
              <span>{t('updateModalRunningNote')}</span>
            </div>
          )}

          {failed && (
            <div className="rounded-xl border border-danger/30 bg-danger/10 p-3 text-xs text-danger leading-relaxed" dir={dir}>
              {updateError}
            </div>
          )}

          {finishedOk && info?.notes && (
            <div className="bg-surface2 border border-border rounded-xl p-3 space-y-1">
              <div className="text-[11px] font-bold text-muted">{t('updateModalNotesTitle')}</div>
              <div className="text-xs text-ink leading-relaxed whitespace-pre-line">{info.notes}</div>
            </div>
          )}

          {!running && !finishedOk && !failed && (
            <div className="modal-actions pt-1">
              <button onClick={onStart} className="btn-primary">
                {t('updateModalStart')}
              </button>
              <button onClick={onClose} className="btn-secondary">
                {t('updateModalCancel')}
              </button>
            </div>
          )}

          {finishedOk && (
            <button onClick={onDone} className="w-full bg-signal text-bg font-bold rounded-xl py-2.5 text-sm hover:opacity-90">
              {t('updateModalDone')}
            </button>
          )}

          {failed && (
            <div className="grid grid-cols-1 gap-2 sm:grid-cols-3">
              <button onClick={copyConsole} className="w-full bg-signal text-bg font-bold rounded-xl py-2.5 text-sm hover:opacity-90">
                {copied ? t('updateCopiedBtn') : t('updateCopyErrorBtn')}
              </button>
              <button onClick={onClose} className="w-full bg-surface2 border border-border text-ink font-bold rounded-xl py-2.5 text-sm hover:bg-surface">
                {t('updateModalClose')}
              </button>
              <button onClick={onDismissError} className="w-full border border-danger/30 bg-danger/10 text-danger font-bold rounded-xl py-2.5 text-xs hover:bg-danger/15">
                {t('updateModalDontShowAgain')}
              </button>
            </div>
          )}
        </div>
      </div>
    </div>,
    document.body,
  )
}

const DISMISSED_UPDATE_ERRORS_KEY = 'vpnpanel_dismissed_update_errors_v1'
const UPDATE_CHECK_CACHE_KEY = 'vpnpanel_update_check_v23252'
const UPDATE_CHECK_CACHE_MAX_AGE_MS = 30 * 60 * 1000

function readCachedUpdateInfo() {
  if (typeof window === 'undefined') return null
  try {
    const cached = JSON.parse(window.sessionStorage.getItem(UPDATE_CHECK_CACHE_KEY) || 'null')
    if (!cached?.info || Date.now() - Number(cached.saved_at || 0) > UPDATE_CHECK_CACHE_MAX_AGE_MS) return null
    return cached.info
  } catch {
    return null
  }
}

function cacheUpdateInfo(info) {
  if (typeof window === 'undefined' || !info) return
  try {
    window.sessionStorage.setItem(UPDATE_CHECK_CACHE_KEY, JSON.stringify({
      saved_at: Date.now(),
      info,
    }))
  } catch { /* sessionStorage unavailable */ }
}

function updateErrorSignature(version, message) {
  return `${version || 'unknown'}:${String(message || '').trim()}`
}

function isUpdateErrorDismissed(signature) {
  try { return JSON.parse(localStorage.getItem(DISMISSED_UPDATE_ERRORS_KEY) || '[]').includes(signature) } catch { return false }
}

function rememberUpdateError(signature) {
  try {
    const values = JSON.parse(localStorage.getItem(DISMISSED_UPDATE_ERRORS_KEY) || '[]')
    localStorage.setItem(DISMISSED_UPDATE_ERRORS_KEY, JSON.stringify(Array.from(new Set([...values, signature])).slice(-50)))
  } catch { /* localStorage unavailable */ }
}

async function copyTextReliable(text) {
  if (navigator.clipboard && window.isSecureContext) {
    await navigator.clipboard.writeText(text)
    return
  }
  const ta = document.createElement('textarea')
  ta.value = text
  ta.style.position = 'fixed'
  ta.style.opacity = '0'
  document.body.appendChild(ta)
  ta.focus()
  ta.select()
  const ok = document.execCommand('copy')
  document.body.removeChild(ta)
  if (!ok) throw new Error('copy failed')
}

export function UpdateCard({ donePath = '/dashboard' }) {
  const { dir, t } = useLang()
  const { notify } = useUI()
  const [checking, setChecking] = useState(true)
  const [checkError, setCheckError] = useState('')
  const [info, setInfo] = useState(() => readCachedUpdateInfo()) // { current_version, latest_version, update_available, notes, ... }

  const [showModal, setShowModal] = useState(false)
  const [running, setRunning] = useState(false)
  const [progress, setProgress] = useState(null) // { percent, state, message }
  const [updateError, setUpdateError] = useState('')
  const pollRef = useRef(null)
  const ticksRef = useRef(0)
  const pendingUpdateRef = useRef(null) // { version, notes } از قبل از شروع آپدیت، برای نمایش بعد از رفرش

  const loadCheck = async () => {
    setChecking(true)
    setCheckError('')
    try {
      const { data } = await api.get('/backup/update/check', { params: { _fresh: Date.now() } })
      setInfo(data)
      cacheUpdateInfo(data)
    } catch (err) {
      setCheckError(err.response?.data?.detail || t('checkErrDefault'))
      // Keep the last successful result visible across a refresh when the
      // license server has a brief timeout. A later successful check replaces
      // it, and a successful update stores the new installed version server-side.
    } finally {
      setChecking(false)
    }
  }

  useEffect(() => {
    loadCheck()
    return () => { if (pollRef.current) clearInterval(pollRef.current) }
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [])

  const stopPolling = () => {
    if (pollRef.current) {
      clearInterval(pollRef.current)
      pollRef.current = null
    }
  }

  const pollStatus = async () => {
    ticksRef.current += 1
    try {
      const { data } = await api.get('/backup/update/status')
      setProgress((previous) => ({
        ...(previous || {}),
        ...data,
        // The Nginx bridge intentionally returns only a sanitized console
        // while the authenticated API is down. Preserve the last full tail if
        // an older bridge does not include even that safe fallback.
        log_tail: data?.log_tail || previous?.log_tail || '',
      }))
      if (data.state === 'success') {
        stopPolling()
        setRunning(false)
        // دیگر این‌جا رفرش نمی‌کنیم؛ مودال دکمه‌ی Done را نشان می‌دهد و
        // رفرش/بازگشت به داشبورد با کلیک روی همان دکمه انجام می‌شود.
        return
      }
      if (data.state === 'failed') {
        stopPolling()
        setRunning(false)
        const message = data.message || t('updatingDefault')
        const signature = updateErrorSignature(info?.latest_version, message)
        if (isUpdateErrorDismissed(signature)) {
          setShowModal(false)
          setUpdateError('')
        } else {
          setUpdateError(message)
        }
        return
      }
    } catch (err) {
      // Last-resort heartbeat for a custom Nginx config that could not accept
      // the exact status fallback. Standard installs receive real progress
      // through the bridge above even while vpn-panel-api is offline.
      if (ticksRef.current % 2 === 0) {
        setProgress((previous) => ({
          ...(previous || {}),
          percent: Math.min(94, Math.max(43, Number(previous?.percent || 43) + 1)),
          state: 'running',
          message: t('updateApiRestarting'),
        }))
      }
    }
    if (ticksRef.current >= UPDATE_MAX_TICKS) {
      stopPolling()
      setRunning(false)
      setUpdateError(t('timeoutErr'))
    }
  }

  const openModal = () => {
    if (!info || !info.update_available) return
    setUpdateError('')
    setProgress(null)
    setShowModal(true)
  }

  const closeModal = () => {
    if (running) return // مودال حین اجرای آپدیت قابل بستن نیست
    setShowModal(false)
  }

  const startUpdate = async () => {
    if (!info || !info.update_available) return

    pendingUpdateRef.current = { version: info.latest_version, notes: info.notes }
    setUpdateError('')
    setRunning(true)
    setProgress({ percent: 1, state: 'running', message: t('startingUpdate') })
    ticksRef.current = 0
    try {
      await api.post('/backup/update/start')
    } catch (err) {
      setRunning(false)
      setUpdateError(err.response?.data?.detail || t('startErrDefault'))
      return
    }
    await pollStatus()
    pollRef.current = setInterval(pollStatus, UPDATE_POLL_MS)
  }

  const dismissUpdateErrorForever = () => {
    const signature = updateErrorSignature(info?.latest_version, updateError)
    rememberUpdateError(signature)
    setShowModal(false)
    setUpdateError('')
  }

  const copyUpdateLog = async (includeError = false) => {
    try {
      let fullLog = progress?.log_tail || ''
      try {
        const { data } = await api.get('/backup/update/log')
        if (data?.log) fullLog = data.log
      } catch { /* use polling tail as fallback */ }
      const content = [
        includeError && updateError ? `ERROR: ${updateError}` : '',
        fullLog,
      ].filter(Boolean).join('\n\n') || updateError || progress?.message || t('updatingDefault')
      await copyTextReliable(content)
    } catch {
      notify?.({ type: 'error', message: t('updateCopyFailed'), dir })
      throw new Error('copy failed')
    }
  }

  const finishUpdate = () => {
    markUpdateSuccess(pendingUpdateRef.current || {})
    // Load the new index atomically and bypass any intermediary/proxy HTML
    // cache. Hashed assets remain immutable; only the SPA entry is refreshed.
    const target = new URL(donePath, window.location.origin)
    target.searchParams.set('_ui', `after-update-${Date.now()}`)
    window.location.replace(target.toString())
  }

  const percent = progress?.percent ?? 0

  return (
    <div className="panel-section p-5 space-y-4">
      <div>
        <div className="text-sm font-bold text-ink">{t('updateHeading')}</div>
      </div>

      {checking && <div className="text-xs text-muted">{t('checkingLatest')}</div>}

      {!checking && checkError && (
        <div className="bg-danger/10 border border-danger/30 text-danger text-sm rounded-lg px-3 py-2">{checkError}</div>
      )}

      {!checking && !checkError && info && (
        <div className="bg-surface2 border border-border rounded-lg p-3 text-xs text-ink leading-6 space-y-1">
          <div>{t('currentVersion')} <span className="font-data text-ink">{info.current_version || t('unknown')}</span></div>
          {info.update_available ? (
            <>
              <div>{t('latestVersion')} <span className="font-data text-signal">{info.latest_version || t('unknown')}</span></div>
              <div className="pt-1"><span className="text-signal font-bold">{t('newVersionAvailable')}</span></div>
            </>
          ) : (
            <div className="pt-1"><span className="text-muted">{t('upToDate')}</span></div>
          )}
        </div>
      )}

      <div className="flex flex-col sm:flex-row gap-2">
        <button
          onClick={loadCheck}
          disabled={checking || running}
          className="flex-1 bg-surface2 border border-border text-ink font-bold rounded-lg py-2.5 text-sm hover:bg-surface disabled:opacity-50"
        >
          {t('btnRecheck')}
        </button>
        <button
          onClick={openModal}
          disabled={running || checking || !info || !info.update_available}
          className="flex-1 bg-signal text-bg font-bold rounded-lg py-2.5 text-sm hover:opacity-90 disabled:opacity-50"
        >
          {running
            ? t('btnUpdating')
            : (info && !info.update_available)
              ? t('btnAlreadyLatest')
              : t('btnGetUpdate')}
        </button>
      </div>

      {showModal && (
        <UpdateModal
          info={info}
          running={running}
          progress={progress}
          percent={percent}
          updateError={updateError}
          onStart={startUpdate}
          onClose={closeModal}
          onDone={finishUpdate}
          onDismissError={dismissUpdateErrorForever}
          onCopyLog={copyUpdateLog}
        />
      )}
    </div>
  )
}

export default function Backup() {
  const { lang } = useGlobalLang()
  const dir = lang === 'en' ? 'ltr' : 'rtl'
  const t = (key) => STRINGS[lang][key] ?? STRINGS.fa[key] ?? key

  const tabs = [
    {
      id: 'backups',
      label: t('tabBackups'),
      icon: 'backup',
      content: <div className="max-w-5xl space-y-4"><BackupCard /></div>,
    },
    {
      id: 'updates',
      label: t('tabUpdates'),
      icon: 'refresh',
      content: <div className="max-w-5xl"><UpdateCard /></div>,
    },
  ]

  return (
    <LangContext.Provider value={{ lang, dir, t }}>
      <div dir={dir} className={dir === 'ltr' ? 'text-left' : 'text-right'}>
        <div className="space-y-6">
          <header><h1 className="page-heading">{t('pageTitle')}</h1><p className="page-subtitle">{t('pageSubtitle')}</p></header>
          <SectionTabs
            tabs={tabs}
            param="view"
            storageKey="vpnpanel_backup_view"
            ariaLabel={t('tabsAria')}
            dir={dir}
          />
        </div>
      </div>
    </LangContext.Provider>
  )
}
