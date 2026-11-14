import React, { useEffect, useState } from 'react'
import api from '../api'
import { useUI } from './ui/UIProvider.jsx'
import { useLang } from '../i18n/dashboardLang.jsx'
import { formatRemainingText } from '../utils/formatRemaining.js'

export default function LicenseReserveModal({ info, onClose, onReserved }) {
  const { notify } = useUI()
  const { dir, t } = useLang()
  const [reservedList, setReservedList] = useState([])
  const [listLoading, setListLoading] = useState(true)
  const [key, setKey] = useState('')
  const [loading, setLoading] = useState(false)
  const [error, setError] = useState('')

  const loadReserved = async () => {
    setListLoading(true)
    try {
      const { data } = await api.get('/license/reserved')
      setReservedList(data)
    } catch (e) {
      // ignore
    } finally {
      setListLoading(false)
    }
  }

  useEffect(() => { loadReserved() }, [])

  const submit = async (e) => {
    e.preventDefault()
    setError('')
    setLoading(true)
    try {
      const { data } = await api.post('/license/reserve', { key: key.trim().toLowerCase() })
      setReservedList(data)
      setKey('')
      notify?.({ type: 'success', message: t('reserveSuccess') })
      onReserved?.()
    } catch (err) {
      setError(err.response?.data?.detail || t('reserveErrDefault'))
    } finally {
      setLoading(false)
    }
  }

  const days = info?.days_remaining
  const totalWithQueue = info?.total_days_remaining_with_queue

  return (
    <div dir={dir} className="modal-backdrop">
      <div className={`modal-panel modal-scroll-shell max-w-lg ${dir === 'ltr' ? 'text-left' : 'text-right'}`}>
        <div className="modal-sticky-header">
          <h2 className="font-bold text-sm">{t('renewModalTitle')}</h2>
          <button onClick={onClose} className="modal-close-button">✕</button>
        </div>

        <div className="modal-scroll-body p-4 space-y-4">
          {error && (
            <div className="bg-danger/10 border border-danger/30 text-danger text-sm rounded-lg px-3 py-2">
              {error}
            </div>
          )}

          <form onSubmit={submit} className="flex flex-col sm:flex-row gap-2">
            <input
              className="flex-1 bg-surface2 border border-border rounded-lg px-3 py-2.5 text-ink outline-none focus:border-signal transition-colors font-data text-center tracking-widest"
              placeholder={t('keyPlaceholder')}
              value={key}
              onChange={(e) => setKey(e.target.value)}
              required
            />
            <button
              disabled={loading}
              className="btn-primary"
            >
              {loading ? t('checkingBtn') : t('reserveBtn')}
            </button>
          </form>

          <div>
            <div className="text-xs font-bold text-ink mb-2">{t('reservedListHeading')}</div>

            {listLoading ? (
              <div className="text-xs text-muted">{t('loadingList')}</div>
            ) : reservedList.length === 0 ? (
              <div className="text-xs text-muted">{t('noReservedYet')}</div>
            ) : (
              <div className="space-y-1.5">
                {reservedList.map((r) => (
                  <div
                    key={r.id}
                    className="flex items-center justify-between bg-surface2 border border-border rounded-lg px-3 py-2 text-xs"
                  >
                    <div className="flex items-center gap-2">
                      <span className="text-muted font-data">{t('queuePrefix')}{r.queue_position}</span>
                      <span className="font-data text-ink">{r.key_masked}</span>
                    </div>
                    <span className="text-muted font-data">
                      {typeof r.days_remaining === 'number'
                        ? `${r.days_remaining} ${t('daysUnit')}`
                        : (r.expiry_pending && r.duration_days
                            ? `${r.duration_days} ${t('pendingDurationSuffix')}`
                            : t('waitingActivation'))}
                    </span>
                  </div>
                ))}
              </div>
            )}
          </div>
        </div>

        <div className="p-4 pt-0 mt-auto space-y-2">
          <div className="flex items-center justify-center gap-2.5 backdrop-blur-md bg-surface2/40 border border-border/60 rounded-full px-4 py-2.5">
            <span className="w-2.5 h-2.5 rounded-full bg-signal signal-dot shrink-0" />
            <span className="text-sm font-bold text-ink font-data whitespace-nowrap">
              {typeof days === 'number'
                ? `${formatRemainingText(days, info?.hours_remaining, info?.minutes_remaining, t)} ${t('remainingSuffix')}`
                : t('daysUnknown')}
            </span>
          </div>
          {typeof totalWithQueue === 'number' && (
            <div className="flex items-center justify-center gap-2.5 bg-surface2/40 border border-border/60 rounded-full px-4 py-2 text-xs text-muted font-data">
              {t('totalWithQueueLabel')}: <span className="font-bold text-ink">{totalWithQueue}</span> {t('daysUnit')}
            </div>
          )}
        </div>
      </div>
    </div>
  )
}
