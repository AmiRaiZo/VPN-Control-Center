import React, { useMemo, useState } from 'react'
import * as ReactDOM from 'react-dom'
import JalaliDatePicker from './JalaliDatePicker.jsx'
import { useLang } from '../i18n/dashboardLang.jsx'

const isoDate = (date) => date.toISOString().slice(0, 10)
const todayIso = () => isoDate(new Date())
const daysAgoIso = (days) => {
  const date = new Date()
  date.setDate(date.getDate() - days)
  return isoDate(date)
}

function ScopeCard({ active, title, subtitle, icon, onClick }) {
  return (
    <button type="button" onClick={onClick} className={`bulk-scope-card ${active ? 'is-active' : ''}`}>
      <span className="bulk-scope-card__icon">{icon}</span>
      <span className="bulk-scope-card__copy"><b>{title}</b><small>{subtitle}</small></span>
      <span className="bulk-scope-card__check">{active ? '✓' : ''}</span>
    </button>
  )
}

export default function BulkUserIncreaseModal({ users, onClose, onSubmit, busy = false, error = '' }) {
  const { t, dir } = useLang()
  const [form, setForm] = useState({
    scope: 'all',
    quota_gb: 0,
    days: 0,
    created_from: daysAgoIso(20),
    created_to: todayIso(),
    reactivate: false,
  })

  const set = (key, value) => setForm((current) => ({ ...current, [key]: value }))
  const matched = useMemo(() => {
    return users.filter((user) => {
      if (form.scope === 'active') return !!user.is_active
      if (form.scope === 'inactive') return !user.is_active
      if (form.scope === 'created_range') {
        const created = String(user.created_at || '').slice(0, 10)
        return created && created >= form.created_from && created <= form.created_to
      }
      return true
    }).length
  }, [users, form.scope, form.created_from, form.created_to])

  const submit = (event) => {
    event.preventDefault()
    onSubmit({
      ...form,
      quota_gb: Math.max(0, Number(form.quota_gb) || 0),
      days: Math.max(0, Math.trunc(Number(form.days) || 0)),
      created_from: form.scope === 'created_range' ? form.created_from : null,
      created_to: form.scope === 'created_range' ? form.created_to : null,
    })
  }

  const modal = (
    <div className="modal-backdrop bulk-increase-backdrop" role="dialog" aria-modal="true">
      <div dir={dir} className={`modal-panel modal-scroll-shell bulk-increase-modal ${dir === 'ltr' ? 'text-left' : 'text-right'}`}>
        <header className="modal-sticky-header">
          <div>
            <h2 className="font-black text-base">{t('bulkIncreaseTitle')}</h2>
            <p className="mt-1 text-[11px] text-muted">{t('bulkIncreaseSubtitle')}</p>
          </div>
          <button type="button" onClick={onClose} className="modal-close-button" aria-label={t('userFormCancelBtn')}>✕</button>
        </header>

        <form onSubmit={submit} className="modal-scroll-body bulk-increase-body">
          {error && <div className="rounded-xl border border-danger/30 bg-danger/10 px-3 py-2 text-sm text-danger">{error}</div>}

          <section className="bulk-increase-section">
            <div className="bulk-increase-section__head">
              <h3>{t('bulkIncreaseTargetTitle')}</h3>
              <span>{matched} {t('bulkIncreaseMatchedSuffix')}</span>
            </div>
            <div className="bulk-scope-grid">
              <ScopeCard active={form.scope === 'all'} onClick={() => set('scope', 'all')} icon="◎" title={t('bulkIncreaseScopeAll')} subtitle={t('bulkIncreaseScopeAllHint')} />
              <ScopeCard active={form.scope === 'active'} onClick={() => set('scope', 'active')} icon="✓" title={t('bulkIncreaseScopeActive')} subtitle={t('bulkIncreaseScopeActiveHint')} />
              <ScopeCard active={form.scope === 'inactive'} onClick={() => set('scope', 'inactive')} icon="○" title={t('bulkIncreaseScopeInactive')} subtitle={t('bulkIncreaseScopeInactiveHint')} />
              <ScopeCard active={form.scope === 'created_range'} onClick={() => set('scope', 'created_range')} icon="⌁" title={t('bulkIncreaseScopeRange')} subtitle={t('bulkIncreaseScopeRangeHint')} />
            </div>

            {form.scope === 'created_range' && (
              <div className="bulk-date-grid">
                <label><span className="field-label">{t('bulkIncreaseFromDate')}</span><JalaliDatePicker value={form.created_from} onChange={(value) => set('created_from', value || daysAgoIso(20))} allowEmpty={false} /></label>
                <label><span className="field-label">{t('bulkIncreaseToDate')}</span><JalaliDatePicker value={form.created_to} onChange={(value) => set('created_to', value || todayIso())} allowEmpty={false} /></label>
                <button type="button" className="bulk-quick-range" onClick={() => setForm((current) => ({ ...current, created_from: daysAgoIso(20), created_to: todayIso() }))}>{t('bulkIncreaseLast20Days')}</button>
              </div>
            )}
          </section>

          <section className="bulk-increase-section">
            <div className="bulk-increase-section__head"><h3>{t('bulkIncreaseAmountTitle')}</h3></div>
            <div className="bulk-amount-grid">
              <label className="bulk-amount-card quota">
                <span className="bulk-amount-card__icon">＋</span>
                <span className="field-label">{t('bulkIncreaseQuotaLabel')}</span>
                <div className="bulk-amount-input"><input dir="ltr" type="number" min="0" step="0.1" value={form.quota_gb} onChange={(event) => set('quota_gb', event.target.value)} /><span>GB</span></div>
              </label>
              <label className="bulk-amount-card days">
                <span className="bulk-amount-card__icon">＋</span>
                <span className="field-label">{t('bulkIncreaseDaysLabel')}</span>
                <div className="bulk-amount-input"><input dir="ltr" type="number" min="0" step="1" value={form.days} onChange={(event) => set('days', event.target.value)} /><span>{t('bulkIncreaseDaysUnit')}</span></div>
              </label>
            </div>
            <p className="bulk-increase-note">{t('bulkIncreaseUnlimitedNote')}</p>
          </section>

          <button type="button" onClick={() => set('reactivate', !form.reactivate)} className={`bulk-reactivate-card ${form.reactivate ? 'is-active' : ''}`}>
            <span><b>{t('bulkIncreaseReactivate')}</b><small>{t('bulkIncreaseReactivateHint')}</small></span>
            <span className={`modern-switch-knob ${form.reactivate ? 'is-active' : ''}`}><span className="modern-switch-knob__dot" /></span>
          </button>

          <footer className="modal-actions bulk-increase-actions">
            <button type="button" onClick={onClose} className="btn-secondary" disabled={busy}>{t('userFormCancelBtn')}</button>
            <button type="submit" className="btn-primary" disabled={busy || matched === 0 || (Number(form.quota_gb) <= 0 && Number(form.days) <= 0)}>{busy ? t('bulkIncreaseSubmitting') : t('bulkIncreaseSubmit')}</button>
          </footer>
        </form>
      </div>
    </div>
  )

  return ReactDOM.createPortal(modal, document.body)
}
