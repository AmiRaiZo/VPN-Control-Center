import React, { useEffect, useState } from 'react'
import { usePanelNavigate } from '../navigation.js'
import api from '../api'
import { getToken } from '../session'
import { firstAllowedPath } from '../permissions.js'
import LicenseLock from './LicenseLock.jsx'

export default function LicenseLockPage() {
  const [statusInfo, setStatusInfo] = useState(null)
  const [loading, setLoading] = useState(true)
  const navigate = usePanelNavigate()

  useEffect(() => {
    if (!getToken()) {
      navigate('/login', { replace: true })
      return
    }
    let cancelled = false
    api.get('/license/status').then(({ data }) => {
      if (cancelled) return
      if (!data.locked) {
        // در فاصله‌ی بین رسیدن به این صفحه و لود شدنش، لایسنس دوباره معتبر
        // شده (مثلاً یک تب دیگر آن را فعال کرده) - برگرد به پنل عادی.
        navigate(firstAllowedPath(), { replace: true })
        return
      }
      setStatusInfo(data)
      setLoading(false)
    }).catch(() => {
      if (!cancelled) setLoading(false)
    })
    return () => { cancelled = true }
  }, [navigate])

  if (loading) return null

  return (
    <LicenseLock
      statusInfo={statusInfo}
      onActivated={(data) => {
        if (!data.locked) navigate(firstAllowedPath(), { replace: true })
        else setStatusInfo(data)
      }}
    />
  )
}
