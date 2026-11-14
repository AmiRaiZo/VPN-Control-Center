import React, { useEffect, useMemo, useRef, useState } from 'react'
import { useSearchParams } from 'react-router-dom'
import { Icon } from './icons.jsx'

export default function SectionTabs({
  tabs,
  param = 'tab',
  storageKey,
  ariaLabel = 'Sections',
  dir = 'ltr',
}) {
  const [searchParams, setSearchParams] = useSearchParams()
  const ids = useMemo(() => tabs.map((tab) => tab.id), [tabs])
  const requested = searchParams.get(param)
  const stored = storageKey ? localStorage.getItem(storageKey) : null
  const firstId = ids[0]
  const initialId = ids.includes(requested) ? requested : (ids.includes(stored) ? stored : firstId)
  const [activeId, setActiveId] = useState(initialId)
  const [motion, setMotion] = useState('forward')
  const tabRefs = useRef({})

  useEffect(() => {
    if (requested && ids.includes(requested) && requested !== activeId) {
      const currentIndex = ids.indexOf(activeId)
      const nextIndex = ids.indexOf(requested)
      setMotion(nextIndex >= currentIndex ? 'forward' : 'backward')
      setActiveId(requested)
    }
  }, [requested, ids, activeId])

  useEffect(() => {
    if (!requested || !ids.includes(requested)) {
      const next = new URLSearchParams(searchParams)
      next.set(param, activeId)
      setSearchParams(next, { replace: true })
    }
  }, []) // eslint-disable-line react-hooks/exhaustive-deps

  const selectTab = (id, focus = false) => {
    if (!ids.includes(id) || id === activeId) return
    const currentIndex = ids.indexOf(activeId)
    const nextIndex = ids.indexOf(id)
    setMotion(nextIndex >= currentIndex ? 'forward' : 'backward')
    setActiveId(id)
    if (storageKey) localStorage.setItem(storageKey, id)
    const next = new URLSearchParams(searchParams)
    next.set(param, id)
    setSearchParams(next, { replace: true })
    if (focus) requestAnimationFrame(() => tabRefs.current[id]?.focus())
  }

  const onKeyDown = (event) => {
    const currentIndex = ids.indexOf(activeId)
    let nextIndex = currentIndex
    if (event.key === 'Home') nextIndex = 0
    else if (event.key === 'End') nextIndex = ids.length - 1
    else if (event.key === 'ArrowRight') nextIndex = dir === 'rtl' ? currentIndex - 1 : currentIndex + 1
    else if (event.key === 'ArrowLeft') nextIndex = dir === 'rtl' ? currentIndex + 1 : currentIndex - 1
    else return
    event.preventDefault()
    if (nextIndex < 0) nextIndex = ids.length - 1
    if (nextIndex >= ids.length) nextIndex = 0
    selectTab(ids[nextIndex], true)
  }

  const activeTab = tabs.find((tab) => tab.id === activeId) || tabs[0]

  return (
    <section className="section-tabs-shell">
      <div className="section-tabs-scroll">
        <div className="section-tabs-nav" role="tablist" aria-label={ariaLabel} onKeyDown={onKeyDown}>
          {tabs.map((tab) => {
            const active = tab.id === activeId
            return (
              <button
                key={tab.id}
                ref={(node) => { tabRefs.current[tab.id] = node }}
                type="button"
                id={`${param}-tab-${tab.id}`}
                role="tab"
                aria-selected={active}
                aria-controls={`${param}-panel-${tab.id}`}
                tabIndex={active ? 0 : -1}
                className={`section-tab-button ${active ? 'is-active' : ''}`}
                onClick={() => selectTab(tab.id)}
              >
                {tab.icon && <Icon name={tab.icon} size={15} className="section-tab-icon" />}
                <span>{tab.label}</span>
                {tab.badge !== undefined && tab.badge !== null && <span className="section-tab-badge">{tab.badge}</span>}
              </button>
            )
          })}
        </div>
      </div>
      <div className="section-tab-panels">
        {tabs.map((tab) => {
          const active = tab.id === activeTab.id
          return (
            <div
              key={tab.id}
              id={`${param}-panel-${tab.id}`}
              role="tabpanel"
              aria-labelledby={`${param}-tab-${tab.id}`}
              aria-hidden={!active}
              hidden={!active}
              className={`section-tab-content ${active ? (motion === 'backward' ? 'from-back' : 'from-forward') : ''}`}
            >
              {tab.content}
            </div>
          )
        })}
      </div>
    </section>
  )
}
