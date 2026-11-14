import React, { useEffect, useRef } from 'react'
import { useTheme } from '../theme/themeContext.jsx'

// Quiet animated atmosphere used behind the application and login page.
// It deliberately avoids the old constellation/web effect: a few soft light
// motes and slow aurora particles provide depth without competing with data.
const PALETTES = {
  dark: {
    colors: ['255,108,0', '56,189,248', '245,158,11'],
    tinyAlpha: 0.42,
    glowAlpha: 0.09,
  },
  light: {
    colors: ['217,79,0', '2,132,199', '180,83,9'],
    tinyAlpha: 0.26,
    glowAlpha: 0.045,
  },
}

export default function ParticleBackground({ density = 0.000028 }) {
  const canvasRef = useRef(null)
  const { resolvedTheme } = useTheme()
  const palette = PALETTES[resolvedTheme] || PALETTES.dark

  useEffect(() => {
    const canvas = canvasRef.current
    const ctx = canvas.getContext('2d')
    let width = 0
    let height = 0
    let dpr = 1
    let motes = []
    let animationId = 0
    const reducedMotion = window.matchMedia?.('(prefers-reduced-motion: reduce)').matches === true
    const lowPower = document.documentElement.dataset.performance === 'lite' || window.matchMedia?.('(max-width: 767px), (pointer: coarse)').matches === true
    const pointer = { x: 0, y: 0, active: false }

    function makeMote(index) {
      const glow = index % 7 === 0
      return {
        x: Math.random() * width,
        y: Math.random() * height,
        vx: (Math.random() - 0.5) * (glow ? 0.07 : 0.14),
        vy: (Math.random() - 0.5) * (glow ? 0.07 : 0.14),
        radius: glow ? 70 + Math.random() * 115 : 0.75 + Math.random() * 1.35,
        color: palette.colors[Math.floor(Math.random() * palette.colors.length)],
        glow,
        phase: Math.random() * Math.PI * 2,
      }
    }

    function resize() {
      width = Math.max(1, canvas.clientWidth)
      height = Math.max(1, canvas.clientHeight)
      dpr = Math.min(window.devicePixelRatio || 1, 2)
      canvas.width = Math.round(width * dpr)
      canvas.height = Math.round(height * dpr)
      ctx.setTransform(dpr, 0, 0, dpr, 0, 0)
      const count = Math.max(18, Math.min(58, Math.round(width * height * density)))
      motes = Array.from({ length: count }, (_, index) => makeMote(index))
    }

    function draw(time = 0) {
      ctx.clearRect(0, 0, width, height)
      for (const mote of motes) {
        if (!reducedMotion) {
          mote.x += mote.vx
          mote.y += mote.vy
          if (mote.x < -mote.radius) mote.x = width + mote.radius
          if (mote.x > width + mote.radius) mote.x = -mote.radius
          if (mote.y < -mote.radius) mote.y = height + mote.radius
          if (mote.y > height + mote.radius) mote.y = -mote.radius
        }

        const parallaxX = pointer.active ? (pointer.x / width - 0.5) * (mote.glow ? 12 : 4) : 0
        const parallaxY = pointer.active ? (pointer.y / height - 0.5) * (mote.glow ? 12 : 4) : 0
        const pulse = 0.84 + Math.sin(time * 0.00032 + mote.phase) * 0.16
        const x = mote.x + parallaxX
        const y = mote.y + parallaxY

        if (mote.glow) {
          const radius = mote.radius * pulse
          const gradient = ctx.createRadialGradient(x, y, 0, x, y, radius)
          gradient.addColorStop(0, `rgba(${mote.color}, ${palette.glowAlpha})`)
          gradient.addColorStop(0.5, `rgba(${mote.color}, ${palette.glowAlpha * 0.34})`)
          gradient.addColorStop(1, `rgba(${mote.color}, 0)`)
          ctx.fillStyle = gradient
          ctx.beginPath()
          ctx.arc(x, y, radius, 0, Math.PI * 2)
          ctx.fill()
        } else {
          ctx.fillStyle = `rgba(${mote.color}, ${palette.tinyAlpha * pulse})`
          ctx.beginPath()
          ctx.arc(x, y, mote.radius, 0, Math.PI * 2)
          ctx.fill()
        }
      }
      if (!reducedMotion) animationId = requestAnimationFrame(draw)
    }

    function onPointerMove(event) {
      pointer.x = event.clientX
      pointer.y = event.clientY
      pointer.active = true
    }
    function onPointerLeave() { pointer.active = false }

    // Mobile GPUs spend a disproportionate amount of time compositing this
    // full-screen canvas. In lite mode keep the atmospheric CSS background and
    // skip the canvas loop entirely.
    if (lowPower) {
      ctx.clearRect(0, 0, canvas.width || 1, canvas.height || 1)
      return undefined
    }

    resize()
    draw()
    window.addEventListener('resize', resize)
    window.addEventListener('pointermove', onPointerMove, { passive: true })
    window.addEventListener('pointerleave', onPointerLeave)
    return () => {
      cancelAnimationFrame(animationId)
      window.removeEventListener('resize', resize)
      window.removeEventListener('pointermove', onPointerMove)
      window.removeEventListener('pointerleave', onPointerLeave)
    }
  }, [density, resolvedTheme])

  return <canvas ref={canvasRef} className="mobile-particle-canvas fixed inset-0 h-full w-full pointer-events-none" style={{ zIndex: 0 }} aria-hidden="true" />
}
