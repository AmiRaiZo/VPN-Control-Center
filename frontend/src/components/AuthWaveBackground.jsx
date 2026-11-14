import React from 'react'

// Broad, anchored sea layers inspired by the smooth overlapping waves in the
// reference UI. The SVG never slides across the page; only the curve control
// points morph vertically, so the wave remains fixed in place and feels calm.
const back = [
  'M0 164C170 126 340 138 520 174C720 214 902 132 1090 150C1232 164 1342 194 1440 172V360H0Z',
  'M0 170C174 148 344 118 526 166C718 216 900 160 1088 142C1230 128 1340 180 1440 178V360H0Z',
  'M0 156C168 112 346 166 524 182C716 200 900 118 1092 160C1236 192 1344 176 1440 164V360H0Z',
  'M0 166C176 142 338 154 518 160C716 168 904 146 1094 146C1236 146 1342 202 1440 174V360H0Z',
]

const middle = [
  'M0 210C166 176 342 188 522 218C714 250 902 178 1088 194C1234 206 1344 230 1440 208V360H0Z',
  'M0 216C172 196 344 166 526 210C716 256 904 208 1090 186C1232 168 1340 218 1440 216V360H0Z',
  'M0 202C168 162 346 216 526 226C718 236 900 166 1092 206C1236 236 1344 218 1440 200V360H0Z',
  'M0 212C176 190 338 202 520 198C716 194 906 192 1094 190C1236 188 1342 242 1440 210V360H0Z',
]

const front = [
  'M0 258C166 226 340 236 520 266C716 298 902 226 1090 242C1234 254 1344 278 1440 256V360H0Z',
  'M0 264C170 244 344 214 526 258C716 304 904 256 1090 234C1234 216 1340 266 1440 264V360H0Z',
  'M0 250C168 210 346 264 526 274C718 284 900 214 1092 254C1236 284 1344 266 1440 248V360H0Z',
  'M0 260C176 238 338 250 520 246C716 242 906 240 1094 238C1236 236 1342 290 1440 258V360H0Z',
]

const crest = front.map((path) => path.replace('V360H0Z', ''))
const softCrest = middle.map((path) => path.replace('V360H0Z', ''))

function Morph({ values, dur, begin = '0s' }) {
  return (
    <animate
      attributeName="d"
      dur={dur}
      begin={begin}
      repeatCount="indefinite"
      calcMode="spline"
      keyTimes="0;0.25;0.5;0.75;1"
      keySplines="0.45 0 0.55 1;0.45 0 0.55 1;0.45 0 0.55 1;0.45 0 0.55 1"
      values={[...values, values[0]].join(';')}
    />
  )
}

export default function AuthWaveBackground() {
  return (
    <div className="auth-wave-background auth-wave-background--ocean" aria-hidden="true">
      <svg viewBox="0 0 1440 360" preserveAspectRatio="none" role="presentation">
        <path className="auth-wave auth-wave-back" d={back[0]}>
          <Morph values={back} dur="15s" />
        </path>
        <path className="auth-wave auth-wave-middle" d={middle[0]}>
          <Morph values={middle} dur="13s" begin="-2.2s" />
        </path>
        <path className="auth-wave auth-wave-front" d={front[0]}>
          <Morph values={front} dur="11s" begin="-1.4s" />
        </path>
        <path className="auth-wave-crest auth-wave-crest-back" d={softCrest[0]}>
          <Morph values={softCrest} dur="13s" begin="-2.2s" />
        </path>
        <path className="auth-wave-crest auth-wave-crest-front" d={crest[0]}>
          <Morph values={crest} dur="11s" begin="-1.4s" />
        </path>
      </svg>
    </div>
  )
}
