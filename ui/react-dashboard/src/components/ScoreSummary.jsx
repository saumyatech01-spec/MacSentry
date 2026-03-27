const STATS_CONFIG = [
  { key:'CRITICAL', label:'Critical', color:'#FF3B30' },
  { key:'HIGH',     label:'High',     color:'#FF9500' },
  { key:'MEDIUM',   label:'Medium',   color:'#FFD60A' },
  { key:'LOW',      label:'Low',      color:'#30D158' },
  { key:'SAFE',     label:'Safe',     color:'#34C759' },
]

function Gauge({ score }) {
  const R = 52, C = 2 * Math.PI * R
  const pct    = score === null ? 0 : Math.min(100, Math.max(0, score))
  const offset = C - (pct / 100) * C
  const color  = score === null ? '#38383a'
    : score >= 90 ? '#34C759' : score >= 70 ? '#30D158'
    : score >= 50 ? '#FFD60A' : score >= 30 ? '#FF9500' : '#FF3B30'
  const band = score === null ? null
    : score >= 90 ? 'Excellent' : score >= 70 ? 'Good'
    : score >= 50 ? 'Fair'      : score >= 30 ? 'Poor' : 'Critical'

  return (
    <div className="score-gauge-wrap">
      <svg className="score-gauge-svg" viewBox="0 0 120 120">
        <circle className="score-gauge-bg"   cx="60" cy="60" r={R} />
        <circle className="score-gauge-fill" cx="60" cy="60" r={R}
          strokeDasharray={C} strokeDashoffset={offset}
          style={{ stroke: color }}
        />
      </svg>
      <div className="score-gauge-center">
        <span className="score-gauge-number" style={{ color }}>
          {score === null ? '—' : score}
        </span>
        <span className="score-gauge-label">Security Score</span>
        {band && <span className="score-band" style={{ background:`${color}22`, color }}>{band}</span>}
      </div>
    </div>
  )
}

export default function ScoreSummary({ score, stats, scanState, completedCount, totalCount }) {
  const scanning = scanState === 'scanning'
  const pct      = Math.round((completedCount / totalCount) * 100)
  return (
    <div className="score-banner">
      <Gauge score={score} />
      <div>
        <div className="score-stats">
          {STATS_CONFIG.map(({ key, label, color }) => (
            <div className="stat-chip" key={key}>
              <span className="stat-dot" style={{ background: color }} />
              <div className="stat-info">
                <span className="stat-count" style={{ color }}>{stats[key] || 0}</span>
                <span className="stat-name">{label}</span>
              </div>
            </div>
          ))}
        </div>
        {scanning && (
          <div className="scan-progress-info">
            <span style={{ fontSize:12, flexShrink:0 }}>Scanning {completedCount}/{totalCount}</span>
            <div className="scan-progress-bar-wrap">
              <div className="scan-progress-bar" style={{ width:`${pct}%` }} />
            </div>
            <span style={{ fontSize:12, flexShrink:0 }}>{pct}%</span>
          </div>
        )}
        {scanState === 'idle' && (
          <p style={{ fontSize:13, color:'var(--text-muted)', marginTop:12 }}>
            Click <strong style={{ color:'var(--primary)' }}>Start Full Scan</strong> to run all 10 security modules.
          </p>
        )}
        {scanState === 'complete' && (
          <p style={{ fontSize:13, color:'var(--safe)', marginTop:12 }}>
            Scan complete - click any module card to explore findings and remediation.
          </p>
        )}
        {scanState === 'error' && (
          <p style={{ fontSize:13, color:'var(--critical)', marginTop:12 }}>
            Scan error - ensure Flask is running on port 5001 and scanner_engine.py is accessible.
          </p>
        )}
      </div>
    </div>
  )
}
