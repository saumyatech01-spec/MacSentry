export default function Header({ scanState, onScan, score }) {
  const scanning = scanState === 'scanning'
  const complete = scanState === 'complete'
  const scoreColor = score === null ? '#98989d'
    : score >= 90 ? '#34C759' : score >= 70 ? '#30D158'
    : score >= 50 ? '#FFD60A' : score >= 30 ? '#FF9500' : '#FF3B30'
  const band = score === null ? '—'
    : score >= 90 ? 'Excellent' : score >= 70 ? 'Good'
    : score >= 50 ? 'Fair'      : score >= 30 ? 'Poor' : 'Critical'

  return (
    <header className="header">
      <div className="header-brand">
        <span className="header-logo">🛡️</span>
        <span className="header-title">MacSentry</span>
        <span className="header-version">v1.0</span>
      </div>
      <div className="header-actions">
        {score !== null && (
          <div className="header-score-pill">
            <span className="header-score-dot" style={{ background: scoreColor }} />
            <span style={{ color: scoreColor, fontWeight: 800 }}>{score}</span>
            <span style={{ color: 'var(--text-muted)', fontSize: 12 }}>{band}</span>
          </div>
        )}
        <button className={`scan-btn${scanning ? ' scanning' : ''}`} onClick={onScan} disabled={scanning}>
          {scanning
            ? <><span className="scan-btn-spinner" /> Scanning…</>
            : complete ? <>↺ Re-Scan</> : <>▶ Start Full Scan</>}
        </button>
      </div>
    </header>
  )
}
