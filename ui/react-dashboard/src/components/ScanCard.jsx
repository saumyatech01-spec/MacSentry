const SEV_META = {
  CRITICAL:{ color:'#FF3B30', bg:'rgba(255,59,48,.15)',  label:'Critical' },
  HIGH:    { color:'#FF9500', bg:'rgba(255,149,0,.15)',  label:'High'     },
  MEDIUM:  { color:'#FFD60A', bg:'rgba(255,214,10,.15)', label:'Medium'   },
  LOW:     { color:'#30D158', bg:'rgba(48,209,88,.15)',  label:'Low'      },
  SAFE:    { color:'#34C759', bg:'rgba(52,199,89,.12)',  label:'Safe'     },
}

function topSeverity(findings = []) {
  for (const s of ['CRITICAL','HIGH','MEDIUM','LOW','SAFE'])
    if (findings.some(f => f.severity === s)) return s
  return null
}

export default function ScanCard({ module, result, scanState, isSelected, animDelay, onClick }) {
  const hasResult = !!result
  const isActive  = scanState === 'scanning' && !hasResult
  const sev  = hasResult ? topSeverity(result.findings) : null
  const meta = sev ? SEV_META[sev] : null
  const pct  = hasResult ? Math.round(result.completion_pct || 100) : 0
  const fCount = hasResult ? (result.findings || []).length : 0

  const cardClass = [
    'scan-card',
    isSelected  ? 'selected'      : '',
    isActive    ? 'scanning-now'  : '',
    !hasResult && !isActive ? 'scan-card-waiting' : '',
  ].filter(Boolean).join(' ')

  return (
    <div className={cardClass} style={{ animationDelay:`${animDelay}ms` }} onClick={onClick}>
      <div className="scan-card-glow"
        style={{ background: isActive ? 'var(--primary)' : meta?.color || 'transparent' }} />
      <div className="scan-card-header">
        <span className="scan-card-icon">{module.icon}</span>
        {hasResult && sev && (
          <span className="scan-card-badge" style={{ background:meta.bg, color:meta.color }}>{meta.label}</span>
        )}
        {isActive && (
          <span className="scan-card-badge" style={{ background:'var(--primary-dim)', color:'var(--primary)' }}>
            Scanning…
          </span>
        )}
        {!hasResult && !isActive && (
          <span className="scan-card-badge" style={{ background:'var(--bg-elevated)', color:'var(--text-muted)' }}>
            Queued
          </span>
        )}
      </div>
      <div className="scan-card-step">Step {module.id}</div>
      <div className="scan-card-name">{module.name}</div>
      <div className="scan-card-desc">{module.desc}</div>
      {hasResult && (
        <div className="scan-card-footer">
          <span className="scan-card-findings">
            {fCount === 0 ? '✓ No issues' : `${fCount} finding${fCount !== 1 ? 's' : ''}`}
          </span>
          <div className="scan-card-progress">
            <div className="scan-card-progress-fill"
              style={{ width:`${pct}%`, background: meta?.color || 'var(--safe)' }} />
          </div>
        </div>
      )}
    </div>
  )
}
