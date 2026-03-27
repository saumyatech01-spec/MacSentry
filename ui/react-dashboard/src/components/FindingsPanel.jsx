const SEV_META = {
  CRITICAL:{ color:'#FF3B30', bg:'rgba(255,59,48,.15)',  label:'Critical', icon:'🔴' },
  HIGH:    { color:'#FF9500', bg:'rgba(255,149,0,.15)',  label:'High',     icon:'🟠' },
  MEDIUM:  { color:'#FFD60A', bg:'rgba(255,214,10,.15)', label:'Medium',   icon:'🟡' },
  LOW:     { color:'#30D158', bg:'rgba(48,209,88,.15)',  label:'Low',      icon:'🟢' },
  SAFE:    { color:'#34C759', bg:'rgba(52,199,89,.12)',  label:'Safe',     icon:'✅' },
}

// Illustrative demo data — so users see live UX before their first scan
const DEMO_FINDINGS = {
  1: { risk_level:'HIGH', findings:[
    { check:'Gatekeeper',  severity:'SAFE',   detail:'Gatekeeper enabled — only notarized apps allowed.',             recommendation:'No action required.', mitre_technique:null },
    { check:'SIP Status',  severity:'SAFE',   detail:'System Integrity Protection is fully enabled.',                 recommendation:'No action required.', mitre_technique:null },
    { check:'XProtect',    severity:'HIGH',   detail:'XProtect definitions are 47 days old (threshold: 30 days).',    recommendation:'sudo softwareupdate --install --all', mitre_technique:'T1195' },
    { check:'Secure Boot', severity:'MEDIUM', detail:'Secure Boot set to Medium Security. Recommended: Full Security.',recommendation:'Open Startup Security Utility → set Full Security.', mitre_technique:'T1542' },
  ]},
  2: { risk_level:'CRITICAL', findings:[
    { check:'Firewall',  severity:'CRITICAL', detail:'macOS Application Firewall is OFF.',          recommendation:'sudo /usr/libexec/ApplicationFirewall/socketfilterfw --setglobalstate on', mitre_technique:'T1040' },
    { check:'Open Ports',severity:'HIGH',     detail:'22 open ports detected; 3 unexpected (8080, 3000, 5900).', recommendation:'sudo lsof -iTCP -sTCP:LISTEN -n -P to audit. Close unused ports.', mitre_technique:'T1040' },
  ]},
  3: { risk_level:'MEDIUM', findings:[
    { check:'Auto-login', severity:'MEDIUM', detail:'Auto-login is enabled. Any physical access bypasses the lock screen.', recommendation:'System Settings → Users & Groups → disable automatic login.', mitre_technique:'T1078' },
    { check:'Screen Lock', severity:'SAFE',  detail:'Screen lock activates after 5 minutes of inactivity.',                 recommendation:'No action required.', mitre_technique:null },
  ]},
}

export default function FindingsPanel({ module, result, onSelectFinding, onClose }) {
  const data     = result || DEMO_FINDINGS[module.id] || { risk_level:'SAFE', findings:[] }
  const isDemo   = !result
  const findings = data.findings || []

  return (
    <div className="findings-panel">
      <div className="findings-panel-header">
        <div>
          <div className="findings-panel-title">{module.icon} {module.name}</div>
          <div className="findings-panel-subtitle">
            {isDemo
              ? '⚠️ Demo preview — run a scan for live results'
              : `${findings.length} finding${findings.length !== 1 ? 's' : ''} · Risk: ${data.risk_level}`
            }
          </div>
        </div>
        <button className="close-btn" onClick={onClose}>✕</button>
      </div>
      <div className="findings-list">
        {findings.length === 0
          ? (
            <div className="no-findings">
              <div style={{ fontSize:36, marginBottom:12 }}>✅</div>
              <div style={{ fontWeight:700, marginBottom:4 }}>All Clear</div>
              <div style={{ fontSize:13, color:'var(--text-muted)' }}>No issues found in this module.</div>
            </div>
          )
          : findings.map((finding, i) => {
            const meta = SEV_META[finding.severity] || SEV_META.SAFE
            return (
              <div key={i} className="finding-item" style={{ animationDelay:`${i*50}ms` }}
                onClick={() => onSelectFinding({ ...finding, moduleName:module.name, moduleIcon:module.icon })}>
                <div className="finding-left-bar" style={{ background:meta.color }} />
                <div className="finding-header">
                  <span className="severity-badge" style={{ background:meta.bg, color:meta.color }}>
                    {meta.icon} {meta.label}
                  </span>
                  <span className="finding-check">{finding.check}</span>
                </div>
                <div className="finding-detail">{finding.detail}</div>
                {finding.mitre_technique && (
                  <span className="finding-mitre">🎯 MITRE {finding.mitre_technique}</span>
                )}
                <div className="finding-action-hint">🔧 Click to see remediation steps →</div>
              </div>
            )
          })
        }
      </div>
    </div>
  )
}