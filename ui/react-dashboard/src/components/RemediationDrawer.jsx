import { useState } from 'react'

const IMPACT = {
  CRITICAL:['Immediate system compromise risk','Active exploitation possible','Data exfiltration exposure','Lateral movement risk'],
  HIGH:    ['Significant security gap','Exploitable with limited user interaction','Partial data exposure'],
  MEDIUM:  ['Moderate risk — exploitable under specific conditions','Hardening recommended'],
  LOW:     ['Minor security gap','Unlikely exploited in isolation'],
  SAFE:    ['No immediate action required'],
}
const MITRE_NAMES = {
  'T1543.004':'LaunchDaemon Persistence', 'T1574.006':'DYLD Injection',
  'T1078':'Valid Accounts / Auto-Login',  'T1053':'Cron/AT Scheduled Task',
  'T1176':'Browser Extension',           'T1059.004':'Shell Backdoor',
  'T1040':'Network Sniffing',            'T1557.002':'ARP Poisoning',
  'T1486':'FileVault Disabled',          'T1496':'Cryptomining',
  'T1203':'Browser Exploit',             'T1195':'Supply Chain / Outdated Packages',
  'T1542':'Secure Boot Bypass',
}
const SEV_META = {
  CRITICAL:{ color:'#FF3B30', bg:'rgba(255,59,48,.15)',  icon:'🔴', label:'Critical' },
  HIGH:    { color:'#FF9500', bg:'rgba(255,149,0,.15)',  icon:'🟠', label:'High'     },
  MEDIUM:  { color:'#FFD60A', bg:'rgba(255,214,10,.15)', icon:'🟡', label:'Medium'   },
  LOW:     { color:'#30D158', bg:'rgba(48,209,88,.15)',  icon:'🟢', label:'Low'      },
  SAFE:    { color:'#34C759', bg:'rgba(52,199,89,.12)',  icon:'✅', label:'Safe'     },
}

function CopyButton({ text }) {
  const [copied, setCopied] = useState(false)
  return (
    <button className={`copy-btn${copied ? ' copied' : ''}`}
      onClick={() => { navigator.clipboard.writeText(text); setCopied(true); setTimeout(()=>setCopied(false),1800) }}>
      {copied ? '✓ Copied' : 'Copy'}
    </button>
  )
}

function parseCommands(rec = '') {
  return rec.split(/[.\n]/).map(s => s.trim()).filter(s =>
    /^(sudo|defaults|spctl|fdesetup|csrutil|chmod|rm |launchctl|ssh-|brew|softwareupdate|socketfilterfw)/i.test(s)
  )
}

export default function RemediationDrawer({ finding, onClose }) {
  const meta    = SEV_META[finding.severity] || SEV_META.SAFE
  const impacts = IMPACT[finding.severity]   || IMPACT.SAFE
  const cmds    = parseCommands(finding.recommendation)
  const mitre   = finding.mitre_technique ? MITRE_NAMES[finding.mitre_technique] : null

  return (
    <>
      <div className="drawer-overlay" onClick={onClose} />
      <div className="drawer">
        <div className="drawer-header">
          <div>
            <div className="drawer-severity-icon">{meta.icon}</div>
            <div className="drawer-title">{finding.check}</div>
            <div className="drawer-subtitle">{finding.moduleIcon} {finding.moduleName}</div>
          </div>
          <button className="close-btn" onClick={onClose}>✕</button>
        </div>
        <div className="drawer-body">

          <div className="drawer-section">
            <div className="drawer-section-title">Risk Level</div>
            <div style={{ display:'flex', gap:8, flexWrap:'wrap', alignItems:'center' }}>
              <span className="risk-pill" style={{ background:meta.bg, color:meta.color }}>
                {meta.icon} {meta.label}
              </span>
              {finding.mitre_technique && (
                <span className="mitre-tag">
                  🎯 {finding.mitre_technique}{mitre ? ` — ${mitre}` : ''}
                </span>
              )}
            </div>
          </div>

          <div className="drawer-section">
            <div className="drawer-section-title">What Was Found</div>
            <div className="drawer-description">{finding.detail}</div>
          </div>

          <div className="drawer-section">
            <div className="drawer-section-title">Potential Impact</div>
            <ul className="impact-list">
              {impacts.map((line, i) => <li key={i}>{line}</li>)}
            </ul>
          </div>

          <div className="drawer-section">
            <div className="drawer-section-title">How to Fix</div>
            <div className="drawer-description" style={{ marginBottom: cmds.length ? 12 : 0 }}>
              {finding.recommendation}
            </div>
            {(cmds.length > 0 ? cmds : [finding.recommendation]).map((cmd, i) => (
              <div className="cmd-block" key={i}>
                <div className="cmd-label">Terminal Command</div>
                <pre className="cmd-code">{cmd}</pre>
                <CopyButton text={cmd} />
              </div>
            ))}
          </div>

          <div className="drawer-section">
            <div className="drawer-section-title">Verify After Fix</div>
            <div className="drawer-description" style={{ fontSize:12 }}>
              Re-run MacSentry after applying the fix. The finding should appear as{' '}
              <strong style={{ color:'var(--safe)' }}>SAFE</strong> on the next scan. Use{' '}
              <code style={{ background:'var(--bg-elevated)', padding:'1px 6px', borderRadius:4 }}>
                python3 core/scanner_engine.py --step {finding.moduleName?.toLowerCase().replace(/ /g,'_')} --verbose
              </code>{' '}
              to re-run just this module.
            </div>
          </div>

        </div>
      </div>
    </>
  )
}