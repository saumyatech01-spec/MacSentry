import { useState, useEffect, useCallback, useRef } from 'react'
import Header from './components/Header'
import ScoreSummary from './components/ScoreSummary'
import ScanGrid from './components/ScanGrid'
import FindingsPanel from './components/FindingsPanel'
import RemediationDrawer from './components/RemediationDrawer'

export const SCAN_MODULES = [
  { id:1,  name:'System Integrity',    icon:'🔒', desc:'SIP, Gatekeeper, XProtect, Secure Boot, SSV' },
  { id:2,  name:'Network Security',    icon:'🌐', desc:'Firewall, open ports, DNS, Wi-Fi, ARP' },
  { id:3,  name:'User Authentication', icon:'👤', desc:'Auto-login, sudo NOPASSWD, SSH keys, screen lock' },
  { id:4,  name:'Encryption',          icon:'🔐', desc:'FileVault 2, Keychain lock, expired certs' },
  { id:5,  name:'App Permissions',     icon:'📱', desc:'TCC DB audit, Full Disk Access, Accessibility' },
  { id:6,  name:'Malware Indicators',  icon:'🧫', desc:'LaunchAgents/Daemons, kexts, cron, IOC matching' },
  { id:7,  name:'Process Audit',       icon:'⚙️', desc:'DYLD injection, unsigned root procs, high-CPU' },
  { id:8,  name:'Startup Persistence', icon:'🚀', desc:'Login Items, shell profiles, native messaging hosts' },
  { id:9,  name:'Browser Security',    icon:'🌍', desc:'Extensions, outdated versions, Safe Browsing' },
  { id:10, name:'Patch Compliance',    icon:'📦', desc:'OSV.dev CVE lookup, Homebrew, Python/Node EOL' },
]

function computeScore(results) {
  const counts = { CRITICAL:0, HIGH:0, MEDIUM:0, LOW:0, SAFE:0 }
  Object.values(results).forEach(s =>
    (s.findings || []).forEach(f => { if (counts[f.severity] !== undefined) counts[f.severity]++ })
  )
  const total = Object.values(counts).reduce((a, b) => a + b, 0)
  if (!total) return { score: null, counts }
  const penalty = counts.CRITICAL*10 + counts.HIGH*7 + counts.MEDIUM*4 + counts.LOW*1
  return { score: Math.round(Math.max(0, 100 - (penalty / (total * 10) * 100))), counts }
}

export default function App() {
  const [scanState,      setScanState]      = useState('idle')
  const [moduleResults,  setModuleResults]  = useState({})
  const [selectedModule, setSelectedModule] = useState(null)
  const [selectedFinding,setSelectedFinding]= useState(null)
  const [score,          setScore]          = useState(null)
  const [stats,          setStats]          = useState({ CRITICAL:0, HIGH:0, MEDIUM:0, LOW:0, SAFE:0 })
  const esRef = useRef(null)

  const handleResults = useCallback((next) => {
    const { score, counts } = computeScore(next)
    setScore(score)
    setStats(counts)
  }, [])

  const startScan = useCallback(() => {
    if (scanState === 'scanning') return
    setScanState('scanning')
    setModuleResults({})
    setScore(null)
    setStats({ CRITICAL:0, HIGH:0, MEDIUM:0, LOW:0, SAFE:0 })
    setSelectedModule(null)
    setSelectedFinding(null)
    esRef.current?.close()

    const es = new EventSource('/api/scan')
    esRef.current = es

    es.onmessage = (e) => {
      try {
        const d = JSON.parse(e.data)
        if (d.done) { setScanState('complete'); es.close(); return }
        if (d.step_number) {
          setModuleResults(prev => {
            const next = { ...prev, [d.step_number]: d }
            handleResults(next)
            return next
          })
        }
      } catch {}
    }
    es.onerror = () => { setScanState('error'); es.close() }
  }, [scanState, handleResults])

  useEffect(() => () => esRef.current?.close(), [])

  const completedCount = Object.keys(moduleResults).length

  return (
    <div className="app">
      <Header scanState={scanState} onScan={startScan} score={score} />
      <main className="main-content">
        <ScoreSummary
          score={score} stats={stats} scanState={scanState}
          completedCount={completedCount} totalCount={10}
        />
        <div className={`content-grid${selectedModule ? ' has-panel' : ''}`}>
          <div>
            <div className="scan-grid-title">10 Security Modules</div>
            <ScanGrid
              modules={SCAN_MODULES} results={moduleResults}
              scanState={scanState}  selectedModule={selectedModule}
              onSelectModule={setSelectedModule}
            />
          </div>
          {selectedModule && (
            <FindingsPanel
              module={selectedModule}
              result={moduleResults[selectedModule.id]}
              onSelectFinding={setSelectedFinding}
              onClose={() => setSelectedModule(null)}
            />
          )}
        </div>
      </main>
      {selectedFinding && (
        <RemediationDrawer finding={selectedFinding} onClose={() => setSelectedFinding(null)} />
      )}
    </div>
  )
}
