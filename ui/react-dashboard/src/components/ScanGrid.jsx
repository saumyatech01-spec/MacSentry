import ScanCard from './ScanCard'

export default function ScanGrid({ modules, results, scanState, selectedModule, onSelectModule }) {
  return (
    <div className="scan-grid">
      {modules.map((mod, i) => (
        <ScanCard
          key={mod.id} module={mod} result={results[mod.id]}
          scanState={scanState}  isSelected={selectedModule?.id === mod.id}
          animDelay={i * 40}
          onClick={() => onSelectModule(selectedModule?.id === mod.id ? null : mod)}
        />
      ))}
    </div>
  )
}
