import { useState } from 'react'

/**
 * AISuggestionPanel
 * Renders the AI-generated security remediation suggestion.
 * Used inside RemediationDrawer.jsx below the "How to Fix" section.
 *
 * Props:
 *   suggestion  {object}  - The suggestion object from the API response
 *   provider    {string}  - Provider name (e.g. 'gemini')
 *   model       {string}  - Model name (e.g. 'gemini-2.5-pro')
 */
export default function AISuggestionPanel({ suggestion, provider, model }) {
  if (!suggestion) return null

  const providerLabel =
    provider === 'gemini'
      ? `Gemini ${model?.includes('2.5') ? '2.5 Pro' : model || '2.5 Pro'}`
      : provider === 'ollama'
      ? `Local AI (${model || 'Ollama'})`
      : model || provider || 'AI'

  return (
    <div className="ai-suggestion-panel">
      {/* Header */}
      <div className="ai-suggestion-header">
        <span className="ai-suggestion-icon">🤖</span>
        <span className="ai-suggestion-title">AI Agent Recommendation</span>
        <span className="ai-provider-badge">Powered by {providerLabel}</span>
      </div>

      {/* Summary */}
      {suggestion.summary && (
        <div className="ai-suggestion-summary">
          {suggestion.summary}
        </div>
      )}

      {/* Steps */}
      {suggestion.steps && suggestion.steps.length > 0 && (
        <div className="ai-steps-list">
          {suggestion.steps.map((step) => (
            <div className="ai-step" key={step.step_number}>
              <div className="ai-step-header">
                <span className="ai-step-number">{step.step_number}</span>
                <span className="ai-step-title">{step.title}</span>
              </div>
              <div className="ai-step-description">{step.description}</div>
              {step.command && (
                <div className="cmd-block ai-cmd-block">
                  <div className="cmd-label">Terminal Command</div>
                  <pre className="cmd-code">{step.command}</pre>
                  <AIStepCopyButton text={step.command} />
                </div>
              )}
              {step.caution && (
                <div className="ai-step-caution">
                  <span>⚠️</span> <strong>Caution:</strong> {step.caution}
                </div>
              )}
            </div>
          ))}
        </div>
      )}

      {/* Verify command */}
      {suggestion.verify_command && (
        <div className="ai-verify-block">
          <div className="ai-verify-label">✅ Verify After Fix</div>
          <div className="cmd-block">
            <pre className="cmd-code">{suggestion.verify_command}</pre>
            <AIStepCopyButton text={suggestion.verify_command} />
          </div>
        </div>
      )}

      {/* References */}
      {suggestion.references && suggestion.references.length > 0 && (
        <div className="ai-references">
          <div className="ai-references-label">📚 References</div>
          <ul className="ai-references-list">
            {suggestion.references.map((ref, i) => (
              <li key={i}>
                <a href={ref} target="_blank" rel="noopener noreferrer">
                  {ref}
                </a>
              </li>
            ))}
          </ul>
        </div>
      )}

      {/* Footer */}
      <div className="ai-suggestion-footer">
        <div className="ai-disclaimer">
          ⚠️ Review all commands before running. MacSentry never auto-executes AI suggestions.
        </div>
        <div className="ai-privacy-badge">
          🔒 Sensitive data removed before sending
        </div>
      </div>
    </div>
  )
}

/**
 * Copy button reusing the same pattern as CopyButton in RemediationDrawer.
 */
function AIStepCopyButton({ text }) {
  const [copied, setCopied] = useState(false)
  return (
    <button
      className={`copy-btn${copied ? ' copied' : ''}`}
      onClick={() => {
        navigator.clipboard.writeText(text)
        setCopied(true)
        setTimeout(() => setCopied(false), 1800)
      }}
    >
      {copied ? '✓ Copied' : 'Copy'}
    </button>
  )
}
