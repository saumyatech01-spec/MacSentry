import { useState, useCallback } from 'react'

// Use relative URL so Vite proxy (or Flask reverse proxy in prod) routes to the AI API
// In dev: Vite proxies /api/ai-suggestion → localhost:5002
// In prod: serve the built UI from behind the same host that serves the API
const AI_API_URL = import.meta.env.VITE_AI_API_URL ?? ''

/**
 * useAISuggestion
 * Manages the lifecycle of an AI suggestion request:
 *   idle → loading → success | error
 *
 * @param {object} finding  - The finding object from the scan result
 * @returns {{ status, suggestion, error, getSuggestion, reset }}
 */
export function useAISuggestion(finding) {
  const [status, setStatus] = useState('idle')   // idle | loading | success | error
  const [suggestion, setSuggestion] = useState(null)
  const [error, setError] = useState(null)

  const getSuggestion = useCallback(async () => {
    if (!finding) return
    setStatus('loading')
    setSuggestion(null)
    setError(null)

    try {
      const payload = {
        check_id:    finding.check_id    ?? finding.id    ?? '',
        title:       finding.title       ?? finding.name  ?? '',
        description: finding.description ?? '',
        severity:    finding.severity    ?? '',
        platform:    finding.platform    ?? '',
        evidence:    finding.evidence    ?? finding.details ?? '',
      }

      const res = await fetch(`${AI_API_URL}/api/ai-suggestion`, {
        method:  'POST',
        headers: { 'Content-Type': 'application/json' },
        body:    JSON.stringify(payload),
      })

      if (!res.ok) {
        const body = await res.json().catch(() => ({}))
        throw new Error(body.detail || `Server error ${res.status}`)
      }

      const data = await res.json()
      setSuggestion(data)
      setStatus('success')
    } catch (err) {
      setError(err.message || 'Unknown error')
      setStatus('error')
    }
  }, [finding])

  const reset = useCallback(() => {
    setStatus('idle')
    setSuggestion(null)
    setError(null)
  }, [])

  return { status, suggestion, error, getSuggestion, reset }
}
