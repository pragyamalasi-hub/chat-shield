// =============================================================================
// hfClassifier.js — Hugging Face Inference API helper
//
// Performs zero-shot classification using facebook/bart-large-mnli.
// This module is intentionally kept separate so it can be tested in isolation
// and swapped for another model without touching App.jsx.
// =============================================================================

const HF_API_URL = 'http://localhost:3001/hf'

// Labels the model will classify against.
// Order doesn't matter — BART-MNLI scores each independently.
const CANDIDATE_LABELS = ["benign user query",
  "prompt injection attack",
  "jailbreak attempt",
  "trying to access system prompt",
  "trying to bypass safety restrictions",
  "roleplay to override AI behavior"
];

// How long to wait before declaring the request a timeout (ms)
const REQUEST_TIMEOUT_MS = 12000

/**
 * Possible status values returned by classifyWithHF:
 *   'success'   — got a valid response from the API
 *   'loading'   — model is still warming up (503); caller should retry
 *   'no_key'    — VITE_HF_API_KEY env var is not set
 *   'rate_limit'— 429 received; caller should back off
 *   'error'     — any other failure
 */

/**
 * Call the Hugging Face Inference API and return a structured result.
 *
 * @param {string} text  — the user's raw prompt
 * @returns {Promise<HFResult>}
 *
 * HFResult shape:
 * {
 *   status: 'success' | 'loading' | 'no_key' | 'rate_limit' | 'error',
 *   classification: 'SAFE' | 'SUSPICIOUS' | 'ADVERSARIAL' | null,
 *   scores: { safe: number, adversarial: number, jailbreakAttempt: number } | null,
 *   topLabel: string | null,
 *   topScore: number | null,
 *   errorMessage: string | null,
 * }
 */
export async function classifyWithHF(text) {
  // ── Guard: API key must be present ──────────────────────────────────────────
  const apiKey = import.meta.env.VITE_HF_API_KEY
  if (!apiKey || apiKey.trim() === '') {
    return {
      status: 'no_key',
      classification: null,
      scores: null,
      topLabel: null,
      topScore: null,
      errorMessage: 'VITE_HF_API_KEY is not set. Add it to your .env file.',
    }
  }

  // ── Guard: don't waste tokens on empty/very short text ─────────────────────
  if (!text || text.trim().length < 3) {
    return {
      status: 'success',
      classification: 'SAFE',
      scores: { safe: 1, adversarial: 0, jailbreakAttempt: 0 },
      topLabel: 'safe',
      topScore: 1,
      errorMessage: null,
    }
  }

  // ── Build fetch with AbortController for timeout ────────────────────────────
  const controller = new AbortController()
  const timeoutId = setTimeout(() => controller.abort(), REQUEST_TIMEOUT_MS)

  try {
    const response = await fetch(HF_API_URL, {
      method: 'POST',
      headers: {
        Authorization: `Bearer ${apiKey}`,
        'Content-Type': 'application/json',
      },
      // multi_label: true lets the model score all labels independently
      // (vs. forcing them to sum to 1). This gives us richer signal.
      body: JSON.stringify({
        prompt: text,
        parameters: {
          candidate_labels: CANDIDATE_LABELS,
          multi_label: true,
        },
      }),
      signal: controller.signal,
    })

    clearTimeout(timeoutId)

    // ── Handle non-200 responses ───────────────────────────────────────────────
    if (response.status === 503) {
      // Model is booting up — happens frequently with free-tier inference
      const body = await response.json().catch(() => ({}))
      return {
        status: 'loading',
        classification: null,
        scores: null,
        topLabel: null,
        topScore: null,
        errorMessage: body.error || 'Model is loading. Please wait a moment.',
      }
    }

    if (response.status === 429) {
      return {
        status: 'rate_limit',
        classification: null,
        scores: null,
        topLabel: null,
        topScore: null,
        errorMessage: 'Rate limit reached. Falling back to local detection.',
      }
    }

    if (!response.ok) {
      const body = await response.json().catch(() => ({}))
      return {
        status: 'error',
        classification: null,
        scores: null,
        topLabel: null,
        topScore: null,
        errorMessage: body.error || `HTTP ${response.status}`,
      }
    }

    // ── Parse successful response ──────────────────────────────────────────────
    // HF returns: { sequence, labels: string[], scores: number[] }
    // labels and scores are parallel arrays, sorted highest-score first.
    const data = await response.json()

    return {
      status: 'success',
      classification: data.classification,
      scores: {
        safe: data.classification === 'SAFE' ? 1 : 0,
        adversarial: data.classification === 'ADVERSARIAL' ? 1 : 0,
        jailbreakAttempt: data.classification === 'ADVERSARIAL' ? 1 : 0,
      },
      topLabel: data.classification,
      topScore: data.confidence,
      errorMessage: null,
    }

    // Build a keyed score map for easy lookup
    const scoreMap = {}
    data.labels.forEach((label, i) => {
      scoreMap[label] = data.scores[i]
    })

    // ✅ Correct mapping from your actual labels
    const safeScore = scoreMap["benign user query"] ?? 0

    const adversarialScore = Math.max(
      scoreMap["prompt injection attack"] ?? 0,
      scoreMap["trying to access system prompt"] ?? 0,
      scoreMap["trying to bypass safety restrictions"] ?? 0,
      scoreMap["roleplay to override AI behavior"] ?? 0
    )

    const jailbreakScore = scoreMap["jailbreak attempt"] ?? 0

    const topLabel = data.labels[0]  // highest scoring label
    const topScore = data.scores[0]

    // ── Map HF labels → internal classification ────────────────────────────────
    // Decision logic:
    //   • If "adversarial" OR "jailbreak attempt" score > threshold → ADVERSARIAL
    //   • Else if any non-safe score is somewhat significant → SUSPICIOUS
    //   • Otherwise → SAFE
    //
    // Thresholds are intentionally conservative to reduce false positives.
    const ADVERSARIAL_THRESHOLD = 0.35   // high confidence needed for hard block
    const SUSPICIOUS_THRESHOLD  = 0.20   // lower bar for a yellow warning

    let hfClassification
    const combinedAttackScore = Math.max(adversarialScore, jailbreakScore)

    if (combinedAttackScore >= ADVERSARIAL_THRESHOLD) {
      hfClassification = 'ADVERSARIAL'
    } else if (combinedAttackScore >= SUSPICIOUS_THRESHOLD) {
      hfClassification = 'SUSPICIOUS'
    } else {
      hfClassification = 'SAFE'
    }

    return {
      status: 'success',
      classification: hfClassification,
      scores: {
        safe: +safeScore.toFixed(4),
        adversarial: +adversarialScore.toFixed(4),
        jailbreakAttempt: +jailbreakScore.toFixed(4),
      },
      topLabel,
      topScore: +topScore.toFixed(4),
      errorMessage: null,
    }
  } catch (err) {
    clearTimeout(timeoutId)

    // AbortController fired = timeout
    if (err.name === 'AbortError') {
      return {
        status: 'error',
        classification: null,
        scores: null,
        topLabel: null,
        topScore: null,
        errorMessage: `Request timed out after ${REQUEST_TIMEOUT_MS / 1000}s.`,
      }
    }

    return {
      status: 'error',
      classification: null,
      scores: null,
      topLabel: null,
      topScore: null,
      errorMessage: err.message || 'Unknown network error.',
    }
  }
}

/**
 * Merge local detection result with HF classification into a single final verdict.
 *
 * Fusion logic (conservative — err toward flagging):
 *   1. If EITHER system says ADVERSARIAL → final is ADVERSARIAL
 *   2. Else if EITHER says SUSPICIOUS   → final is SUSPICIOUS
 *   3. Both agree on SAFE               → final is SAFE
 *
 * The fused confidence is a weighted average:
 *   local engine  → 40% weight (fast, rule-based, lower FP on known patterns)
 *   HF model      → 60% weight (semantic understanding, catches novel phrasing)
 *   If HF failed  → 100% local weight (graceful degradation)
 *
 * @param {object} localResult   — output of analyzeLocally()
 * @param {object|null} hfResult — output of classifyWithHF(), or null if pending/failed
 * @returns {{ classification: string, confidence: number, hfAvailable: boolean }}
 */
export function fuseResults(localResult, hfResult) {
  const localClass = localResult.classification  // 'SAFE' | 'SUSPICIOUS' | 'ADVERSARIAL'
  const localConf  = localResult.confidence       // 0–1

  // If HF didn't return a usable result, fall back to local only
  if (!hfResult || hfResult.status !== 'success' || !hfResult.classification) {
    return {
      classification: localClass,
      confidence: localConf,
      hfAvailable: false,
    }
  }

  const hfClass = hfResult.classification   // 'SAFE' | 'SUSPICIOUS' | 'ADVERSARIAL'
  // For HF confidence: use 1 - safeScore as a "risk score" (0 = definitely safe, 1 = not safe)
  const hfRiskScore = 1 - (hfResult.scores?.safe ?? 1)

  // Weighted fusion of confidence scores
  const fusedConfidence = Math.min(localConf * 0.30 + hfRiskScore * 0.70, 1)

  // Classification fusion — most severe wins
  const SEVERITY = { SAFE: 0, SUSPICIOUS: 1, ADVERSARIAL: 2 }
  const localSev  = SEVERITY[localClass]  ?? 0
  const hfSev     = SEVERITY[hfClass]     ?? 0
  const finalSev  = Math.max(localSev, hfSev)
  const finalClass = Object.keys(SEVERITY).find(k => SEVERITY[k] === finalSev) ?? 'SAFE'

  return {
    classification: finalClass,
    confidence: +fusedConfidence.toFixed(4),
    hfAvailable: true,
  }
}
