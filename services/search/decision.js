/**
 * KinyaBot — Search Decision Engine (Web Search §5)
 * ═══════════════════════════════════════════════════════════════
 * Decides whether a user's message needs live web information.
 *
 * Outcome values:
 *   SEARCH_REQUIRED    — clearly needs current/external info
 *   SEARCH_OPTIONAL    — would benefit (verification, freshness edge)
 *   SEARCH_NOT_NEEDED  — confidently answerable without the web
 *
 * Two layers (§5 — NOT a simplistic keyword detector):
 *   1. Fast heuristic pre-filter — cheap, deterministic. Only used to
 *      SKIP the model call when the answer is obvious in BOTH
 *      directions, and as a SAFE FALLBACK when the model itself is
 *      unavailable (conservative: no search).
 *   2. Model classification — a tiny Groq completion classifies the
 *      request considering freshness needs, current events, explicit
 *      search commands, research requests, prices, availability,
 *      sports, public figures, docs, news, and the surrounding
 *      conversation context (§22 follow-ups: "How old is he?").
 *
 * The model NEVER sees private prompts in the UI — only the decision
 * outcome is surfaced (§15).
 */
const { chatComplete } = require('../ai/groqProvider')

const REQUIRED = 'SEARCH_REQUIRED'
const OPTIONAL = 'SEARCH_OPTIONAL'
const NOT_NEEDED = 'SEARCH_NOT_NEEDED'

/* ── Layer 1: deterministic pre-filter ─────────────────────────── */
/* Explicit search commands → always worth searching (still gated by
   plan/config upstream). Kept narrow to avoid false positives.    */
const EXPLICIT_SEARCH_RE = /\b(search( the web| online| for)?|google|look up|lookup|find (out|the latest|recent|current|news)|latest news|breaking|what happened|who won|current (price|version|ceo|status|news)|right now|as of (today|this week|this month)|today'?s?|this week|this month|up to date|up-to-date)\b/i

/* Strong "static knowledge" signals — explain/define/code-help style
   questions that models answer confidently from training.          */
const STATIC_RE = /^\s*(what is|what are|who is|who was|explain|define|describe|how do(es)?|write|create|build|make|generate|refactor|debug|fix|translate|summarize( this| the)?|help me (understand|write|fix|build|learn)|give me (a|an|some) (idea|example|tip)|teach me)\b/i

/* Ambiguity: neither filter fires → ask the model (layer 2). */
function heuristicDecision(userText) {
  const t = String(userText || '').trim()
  if (!t) return NOT_NEEDED
  if (EXPLICIT_SEARCH_RE.test(t)) return REQUIRED
  if (STATIC_RE.test(t)) {
    // "what is X" CAN still need freshness (e.g. "what is the latest React version")
    // — only the explicit-current patterns above catch that; otherwise static.
    return NOT_NEEDED
  }
  return null // inconclusive → model classification
}

/* ── Layer 2: model classification ─────────────────────────────── */
const DECISION_SYSTEM_PROMPT = `You are the web-search decision engine of an AI assistant. Decide if answering the user's LATEST message requires CURRENT information from the public web.

Answer with ONLY a JSON object, no prose:
{"decision":"SEARCH_REQUIRED"|"SEARCH_OPTIONAL"|"SEARCH_NOT_NEEDED"}

Guidance:
- SEARCH_REQUIRED: current events, news, recent releases/versions, prices, availability, sports results, weather, who currently holds a position, anything with "today/latest/current/right now", explicit requests to search or look up, or facts that change quickly.
- SEARCH_OPTIONAL: verifiable facts where fresh sources would improve trust (company info, statistics, documentation details), or research/comparison requests that benefit from sources.
- SEARCH_NOT_NEEDED: general explanations, definitions, coding help, creative writing, math, advice, conversation, anything confidently answerable from an LLM's existing knowledge.
- Use the conversation context to resolve pronouns ("How old is he?" after a question about a person). If the referent needs current info, search.
- When unsure between NOT_NEEDED and OPTIONAL, choose OPTIONAL; between OPTIONAL and REQUIRED choose OPTIONAL.`

function parseDecision(text) {
  if (!text) return null
  const m = String(text).match(/\{\s*"decision"[\s\S]*?\}/i) || String(text).match(/\{[\s\S]*\}/)
  if (!m) return null
  try {
    const obj = JSON.parse(m[0])
    const d = String(obj.decision || '').toUpperCase()
    if (d === REQUIRED || d === OPTIONAL || d === NOT_NEEDED) return d
  } catch { /* fall through */ }
  return null
}

/**
 * Decide whether web search is needed.
 * @param {object} p
 * @param {string}  p.userText  the latest user message
 * @param {Array}   [p.history] recent conversation [{role, content}] for context
 * @returns {Promise<{decision: string, source: 'heuristic'|'model'|'fallback', reason?: string}>}
 */
async function decideSearchNeed({ userText, history = [] } = {}) {
  const heuristic = heuristicDecision(userText)
  // Deterministic answers where BOTH filters agree — skip the model call.
  // REQUIRED always goes through the model? No: an explicit search command
  // is a direct user instruction — honor it without a model round-trip.
  if (heuristic === REQUIRED) return { decision: REQUIRED, source: 'heuristic' }
  if (heuristic === NOT_NEEDED && EXPLICIT_SEARCH_RE.test(userText || '') === false && STATIC_RE.test(userText || '')) {
    // Static-looking question — still verify with the model ONLY when it
    // mentions fast-changing topics; otherwise skip for speed (§34).
    const fastChanging = /\b(latest|current|newest|today|now|price|version|release|update)\b/i.test(userText || '')
    if (!fastChanging) return { decision: NOT_NEEDED, source: 'heuristic' }
  }

  // Model classification with a tight token budget (fast, §34).
  const context = (Array.isArray(history) ? history : [])
    .filter(m => m && ['user', 'assistant'].includes(m.role) && (m.content || '').trim())
    .slice(-4)
    .map(m => `${m.role === 'user' ? 'User' : 'Assistant'}: ${String(m.content).slice(0, 300)}`)
    .join('\n')

  try {
    const { text } = await chatComplete({
      messages: [
        { role: 'system', content: DECISION_SYSTEM_PROMPT },
        { role: 'user', content: context ? `Conversation so far:\n${context}\n\nLatest message: ${String(userText).slice(0, 600)}` : String(userText).slice(0, 800) },
      ],
      maxTokens: 24,
      temperature: 0,
    })
    const decision = parseDecision(text)
    if (decision) return { decision, source: 'model' }
  } catch { /* model unavailable → fall back below */ }

  // Safe fallback: heuristic only; inconclusive ⇒ no search. Never
  // let a decision-engine failure break or slow the chat (§34).
  return { decision: heuristic === REQUIRED ? REQUIRED : (heuristic === OPTIONAL ? OPTIONAL : NOT_NEEDED), source: 'fallback' }
}

module.exports = { decideSearchNeed, heuristicDecision, parseDecision, SEARCH_REQUIRED: REQUIRED, SEARCH_OPTIONAL: OPTIONAL, SEARCH_NOT_NEEDED: NOT_NEEDED }
