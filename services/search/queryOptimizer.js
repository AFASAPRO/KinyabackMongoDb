/**
 * KinyaBot — Search Query Optimizer (Web Search §8)
 * ═══════════════════════════════════════════════════════════════
 * Transforms the user's request into effective search queries before
 * calling LangSearch.
 *
 *   • Model-based rewrite: adds the current date context when the
 *     question is freshness-sensitive, resolves pronouns from the
 *     conversation, and — for comparison/research questions — emits
 *     MULTIPLE focused queries (§9 multi-search, capped).
 *   • Coding/technical questions may pin authoritative domains
 *     (react.dev, developer.mozilla.org, github.com, nodejs.org…)
 *     ONLY when the user explicitly asks for official/authoritative
 *     documentation (§8: do not unnecessarily restrict).
 *   • Fallback: the raw user text (still a valid natural-language
 *     query) so a model outage can never block searching (§25).
 */
const { chatComplete } = require('../ai/groqProvider')

const MAX_QUERIES_HARD_CAP = 3

const OPTIMIZER_SYSTEM_PROMPT = `You convert a user's request into effective web search queries. Today's date is {DATE}.

Rules:
- Output ONLY a JSON array of 1 to {MAX} query strings — no prose, no markdown.
- Each query is a self-contained web search (resolve pronouns from context; never use "he/she/it" alone).
- Add the current month/year when freshness matters ("What happened in AI today" → include the date).
- For comparisons across products/companies/people, emit one focused query per subject.
- Keep queries under 12 words each, natural-language, no quotes inside.
- Never answer the question — only produce queries.`

/* Domain hints used ONLY when the user explicitly asks for official /
   authoritative documentation (§8, §20). */
const AUTHORITATIVE_HINTS = [
  { re: /\bofficial (react|reactjs)\b|\breact(16|17|18|19)? docs(umentation)?\b/i, domains: ['react.dev'] },
  { re: /\bjavascript|typescript|dom api\b/i, domains: ['developer.mozilla.org'] },
  { re: /\bnode\.?js\b/i, domains: ['nodejs.org', 'github.com'] },
  { re: /\bgithub (repo|repository|project)\b/i, domains: ['github.com'] },
]

function buildUserPrompt({ userText, history, maxQueries }) {
  const context = (Array.isArray(history) ? history : [])
    .filter(m => m && ['user', 'assistant'].includes(m.role) && (m.content || '').trim())
    .slice(-4)
    .map(m => `${m.role === 'user' ? 'User' : 'Assistant'}: ${String(m.content).slice(0, 240)}`)
    .join('\n')
  const sys = OPTIMIZER_SYSTEM_PROMPT
    .replace('{DATE}', new Date().toISOString().slice(0, 10))
    .replace('{MAX}', String(maxQueries))
  const user = context
    ? `Conversation:\n${context}\n\nLatest request: ${String(userText).slice(0, 600)}`
    : String(userText).slice(0, 800)
  return { sys, user }
}

function parseQueries(text) {
  if (!text) return null
  const m = String(text).match(/\[[\s\S]*\]/)
  if (!m) return null
  try {
    const arr = JSON.parse(m[0])
    if (!Array.isArray(arr)) return null
    const queries = arr
      .map(q => String(q || '').replace(/\s+/g, ' ').trim().slice(0, 200))
      .filter(q => q.length >= 2)
    return queries.length ? queries.slice(0, MAX_QUERIES_HARD_CAP) : null
  } catch { return null }
}

/**
 * Plan the queries for a search turn.
 * @param {object} p
 * @param {string}  p.userText        the latest user message
 * @param {Array}   [p.history]       recent conversation turns
 * @param {number}  [p.maxQueries]    cap from admin config
 * @returns {Promise<{queries: string[], source: 'model'|'fallback', includeDomains: string[]}>}
 */
async function planQueries({ userText, history = [], maxQueries = MAX_QUERIES_HARD_CAP } = {}) {
  const cap = Math.min(MAX_QUERIES_HARD_CAP, Math.max(1, Math.floor(Number(maxQueries) || MAX_QUERIES_HARD_CAP)))
  const fallback = { queries: [String(userText || '').trim().slice(0, 300)].filter(Boolean), source: 'fallback', includeDomains: [] }
  if (!fallback.queries.length) return { queries: [], source: 'fallback', includeDomains: [] }

  try {
    const { sys, user } = buildUserPrompt({ userText, history, maxQueries: cap })
    const { text } = await chatComplete({
      messages: [
        { role: 'system', content: sys },
        { role: 'user', content: user },
      ],
      maxTokens: 120,
      temperature: 0.2,
    })
    const queries = parseQueries(text)
    if (queries && queries.length) {
      // Explicit authoritative-domain requests (§8) — never otherwise.
      const includeDomains = []
      for (const hint of AUTHORITATIVE_HINTS) {
        if (/\b(official|docs|documentation|authoritative)\b/i.test(userText) && hint.re.test(userText))
          for (const d of hint.domains) if (!includeDomains.includes(d)) includeDomains.push(d)
      }
      return { queries: queries.slice(0, cap), source: 'model', includeDomains: includeDomains.slice(0, 3) }
    }
  } catch { /* optimizer outage → raw-query fallback (§25) */ }

  return fallback
}

module.exports = { planQueries, parseQueries, MAX_QUERIES_HARD_CAP }
