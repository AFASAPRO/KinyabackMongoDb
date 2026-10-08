/**
 * KinyaBot — Web Search Orchestrator (Web Search §7, §26, §53)
 * ═══════════════════════════════════════════════════════════════
 * ONE reusable backend search service shared by Chat (auto + manual)
 * and the Agent's `web_search` tool (§30/§31) — never duplicated.
 *
 * Full workflow (§7):
 *   User Message → decision → query optimization → (cache) →
 *   LangSearch → filtering/ranking/selection → SOURCE blocks for Groq
 *   → grounded answer (+ structured sources to the client).
 *
 * Activity callbacks let the SSE layer stream elegant progress to the
 * UI (§13/§14) WITHOUT exposing internal prompts (§15):
 *   onStage('understanding' | 'searching' | 'reading' | 'preparing' | 'unavailable')
 *   onQuery(query)          — the ACTUAL query being searched
 *   onSources(count, domains)
 *
 * Failure policy (§25): LangSearch outages NEVER fail the chat turn —
 * the caller receives { performed: false, status: 'unavailable' } and
 * answers from existing knowledge, honestly labeled.
 */
const langSearch = require('./langSearchProvider')
const decision = require('./decision')
const optimizer = require('./queryOptimizer')
const results = require('./results')
const resultCache = require('./cache')
const rateLimiter = require('../rateLimiter')
const aiConfig = require('../ai/config')
const settings = require('../settings')

const SEARCH_DECISION = {
  REQUIRED: 'SEARCH_REQUIRED',
  OPTIONAL: 'SEARCH_OPTIONAL',
  NOT_NEEDED: 'SEARCH_NOT_NEEDED',
}

/* Map natural-language freshness hints to LangSearch freshness values (§19). */
function freshnessFor(text) {
  const t = String(text || '').toLowerCase()
  if (/\b(today|tonight|right now|just now|this hour|breaking|latest news)\b/.test(t)) return 'oneDay'
  if (/\b(this week|past week|last week|recently)\b/.test(t)) return 'oneWeek'
  if (/\b(this month|past month|last month)\b/.test(t)) return 'oneMonth'
  if (/\b(this year|past year|last year)\b/.test(t)) return 'oneYear'
  return 'noLimit' // historical research → no unnecessary restriction (§19)
}

function domainsOf(sources) {
  const domains = []
  for (const s of sources) {
    if (s.domain && !domains.includes(s.domain)) domains.push(s.domain)
  }
  return domains
}

/**
 * Decide + execute web searches for one user turn.
 * @param {object} p
 * @param {string}  p.userText          latest user message
 * @param {string}  [p.userId]          caller id — per-user search rate limit (§26)
 * @param {Array}   [p.history]         recent conversation [{role,content}]
 * @param {'auto'|'manual'|'agent'} [p.trigger]
 *        auto   — decision engine decides (Chat mode)
 *        manual — user explicitly chose Web Search (always search)
 *        agent  — the Agent tool invoked web_search (always search)
 * @param {Function[]} [p.callbacks]    { onStage, onQuery, onSources }
 * @returns {Promise<{
 *   performed, status, mode, queries, sources, resultCount, domains,
 *   durationMs, cached, usage, decision, error
 * }>}
 */
async function runWebSearch({ userText, userId = null, history = [], trigger = 'auto', callbacks = {} } = {}) {
  const cfg = settings.get()
  const started = Date.now()
  const out = {
    performed: false,
    status: 'unavailable',       // success | empty | unavailable | skipped | rate_limited
    mode: trigger,               // auto | manual | agent (persisted naming)
    queries: [],
    sources: [],
    resultCount: 0,
    domains: [],
    durationMs: 0,
    cached: false,
    usage: null,
    decision: null,
    error: null,
  }

  const onStage = (stage, data) => { try { callbacks.onStage?.(stage, data) } catch {} }
  const onQuery = (q) => { try { callbacks.onQuery?.(q) } catch {} }
  const onSources = (n, d) => { try { callbacks.onSources?.(n, d) } catch {} }

  try {
    /* ── 1. Decision (auto mode only — manual/agent always search) ── */
    onStage('understanding')
    if (trigger === 'auto') {
      const d = await decision.decideSearchNeed({ userText, history })
      out.decision = d.decision
      if (d.decision !== SEARCH_DECISION.REQUIRED && d.decision !== SEARCH_DECISION.OPTIONAL) {
        out.status = 'skipped'
        out.durationMs = Date.now() - started
        return out
      }
    }

    /* ── 2. Query optimization (§8) ────────────────────────────── */
    const plan = await optimizer.planQueries({
      userText, history, maxQueries: cfg.web_search_max_queries,
    })
    out.queries = plan.queries
    if (!out.queries.length) {
      out.status = 'empty'
      out.durationMs = Date.now() - started
      return out
    }

    /* ── 3. Rate limit + search execution (§26, cached §35) ───── */
    // Per-user server-side protection (§26): the frontend can NEVER
    // bypass the Pro restriction by calling the search path directly —
    // entitlement is resolved upstream and volume is capped here, at
    // the single shared enforcement point for Chat AND Agent (§30).
    if (userId) {
      const rl = rateLimiter.allow(userId, 'search', aiConfig.rateLimits.search)
      if (!rl.ok) {
        out.status = 'rate_limited'
        out.error = 'SEARCH_RATE_LIMITED'
        out.durationMs = Date.now() - started
        onStage('unavailable', { reason: 'rate_limited' })
        return out
      }
    }

    onStage('searching')
    const freshness = trigger === 'auto' ? freshnessFor(userText) : freshnessFor(userText)
    const perQueryLimit = Math.max(3, Math.floor((Number(cfg.web_search_max_results) || 8) / Math.min(out.queries.length, 2)))
    const allSources = []
    let anyCached = true
    let usageTokens = null
    const maxSearches = Math.max(1, Math.min(Number(cfg.web_search_max_queries) || 3, out.queries.length))
    const executed = out.queries.slice(0, maxSearches)

    const searchOne = async (query) => {
      onQuery(query)
      const key = resultCache.cacheKey({
        query, freshness, includeDomains: plan.includeDomains,
        excludeDomains: cfg.web_search_blocked_domains || [], count: perQueryLimit,
      })
      const hit = resultCache.get(key)
      if (hit && resultCache.isFresh(hit, { baseMinutes: cfg.web_search_cache_minutes, freshness })) {
        return { sources: hit.sources, usage: null, cached: true }
      }
      const r = await langSearch.webSearch({
        query,
        count: perQueryLimit + 2, // margin for filtering losses (§10)
        freshness,
        includeDomains: plan.includeDomains,
        excludeDomains: cfg.web_search_blocked_domains || [],
        timeoutMs: cfg.web_search_timeout_ms,
        withText: true, // bounded webpage text (§34)
      })
      return { sources: r.sources, usage: r.usage, cached: false }
    }

    // Parallel searches when multiple queries (§34) — capped above.
    const settled = await Promise.allSettled(executed.map(searchOne))
    for (const s of settled) {
      if (s.status === 'fulfilled') {
        allSources.push(...s.value.sources)
        if (!s.value.cached) anyCached = false
        if (s.value.usage && !usageTokens) usageTokens = s.value.usage
      } else {
        anyCached = false
        out.error = s.reason?.code || 'LANGSEARCH_ERROR'
      }
    }

    // Total provider outage (every query failed AND nothing retrieved)
    if (!allSources.length && settled.every(s => s.status === 'rejected')) {
      out.status = 'unavailable'
      out.durationMs = Date.now() - started
      onStage('unavailable')
      return out
    }

    /* ── 4. Result filtering / selection (§10, §20) ─────────────── */
    onStage('reading')
    const processed = results.processResults({
      sources: allSources,
      opts: {
        freshness,
        maxResults: Number(cfg.web_search_max_results) || 8,
        maxPerDomain: 3,
        allowedDomains: cfg.web_search_allowed_domains || [],
        blockedDomains: cfg.web_search_blocked_domains || [],
      },
    })
    out.sources = processed.selected
    out.resultCount = processed.selected.length
    out.domains = domainsOf(processed.selected)
    out.cached = anyCached && processed.selected.length > 0
    out.usage = usageTokens

    // Cache the merged selection per executed query (best-effort)
    if (processed.selected.length) {
      for (const q of executed) {
        resultCache.set(
          resultCache.cacheKey({ query: q, freshness, includeDomains: plan.includeDomains, excludeDomains: cfg.web_search_blocked_domains || [], count: perQueryLimit }),
          processed.selected,
          { baseMinutes: cfg.web_search_cache_minutes, freshness }
        )
      }
    }

    out.status = processed.selected.length ? 'success' : 'empty'
    out.performed = processed.selected.length > 0
    onSources(out.resultCount, out.domains)

    out.durationMs = Date.now() - started
    onStage(out.status === 'success' ? 'preparing' : 'preparing')
    return out
  } catch (err) {
    // Absolute guard: search must never throw into the chat path (§25)
    out.status = 'unavailable'
    out.error = err?.code || 'LANGSEARCH_ERROR'
    out.durationMs = Date.now() - started
    onStage('unavailable')
    return out
  }
}

/**
 * Build the structured SOURCE context block for Groq (§11).
 * The model must answer from this evidence and cite [n] markers.
 */
function buildSearchContextBlock(searchOutcome) {
  if (!searchOutcome || searchOutcome.status !== 'success' || !searchOutcome.sources.length) return ''
  const blocks = searchOutcome.sources.map((s, i) => {
    const date = s.published_date ? `\nPublished: ${s.published_date}` : ''
    return `SOURCE ${i + 1}\nTitle: ${s.title}\nURL: ${s.url}${date}\nSnippet: ${s.snippet.slice(0, 400)}`
  })
  return [
    `[Web Search Results — retrieved ${new Date().toISOString()} for the user's latest question]`,
    ...blocks,
  ].join('\n\n')
}

/** Grounding instructions appended to the system prompt (§11/§12). */
const GROUNDED_ANSWER_INSTRUCTIONS = [
  'Web-grounded answering rules:',
  'Answer the user\'s question using the WEB SEARCH RESULTS provided in context. Cite sources inline with bracketed numbers matching the source, e.g. [1] or [2][3], placed right after the claim they support.',
  'Do not invent facts that are not supported by the retrieved sources; when the sources are insufficient, say so clearly and answer from general knowledge while labeling what is uncertain.',
  'If sources disagree, briefly explain the disagreement. Keep the tone natural — citations are markers, not the focus.',
].join(' ')

module.exports = {
  runWebSearch,
  buildSearchContextBlock,
  GROUNDED_ANSWER_INSTRUCTIONS,
  freshnessFor,
  SEARCH_DECISION,
}
