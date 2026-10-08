/**
 * KinyaBot — LangSearch Web Search Provider (Web Search §4)
 * ═══════════════════════════════════════════════════════════════
 * The ONLY place that talks to the LangSearch Web Search API.
 * Implemented against the OFFICIAL current API (docs.langsearch.com):
 *
 *   POST {endpoint}/v1/web-search
 *   Authorization: Bearer <LANGSEARCH_API_KEY>      (server-side only, §3)
 *
 *   body: {
 *     query           — non-empty natural-language query (required)
 *     count           — 1..50 (default 10)
 *     freshness       — noLimit | oneDay | oneWeek | oneMonth | oneYear
 *                       | YYYY-MM-DD | YYYY-MM-DD..YYYY-MM-DD
 *     includeDomains  — string[] (omit/empty = no restriction)
 *     excludeDomains  — string[]
 *     contents.text   — true | { maxCharacters } (full webpage text;
 *                       text mode REPLACES snippet in each result)
 *   }
 *
 *   200 → { code, log_id, msg, data: { webPages: { value: [ { id, name,
 *           url, displayUrl, snippet, datePublished, text } ] } },
 *           usage: { input_tokens, output_tokens } }
 *
 *   Errors: use the HTTP STATUS as the primary signal. Error bodies
 *   carry `message` OR `msg` and a `log_id`. 401 auth · 403 access ·
 *   429 rate/daily allowance · 5xx provider (bounded retry).
 *
 * This module NEVER logs or returns the API key. Node ≥18 global
 * fetch is used (no SDK dependency); tests can stub it via
 * __setFetchImpl().
 */
const aiConfig = require('../ai/config')

/* Injectable HTTP layer (tests stub this; production uses fetch). */
let fetchImpl = (...args) => fetch(...args)

/* Provider-shaped search result (SearchSource, §47). */
function toSearchSource(raw) {
  if (!raw || typeof raw !== 'object') return null
  const url = typeof raw.url === 'string' ? raw.url.trim() : ''
  if (!url) return null
  const title = typeof raw.name === 'string' ? raw.name.trim() : ''
  // text mode returns `text`; snippet mode returns `snippet`
  const snippet = (typeof raw.text === 'string' && raw.text.trim()) ||
                  (typeof raw.snippet === 'string' ? raw.snippet.trim() : '') || ''
  const published = typeof raw.datePublished === 'string' && raw.datePublished.trim()
    ? raw.datePublished.trim() : null
  return {
    title: title || url,
    url,
    snippet,
    published_date: published,
  }
}

/* Map a coded failure into an error the API layer can translate into
   an honest user message (§25). Never includes the key or raw body. */
function normalizeError(status, bodyText, cause) {
  let code = 'LANGSEARCH_ERROR'
  if (status === 401 || status === 403) code = 'LANGSEARCH_AUTH'
  else if (status === 429) code = 'LANGSEARCH_QUOTA'
  else if (status === 400) code = 'LANGSEARCH_BAD_REQUEST'
  else if (status === 0 || cause?.name === 'AbortError') code = 'LANGSEARCH_TIMEOUT'
  const err = new Error(`LangSearch request failed${status ? ` (${status})` : ''}`)
  err.code = code
  err.status = status || 502
  err.userSafe = true
  err.userMessage = 'Web Search is temporarily unavailable. I can still answer using my existing knowledge.'
  return err
}

/**
 * Execute ONE web search against LangSearch.
 * @param {object} p
 * @param {string}   p.query            required, 1..1000 chars
 * @param {number}   [p.count]          results to request (1..50)
 * @param {string}   [p.freshness]      noLimit|oneDay|oneWeek|oneMonth|oneYear
 * @param {string[]} [p.includeDomains] restrict to these domains
 * @param {string[]} [p.excludeDomains] exclude these domains
 * @param {number}   [p.timeoutMs]      abort guard
 * @param {boolean}  [p.withText]       request bounded full webpage text
 * @returns {Promise<{ sources: Array, usage: {input_tokens,output_tokens}|null, logId: string|null }>}
 */
async function webSearch(p = {}) {
  const cfg = aiConfig.langSearch
  const query = String(p.query || '').trim().slice(0, 1000)
  if (!query) {
    const e = new Error('A non-empty search query is required')
    e.code = 'LANGSEARCH_BAD_REQUEST'; e.status = 400; e.userSafe = true
    throw e
  }
  if (!cfg.apiKey) {
    const e = new Error('Web Search is not configured')
    e.code = 'LANGSEARCH_NOT_CONFIGURED'; e.status = 503; e.userSafe = true
    throw e
  }

  const count = Math.min(cfg.maxCount, Math.max(1, Math.floor(Number(p.count) || cfg.defaultCount)))
  const body = { query, count }
  const FRESHNESS = new Set(['noLimit', 'oneDay', 'oneWeek', 'oneMonth', 'oneYear'])
  if (p.freshness && FRESHNESS.has(p.freshness)) body.freshness = p.freshness
  if (Array.isArray(p.includeDomains) && p.includeDomains.length)
    body.includeDomains = p.includeDomains.map(d => String(d).toLowerCase().trim()).filter(Boolean).slice(0, 20)
  if (Array.isArray(p.excludeDomains) && p.excludeDomains.length)
    body.excludeDomains = p.excludeDomains.map(d => String(d).toLowerCase().trim()).filter(Boolean).slice(0, 20)
  // Bounded webpage text (§34 performance: minimum useful context only)
  if (p.withText) body.contents = { text: { maxCharacters: cfg.textMaxCharacters } }

  const controller = new AbortController()
  const timer = setTimeout(() => controller.abort(new Error('LangSearch timed out')), p.timeoutMs || cfg.timeoutMs)
  let res
  try {
    res = await fetchImpl(cfg.endpoint, {
      method: 'POST',
      headers: {
        'Authorization': `Bearer ${cfg.apiKey}`,
        'Content-Type': 'application/json',
      },
      body: JSON.stringify(body),
      signal: controller.signal,
    })
  } catch (err) {
    throw normalizeError(0, null, err)
  } finally {
    clearTimeout(timer)
  }

  let payload = null
  try { payload = await res.json() } catch { /* non-JSON error body */ }

  if (!res.ok) {
    throw normalizeError(res.status, payload ? JSON.stringify(payload).slice(0, 300) : null)
  }
  // The API also signals failures in-body — trust the HTTP status first,
  // but guard against 200-with-error-code shapes.
  if (payload && typeof payload.code === 'number' && payload.code !== 200 && payload.code !== 0) {
    throw normalizeError(Number(payload.code), null)
  }

  const pages = payload?.data?.webPages?.value
  if (!Array.isArray(pages)) {
    // Malformed response — treat as provider failure (§25)
    throw normalizeError(res.status || 502, null)
  }

  const sources = pages.map(toSearchSource).filter(Boolean)
  const usage = payload?.usage && Number.isFinite(Number(payload.usage.input_tokens))
    ? { input_tokens: Number(payload.usage.input_tokens) || 0, output_tokens: Number(payload.usage.output_tokens) || 0 }
    : null

  return { sources, usage, logId: payload?.log_id || null }
}

function isConfigured() {
  return !!aiConfig.langSearch.apiKey
}

/* Test hook — swap the HTTP layer without network access. */
function __setFetchImpl(fn) { fetchImpl = fn }

module.exports = { webSearch, isConfigured, toSearchSource, __setFetchImpl }
