/**
 * KinyaBot — Search Result Quality Processor (Web Search §10, §19, §20)
 * ═══════════════════════════════════════════════════════════════
 * Never blindly passes every result to Groq. Results are:
 *   • sanitized — safe URLs only (http/https, no localhost/private
 *     ranges → SSRF-safe rendering; §33), length-bounded text
 *   • deduplicated — by normalized URL and capped per domain
 *   • domain-filtered — admin allow/block lists + per-request include
 *   • ranked — authority, freshness (when freshness matters), snippet
 *     availability and provider position (relevance proxy)
 *   • selected — top N (config web_search_max_results)
 */
const { URL } = require('url')

/* Well-known authoritative domains get a ranking boost (§10) — a soft
   signal, never a hard restriction. */
const AUTHORITATIVE_DOMAINS = new Set([
  'wikipedia.org', 'github.com', 'developer.mozilla.org', 'stackoverflow.com',
  'react.dev', 'nodejs.org', 'python.org', 'docs.python.org', 'arxiv.org',
  'nature.com', 'science.org', 'reuters.com', 'apnews.com', 'bbc.com', 'bbc.co.uk',
  'nytimes.com', 'theguardian.com', 'openai.com', 'anthropic.com', 'google.com',
  'microsoft.com', 'apple.com', 'aws.amazon.com', 'cloud.google.com', 'vercel.com',
])

/* Domains never surfaced to users (safety net on top of admin blocklist). */
const ALWAYS_BLOCKED = new Set([
  'localhost', '127.0.0.1', '0.0.0.0', '::1', '169.254.169.254',
])

function safeDomain(host) {
  return String(host || '').toLowerCase().replace(/^www\./, '')
}

function registrableDomain(host) {
  // Cheap registrable-domain approximation: last two labels
  // (good enough for ranking/dedup; not for security decisions).
  const parts = safeDomain(host).split('.').filter(Boolean)
  if (parts.length <= 2) return parts.join('.')
  const twoLevelTlds = new Set(['co.uk', 'co.jp', 'com.au', 'co.nz', 'org.uk', 'gov.uk', 'ac.uk'])
  const last2 = parts.slice(-2).join('.')
  if (twoLevelTlds.has(last2)) return parts.slice(-3).join('.')
  return last2
}

/** SSRF-safe URL validation: only public http(s) URLs pass (§33). */
function safeUrl(rawUrl) {
  try {
    const u = new URL(String(rawUrl))
    if (u.protocol !== 'http:' && u.protocol !== 'https:') return null
    const host = u.hostname.toLowerCase()
    if (!host || ALWAYS_BLOCKED.has(host) || ALWAYS_BLOCKED.has(safeDomain(host))) return null
    if (host.endsWith('.local') || host.endsWith('.internal') || host.endsWith('.localhost')) return null
    // Private/reserved ranges (the backend never FETCHES these URLs —
    // they are only rendered as links — but we still never surface them)
    if (/^10\./.test(host) || /^192\.168\./.test(host) || /^172\.(1[6-9]|2\d|3[01])\./.test(host)) return null
    return u.toString()
  } catch { return null }
}

function sanitize(raw) {
  const url = safeUrl(raw?.url)
  if (!url) return null
  let domain = ''
  try { domain = registrableDomain(new URL(url).hostname) } catch { domain = '' }
  const title = String(raw?.title || '').replace(/\s+/g, ' ').trim().slice(0, 220)
  const snippet = String(raw?.snippet || '').replace(/\s+/g, ' ').trim().slice(0, 1200)
  if (!title && !snippet) return null
  const published = raw?.published_date && typeof raw.published_date === 'string'
    ? raw.published_date.slice(0, 40) : null
  return { title: title || url, url, domain, snippet, published_date: published }
}

function normalizeForDedup(url) {
  try {
    const u = new URL(url)
    u.hash = ''
    // strip common tracking params
    for (const p of [...u.searchParams.keys()]) {
      if (/^(utm_|ref|ref_src|fbclid|gclid)/i.test(p)) u.searchParams.delete(p)
    }
    let s = u.toString()
    if (s.endsWith('/')) s = s.slice(0, -1)
    return s.toLowerCase()
  } catch { return String(url).toLowerCase() }
}

function freshnessWeight(published, freshness) {
  if (!published || !freshness || freshness === 'noLimit') return 0
  const t = Date.parse(published)
  if (!Number.isFinite(t)) return 0
  const ageDays = (Date.now() - t) / 86400e3
  if (ageDays <= 1) return 2.5
  if (ageDays <= 7) return 2
  if (ageDays <= 30) return 1.4
  if (ageDays <= 90) return 0.8
  if (ageDays <= 365) return 0.3
  return -0.5 // stale results actively hurt freshness-sensitive queries
}

/**
 * Filter + rank + select search results.
 * @param {object} p
 * @param {Array}  p.sources        provider results [{title,url,snippet,published_date}]
 * @param {object} [p.opts]
 * @param {string} [p.opts.freshness]        freshness intent of the query
 * @param {number} [p.opts.maxResults]       top N to keep
 * @param {number} [p.opts.maxPerDomain]     per-domain cap (diversity, §10)
 * @param {string[]} [p.opts.allowedDomains] admin allow list (empty = all)
 * @param {string[]} [p.opts.blockedDomains] admin block list
 * @returns {{ selected: Array, stats: { received, afterSanitize, afterDedup, afterDomainFilter } }}
 */
function processResults({ sources = [], opts = {} } = {}) {
  const maxResults = Math.min(20, Math.max(1, Math.floor(Number(opts.maxResults) || 8)))
  const maxPerDomain = Math.min(10, Math.max(1, Math.floor(Number(opts.maxPerDomain) || 3)))
  const allowed = new Set((opts.allowedDomains || []).map(d => safeDomain(d)).filter(Boolean))
  const blocked = new Set((opts.blockedDomains || []).map(d => safeDomain(d)).filter(Boolean))

  const stats = { received: sources.length, afterSanitize: 0, afterDedup: 0, afterDomainFilter: 0 }

  const clean = sources.map(sanitize).filter(Boolean)
  stats.afterSanitize = clean.length

  // Dedup by URL (keep the first = provider's most relevant instance)
  const seen = new Set()
  const deduped = []
  for (const s of clean) {
    const key = normalizeForDedup(s.url)
    if (seen.has(key)) continue
    seen.add(key)
    deduped.push(s)
  }
  stats.afterDedup = deduped.length

  // Domain policy + diversity
  const perDomain = new Map()
  const filtered = []
  for (const s of deduped) {
    if (blocked.has(s.domain) || ALWAYS_BLOCKED.has(s.domain)) continue
    if (allowed.size && !allowed.has(s.domain)) continue
    const count = perDomain.get(s.domain) || 0
    if (count >= maxPerDomain) continue
    perDomain.set(s.domain, count + 1)
    filtered.push(s)
  }
  stats.afterDomainFilter = filtered.length

  // Rank: authority + freshness + content availability + provider position
  const ranked = filtered
    .map((s, i) => ({
      source: s,
      score:
        (AUTHORITATIVE_DOMAINS.has(s.domain) ? 1.5 : 0) +
        freshnessWeight(s.published_date, opts.freshness) +
        (s.snippet.length > 160 ? 0.4 : 0) +
        (s.published_date ? 0.2 : 0) +
        Math.max(0, (filtered.length - i)) * 0.02, // provider relevance order
    }))
    .sort((a, b) => b.score - a.score)
    .map(x => x.source)

  return { selected: ranked.slice(0, maxResults), stats }
}

module.exports = { processResults, safeUrl, sanitize, registrableDomain, AUTHORITATIVE_DOMAINS }
