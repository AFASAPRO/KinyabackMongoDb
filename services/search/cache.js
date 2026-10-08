/**
 * KinyaBot — Search Result Cache (Web Search §35)
 * ═══════════════════════════════════════════════════════════════
 * In-process TTL cache for identical/recent searches.
 *
 *   key     = normalized query + freshness + domain filters + count
 *   value   = { sources, cachedAt }
 *   ttl     = admin-configured base (web_search_cache_minutes),
 *             SHRUNK for freshness-sensitive queries so users who ask
 *             for "today"/"latest" never get stale answers (§35).
 *
 * Bounded size (LRU-ish trim) so a busy instance cannot grow forever.
 */
const MAX_ENTRIES = 300

const FRESHNESS_TTL_FRACTION = {
  oneDay: 1 / 3,     // 30 min base → 10 min for daily news
  oneWeek: 1 / 2,
  oneMonth: 1,
  oneYear: 1,
  noLimit: 1,
}

const cache = new Map() // key → { sources, cachedAt }

function cacheKey({ query, freshness = 'noLimit', includeDomains = [], excludeDomains = [], count = 0 }) {
  const q = String(query || '').toLowerCase().replace(/\s+/g, ' ').trim()
  return JSON.stringify([q, freshness, [...includeDomains].sort(), [...excludeDomains].sort(), count])
}

function get(key) {
  const hit = cache.get(key)
  if (!hit) return null
  return { sources: hit.sources, ageMs: Date.now() - hit.cachedAt }
}

function set(key, sources, { baseMinutes = 30, freshness = 'noLimit' } = {}) {
  const minutes = Math.max(0, Number(baseMinutes) || 0)
  if (!minutes) return
  const frac = FRESHNESS_TTL_FRACTION[freshness] ?? 1
  const ttlMs = minutes * 60e3 * frac
  if (ttlMs < 30e3) return // ultra-short TTLs are not worth caching
  if (cache.size >= MAX_ENTRIES) {
    // trim the oldest third
    const entries = [...cache.entries()].sort((a, b) => a[1].cachedAt - b[1].cachedAt)
    for (const [k] of entries.slice(0, Math.ceil(MAX_ENTRIES / 3))) cache.delete(k)
  }
  cache.set(key, { sources: sources.slice(0, 50), cachedAt: Date.now(), ttlMs })
}

function isFresh(hit, { baseMinutes = 30, freshness = 'noLimit' } = {}) {
  if (!hit) return false
  const frac = FRESHNESS_TTL_FRACTION[freshness] ?? 1
  const ttlMs = Math.max(30e3, (Number(baseMinutes) || 0) * 60e3 * frac)
  return hit.ageMs < ttlMs
}

function clear() { cache.clear() }
function size() { return cache.size }

module.exports = { cacheKey, get, set, isFresh, clear, size }
