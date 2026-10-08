/**
 * KinyaBot — Global Settings (shared service)
 * ─────────────────────────────────────────────────────────────────
 * Single owner of the runtime configuration (admin-settings.json).
 * Used by user-facing routes (moderation, quotas, system prompt) and
 * by the Superadmin Settings / AI Control pages — so there is exactly
 * one source of truth and no drift.
 */
const fs = require('fs')

const SETTINGS_FILE = './admin-settings.json'

const DEFAULTS = {
  max_tokens: 2048, temperature: 0.7, max_context_messages: 10,
  system_prompt: 'You are KinyaBot, a helpful AI assistant. Be concise, friendly, and accurate.',
  image_gen_enabled: true, file_uploads_enabled: true,
  maintenance_mode: false, app_name: 'KinyaBot AI',
  blocked_ips: [], cost_per_1k_tokens: 0.002,
  free_daily_limit: 50, premium_daily_limit: 500,
  moderation_enabled: true, knowledge_base_enabled: true,
  /* ── Web Search operational configuration (Web Search §38) ──
     Safe runtime knobs for the SuperAdmin AI Control page. The
     LangSearch API key itself is env-only and NEVER stored here. */
  web_search_enabled: true,          // global kill switch
  web_search_auto_enabled: true,     // automatic search decisions in Chat mode
  web_search_max_results: 8,         // results passed to the model per query
  web_search_max_queries: 3,         // max optimized searches per user message
  web_search_cache_minutes: 30,      // result cache TTL (freshness-aware)
  web_search_timeout_ms: 12000,      // per-search backend timeout
  web_search_allowed_domains: [],    // empty = no restriction
  web_search_blocked_domains: [],    // always excluded
}

let cfg = { ...DEFAULTS }
try { cfg = { ...DEFAULTS, ...JSON.parse(fs.readFileSync(SETTINGS_FILE, 'utf8')) } } catch {}

function get() { return cfg }

/** Update with an allow-list of keys. Mutates the shared object IN
 *  PLACE so every existing reference (app.js `cfg`, etc.) stays live. */
function update(partial = {}) {
  const allowed = [
    'max_tokens', 'temperature', 'system_prompt', 'image_gen_enabled',
    'file_uploads_enabled', 'maintenance_mode', 'app_name', 'max_context_messages',
    'blocked_ips', 'cost_per_1k_tokens', 'free_daily_limit', 'premium_daily_limit',
    'moderation_enabled', 'knowledge_base_enabled',
    'web_search_enabled', 'web_search_auto_enabled', 'web_search_max_results',
    'web_search_max_queries', 'web_search_cache_minutes', 'web_search_timeout_ms',
    'web_search_allowed_domains', 'web_search_blocked_domains',
  ]
  for (const k of allowed) {
    if (Object.prototype.hasOwnProperty.call(partial, k)) cfg[k] = partial[k]
  }
  save()
  return cfg
}

function blockIp(ip) {
  if (!cfg.blocked_ips) cfg.blocked_ips = []
  if (!cfg.blocked_ips.includes(ip)) cfg.blocked_ips.push(ip)
  save()
}
function unblockIp(ip) {
  cfg.blocked_ips = (cfg.blocked_ips || []).filter(i => i !== ip)
  save()
}

function save() { try { fs.writeFileSync(SETTINGS_FILE, JSON.stringify(cfg, null, 2)) } catch {} }

module.exports = { get, update, save, blockIp, unblockIp, DEFAULTS }
