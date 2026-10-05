/**
 * KinyaBot — Real System Health Checks
 * ─────────────────────────────────────────────────────────────────
 * Every component status below comes from an ACTUAL check performed
 * against the real infrastructure — never from "the UI loaded, so it
 * must be fine":
 *
 *   database      mongoose connection state + live admin ping (latency)
 *   aiProvider    real Groq API call (models.list) with latency
 *   socket        live Socket.IO engine client count
 *   auth          JWT secret configured + sign/verify round-trip
 *   email         SMTP transport verify() when configured, else unknown
 *   storage       uploads dir writable + real size (cached)
 *   push          web-push VAPID configuration state + subscriptions
 *   process       uptime, RSS, heap — real process metrics
 *
 * Results are cached briefly (15s) so dashboard polling doesn't hammer
 * providers, with a `force` option for the manual "Recheck" button.
 */
const mongoose = require('mongoose')
const fs = require('fs')
const jwt = require('jsonwebtoken')
const crypto = require('crypto')
const aiConfig = require('./ai/config')
const provider = require('./ai/groqProvider')
const pushService = require('./push')

const JWT_SECRET = process.env.JWT_SECRET || 'kinyabot_jwt_secret_change_me'

const CACHE_TTL_MS = 15 * 1000
let cache = { data: null, at: 0 }
let inflight = null

function level(ok, degradedIf) {
  if (ok) return 'operational'
  if (degradedIf) return 'degraded'
  return 'down'
}

async function checkDatabase() {
  const state = mongoose.connection.readyState // 0 disconnected 1 connected 2 connecting 3 disconnecting
  if (state !== 1) return { status: 'down', detail: `Connection state: ${state}`, latency_ms: null }
  const start = Date.now()
  try {
    await mongoose.connection.db.admin().command({ ping: 1 })
    return { status: 'operational', detail: 'Ping OK', latency_ms: Date.now() - start }
  } catch (err) {
    return { status: 'degraded', detail: `Ping failed: ${err.message}`, latency_ms: Date.now() - start }
  }
}

async function checkAiProvider() {
  if (!aiConfig.apiKey) return { status: 'unknown', detail: 'GROQ_API_KEY not configured', latency_ms: null }
  const start = Date.now()
  try {
    // Cheap, real provider call — lists models the key can actually use.
    await provider.getClient().models.list()
    return { status: 'operational', detail: 'Provider reachable', latency_ms: Date.now() - start }
  } catch (err) {
    const code = err?.code || ''
    const msg = err?.message || 'provider error'
    const status = ['AI_AUTH', 'GROQ_NOT_CONFIGURED'].includes(code) ? 'down' : (['AI_RATE_LIMIT', 'AI_TIMEOUT'].includes(code) ? 'degraded' : 'degraded')
    return { status, detail: msg.slice(0, 160), latency_ms: Date.now() - start }
  }
}

function checkSocket(io) {
  if (!io) return { status: 'unknown', detail: 'Socket.IO not initialized', latency_ms: null }
  const count = io.engine?.clientsCount ?? 0
  return { status: 'operational', detail: `${count} live connection${count === 1 ? '' : 's'}`, latency_ms: null, clients: count }
}

function checkAuth() {
  if (!process.env.JWT_SECRET) return { status: 'degraded', detail: 'JWT_SECRET using insecure default — set it in .env', latency_ms: null }
  const start = Date.now()
  try {
    const t = jwt.sign({ probe: crypto.randomUUID() }, JWT_SECRET, { expiresIn: '10s' })
    jwt.verify(t, JWT_SECRET)
    return { status: 'operational', detail: 'Sign/verify OK', latency_ms: Date.now() - start }
  } catch (err) {
    return { status: 'down', detail: err.message, latency_ms: Date.now() - start }
  }
}

let smtpProbe = { at: 0, result: null }
async function checkEmail() {
  if (!process.env.SMTP_USER) return { status: 'unknown', detail: 'SMTP not configured', latency_ms: null }
  if (smtpProbe.result && Date.now() - smtpProbe.at < 5 * 60 * 1000) return smtpProbe.result
  const start = Date.now()
  try {
    const nodemailer = require('nodemailer')
    const t = nodemailer.createTransport({
      host: process.env.SMTP_HOST || 'smtp.gmail.com',
      port: parseInt(process.env.SMTP_PORT || '587'),
      secure: process.env.SMTP_SECURE === 'true',
      auth: { user: process.env.SMTP_USER, pass: process.env.SMTP_PASS || '' },
      connectionTimeout: 6000, greetingTimeout: 6000, socketTimeout: 8000,
    })
    await t.verify()
    smtpProbe = { at: Date.now(), result: { status: 'operational', detail: 'SMTP ready', latency_ms: Date.now() - start } }
  } catch (err) {
    smtpProbe = { at: Date.now(), result: { status: 'degraded', detail: `SMTP verify failed: ${String(err.message).slice(0, 120)}`, latency_ms: Date.now() - start } }
  }
  return smtpProbe.result
}

let storageCache = { at: 0, size: 0 }
async function checkStorage() {
  const dir = './uploads'
  try {
    fs.mkdirSync(dir, { recursive: true })
    fs.accessSync(dir, fs.constants.W_OK)
    if (Date.now() - storageCache.at > 60 * 1000) {
      let size = 0
      for (const f of fs.readdirSync(dir)) {
        try { size += fs.statSync(`${dir}/${f}`).size } catch {}
      }
      storageCache = { at: Date.now(), size }
    }
    return { status: 'operational', detail: 'Uploads dir writable', latency_ms: null, bytes: storageCache.size }
  } catch (err) {
    return { status: 'down', detail: err.message, latency_ms: null }
  }
}

async function checkPush() {
  const st = pushService.status()
  if (!st.enabled) return { status: 'unknown', detail: 'VAPID keys not configured — push disabled', latency_ms: null }
  const subs = await pushService.subscriptionCount()
  return { status: 'operational', detail: `${subs} subscription${subs === 1 ? '' : 's'} registered`, latency_ms: null, subscriptions: subs }
}

function checkProcess() {
  const mem = process.memoryUsage()
  return {
    uptime_s: Math.round(process.uptime()),
    rss_bytes: mem.rss,
    heap_used_bytes: mem.heapUsed,
    node_version: process.version,
  }
}

function overall(checks) {
  const values = ['database', 'aiProvider', 'auth', 'socket']
    .map(k => checks[k]?.status)
    .filter(Boolean)
  if (values.includes('down')) return 'down'
  if (values.includes('degraded')) return 'degraded'
  if (values.some(v => v === 'unknown')) return 'degraded'
  return 'operational'
}

async function runChecks(io, { force = false } = {}) {
  if (!force && cache.data && Date.now() - cache.at < CACHE_TTL_MS) {
    return { ...cache.data, cached: true }
  }
  if (inflight) return inflight
  inflight = (async () => {
    const [database, aiProvider, email, storage, push] = await Promise.all([
      checkDatabase(), checkAiProvider(), checkEmail(), checkStorage(), checkPush(),
    ])
    const socket = checkSocket(io)
    const auth = checkAuth()
    const processInfo = checkProcess()
    const checks = { database, aiProvider, socket, auth, email, storage, push, process: processInfo }
    const result = { overall: overall(checks), checks, checked_at: new Date().toISOString(), cached: false }
    cache = { data: result, at: Date.now() }
    return result
  })()
  try { return await inflight } finally { inflight = null }
}

module.exports = { runChecks }
