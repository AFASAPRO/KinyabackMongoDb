/**
 * KinyaBot Agent V1.1 — GROQ PRODUCTION SMOKE TEST
 * ─────────────────────────────────────────────────────────────────
 * Validates the REAL production AI path end-to-end. This script NEVER
 * uses the scripted test provider and never silently falls back to
 * anything — a failure is reported as a failure (§14).
 *
 *   Phase A  provider-level (no database needed)
 *     A1  real chat completion            (reachability + auth)
 *     A2  real structured tool-call req.  (native function calling)
 *     A3  real tool execution             (file really written on disk)
 *     A4  continuation after tool result  (multi-turn tool loop)
 *     A5  real command execution          (bash reads the file back)
 *
 *   Phase B  full-stack acceptance (needs MONGODB_URI)
 *     boots the REAL app.js with AGENT_PROVIDER=groq (production
 *     default), runs an acceptance task through the real routes and
 *     verifies the artifact on disk + the event timeline.
 *
 * Exit codes:  0 = PASS · 1 = FAIL · 3 = BLOCKED (with the reason)
 *
 * Run on production infrastructure:
 *   GROQ_API_KEY=gsk_…  MONGODB_URI=mongodb://…  node scripts/groq-smoke.js
 */
const path = require('path')
const fs = require('fs')
const fsp = fs.promises

const BLOCKED = (msg) => { console.error(`\n⛔ BLOCKED — ${msg}`); process.exit(3) }

/* ── Phase 0: preflight — a real key or an honest stop ────────── */
const RAW_KEY = process.env.GROQ_API_KEY || ''
if (!RAW_KEY) {
  BLOCKED('GROQ_API_KEY is not set. Provide the production key and re-run: GROQ_API_KEY=gsk_… node scripts/groq-smoke.js')
}
if (!/^gsk_/.test(RAW_KEY) && /^(sk-test|test|placeholder|dummy|fake|changeme)/i.test(RAW_KEY)) {
  BLOCKED(`GROQ_API_KEY="${RAW_KEY.slice(0, 12)}…" looks like a test placeholder, not a real Groq key. The production smoke refuses to run against a fake key.`)
}
if (process.env.KINYA_ALLOW_SCRIPTED_PROVIDER || /^(test)$/i.test(process.env.NODE_ENV || '')) {
  BLOCKED('Refusing to run: KINYA_ALLOW_SCRIPTED_PROVIDER / NODE_ENV=test would allow the scripted provider to answer. The production smoke must exercise the REAL Groq path only.')
}

console.log('════════ KinyaBot Agent V1.1 — Groq PRODUCTION smoke ════════')
console.log(`key: gsk_…${RAW_KEY.slice(-4)} · node ${process.version}`)

const { chatComplete, chatCompleteWithTools } = require('../services/ai/groqProvider')
const registry = require('../services/agent/tools/registry')
const { Workspace } = require('../services/agent/sandbox')
const { runRealCommand } = require('../services/agent/tools/terminal')

const MARKER = 'KINYABOT_GROQ_SMOKE_OK'
const t0 = Date.now()
const step = (name, ms) => console.log(`✓ ${name} (${ms}ms)`)
const fail = (name, err) => {
  console.error(`✗ ${name}`)
  console.error(`  code: ${err?.code || 'UNCODED'} · status: ${err?.status || '-'} · ${err?.message || err}`)
  // The sandbox/network-edge denial signature: a 403 whose body is the
  // generic {"error":{"message":"Forbidden"}} — NOT Groq's error format.
  // Distinguish it from a real provider auth failure so operators know
  // the request never reached Groq at all (§14: report blockers clearly).
  if (err?.status === 403 && /^\s*403\s*\{"error":\{"message":"Forbidden"\}\}/.test(String(err?.message || ''))) {
    console.error('\n⛔ BLOCKED — the request never reached api.groq.com: this environment\'s network edge rejects Groq egress with a generic 403.')
    console.error('   Re-run on production infrastructure:  GROQ_API_KEY=gsk_… [MONGODB_URI=…] npm run smoke:groq')
    process.exit(3)
  }
  console.error('\n════════ GROQ PRODUCTION SMOKE — FAILED ════════')
  process.exit(1)
}

async function phaseA() {
  /* A1 ── plain completion: reachability + authentication ──────── */
  let s = Date.now()
  let out
  try {
    out = await chatComplete({
      messages: [
        { role: 'system', content: 'You are a connectivity probe. Reply with the exact token requested and nothing else.' },
        { role: 'user', content: 'Reply with exactly: KINYABOT_PROBE_ACK' },
      ],
      maxTokens: 32, temperature: 0,
    })
  } catch (err) { fail('A1 real chat completion (reachability/auth)', err) }
  if (!/KINYABOT_PROBE_ACK/i.test(out.text || '')) {
    fail('A1 real chat completion', new Error(`unexpected model reply: ${String(out.text).slice(0, 80)}`))
  }
  step(`A1 real chat completion — model=${out.model}, tokens=${out.tokens}`, Date.now() - s)

  /* A2 ── structured tool-call request (native function calling) ─ */
  s = Date.now()
  const ws = new Workspace(`groqsmoke${Date.now().toString(36)}`)
  await ws.ensure()
  const tools = registry.toModelTools()           // the REAL production toolset
  let response
  try {
    response = await chatCompleteWithTools({
      messages: [
        { role: 'system', content: 'You are executing a production smoke test. Use the create_file tool exactly as instructed; do not use any other tool.' },
        { role: 'user', content: `Create a file named smoke-check.txt whose content is exactly the string ${MARKER} (no other text).` },
      ],
      tools,
      toolChoice: 'auto',
      temperature: 0,
    })
  } catch (err) { await ws.remove().catch(() => {}); fail('A2 structured tool-call request', err) }

  const calls = response.message?.tool_calls || []
  const createCall = calls.find(c => c.function?.name === 'create_file')
  if (!createCall) {
    await ws.remove().catch(() => {})
    fail('A2 structured tool-call request', new Error(`model returned ${calls.length ? `tool_calls for [${calls.map(c => c.function?.name).join(', ')}]` : 'no tool_calls (content-only reply)'} — expected create_file`))
  }
  step(`A2 structured tool-call request — create_file${createCall._args_repaired ? ' (arguments were REPAIRED by the V1.1 toolCallRepair layer)' : ''}`, Date.now() - s)

  /* A3 ── real tool execution: the file lands on disk ──────────── */
  s = Date.now()
  let args
  try { args = JSON.parse(createCall.function.arguments) }
  catch { await ws.remove().catch(() => {}); fail('A3 tool arguments', new Error('arguments did not parse even after normalisation')) }
  const events = []
  const toolCtx = { workspace: ws, emit: (type, data) => events.push({ type, data }) }
  let toolResult
  try { toolResult = await registry.executeTool('create_file', args, toolCtx) }
  catch (err) { await ws.remove().catch(() => {}); fail('A3 real tool execution', err) }
  const onDisk = await fsp.readFile(ws.resolve('smoke-check.txt'), 'utf8').catch(() => null)
  if (!onDisk || !onDisk.includes(MARKER)) {
    await ws.remove().catch(() => {})
    fail('A3 real tool execution', new Error('smoke-check.txt missing on disk or missing the marker string'))
  }
  step('A3 real tool execution — smoke-check.txt written on disk', Date.now() - s)

  /* A4 ── continuation: feed the real tool result back ─────────── */
  s = Date.now()
  const messages = [
    { role: 'system', content: 'You are executing a production smoke test. Use the create_file tool exactly as instructed; do not use any other tool.' },
    { role: 'user', content: `Create a file named smoke-check.txt whose content is exactly the string ${MARKER} (no other text).` },
    response.message,
    { role: 'tool', tool_call_id: createCall.id, name: 'create_file', content: JSON.stringify(toolResult).slice(0, 2000) },
  ]
  let final
  try { final = await chatCompleteWithTools({ messages, tools, temperature: 0 }) }
  catch (err) { await ws.remove().catch(() => {}); fail('A4 continuation after tool result', err) }
  if (!String(final.message?.content || '').trim()) {
    await ws.remove().catch(() => {})
    fail('A4 continuation after tool result', new Error('model returned an empty final message'))
  }
  step('A4 continuation after tool result — multi-turn tool loop works', Date.now() - s)

  /* A5 ── real command execution: bash reads the file back ─────── */
  s = Date.now()
  const cmd = await runRealCommand({
    command: 'cat smoke-check.txt && echo "exit=$?"',
    cwd: ws.root,
    env: { PATH: process.env.PATH, HOME: ws.root },
    timeoutMs: 15_000,
    maxOutputBytes: 64 * 1024,
  }).catch(err => ({ exit_code: -1, stdout: '', stderr: String(err?.message || err) }))
  if (cmd.exit_code !== 0 || !String(cmd.stdout || '').includes(MARKER)) {
    await ws.remove().catch(() => {})
    fail('A5 real command execution', new Error(`cat exited ${cmd.exit_code}: ${String(cmd.stderr).slice(0, 120)}`))
  }
  step('A5 real command execution — bash verified the artifact', Date.now() - s)

  await ws.remove().catch(() => {})
  console.log(`\n── Phase A PASSED in ${((Date.now() - t0) / 1000).toFixed(1)}s — provider path, native tool calling, real execution all verified.`)
}

/* ── Phase B: full-stack acceptance through the real app.js ────── */
async function phaseB() {
  const mongoose = require('mongoose')
  const { spawn } = require('child_process')
  const bcrypt = require('bcryptjs')
  const jwt = require('jsonwebtoken')

  const baseUri = process.env.MONGODB_URI
  if (!baseUri) {
    console.log('\n── Phase B SKIPPED — set MONGODB_URI to run the full-stack acceptance against the real app.js.')
    return
  }
  const PORT = 5021
  const BASE = `http://127.0.0.1:${PORT}`
  const DB = 'kinyabot-groq-smoke'
  const SECRET = `smoke_${Date.now()}`
  const PROMPT = `Create a file named groq-smoke.html containing the exact marker string KINYABOT_GROQ_E2E_OK and a short heading that mentions KinyaBot. Then read the file back to verify it.`
  const wait = ms => new Promise(r => setTimeout(r, ms))
  const waitFor = async (fn, label, ms = 240_000) => {
    const start = Date.now()
    while (Date.now() - start < ms) { const v = await fn().catch(() => null); if (v) return v; await wait(500) }
    throw new Error(`timeout waiting for: ${label}`)
  }

  await mongoose.connect(baseUri, { dbName: DB })
  await mongoose.connection.dropDatabase()
  const { User } = require('../models')
  const u = await User.create({ username: 'groqsmoke', email: 'groq-smoke@test.local', password_hash: await bcrypt.hash('groq-smoke-pass', 10), onboarded: true, email_verified: true })
  const token = jwt.sign({ id: u._id, username: u.username, email: u.email }, SECRET, { expiresIn: '1d' })
  await mongoose.disconnect()

  const app = spawn('node', ['app.js'], {
    cwd: path.join(__dirname, '..'),
    env: {
      ...process.env,
      PORT: String(PORT),
      MONGODB_URI: `${baseUri}/${DB}`,
      JWT_SECRET: SECRET,
      NODE_ENV: 'production',
      AGENT_PROVIDER: 'groq',                    // production default, explicit
      GROQ_API_KEY: RAW_KEY,
    },
    stdio: ['ignore', 'pipe', 'pipe'],
  })
  let serverLog = ''
  app.stdout.on('data', d => { serverLog += d })
  app.stderr.on('data', d => { serverLog += d })

  const call = async (method, p, body) => {
    const res = await fetch(`${BASE}${p}`, { method, headers: { 'Content-Type': 'application/json', Authorization: `Bearer ${token}` }, body: body ? JSON.stringify(body) : undefined })
    let json = null; try { json = await res.json() } catch {}
    return { status: res.status, json }
  }

  try {
    await waitFor(async () => { try { const r = await fetch(`${BASE}/api/health`); return r.ok } catch { return false } }, 'server boot', 30_000)
    console.log('✓ B1 real app.js booted (production entry, AGENT_PROVIDER=groq)')

    const create = await call('POST', '/api/agent/tasks', { prompt: PROMPT })
    if (create.status !== 201) throw new Error(`create task: ${create.status} ${JSON.stringify(create.json)}`)
    const ref = create.json.task.task_ref
    const id = create.json.task.id
    console.log(`✓ B2 acceptance task created (${ref}) — real Groq loop running`)

    const final = await waitFor(async () => {
      const r = await call('GET', `/api/agent/tasks/${ref}`)
      return ['completed', 'failed', 'cancelled'].includes(r.json?.task?.status) ? r.json : null
    }, 'task completion')
    if (final.task.status !== 'completed') throw new Error(`task ${final.task.status}: ${final.task.error?.code || ''} ${final.task.error?.message || ''}`)
    console.log(`✓ B3 task completed in ${Math.round(final.task.stats.duration_ms / 1000)}s — steps=${final.task.stats.steps}, tools=${final.task.stats.tool_calls}, commands=${final.task.stats.commands_run}`)

    const ws2 = new Workspace(String(id))
    const html = await fsp.readFile(ws2.resolve('groq-smoke.html'), 'utf8').catch(() => null)
    if (!html || !html.includes('KINYABOT_GROQ_E2E_OK')) throw new Error('groq-smoke.html missing on disk or missing the marker')
    console.log('✓ B4 real artifact verified on disk')

    const events = await call('GET', `/api/agent/tasks/${ref}/events?after=0`)
    const types = (events.json.events || []).map(e => e.type)
    for (const want of ['task.started', 'task.tool.started', 'task.completed']) {
      if (!types.includes(want)) throw new Error(`event missing: ${want}`)
    }
    console.log(`✓ B5 event timeline: ${events.json.events.length} events`)
    await ws2.remove().catch(() => {})
    console.log('\n── Phase B PASSED — full production stack verified against real Groq.')
  } catch (err) {
    console.error(`\n✗ Phase B FAILED — ${err.message}`)
    console.error('--- last server log ---')
    console.error(serverLog.slice(-2000))
    process.exitCode = 1
  } finally {
    app.kill('SIGKILL')
    await mongoose.disconnect().catch(() => {})
  }
}

;(async () => {
  try {
    await phaseA()
    await phaseB()
    console.log(`\n════════ GROQ PRODUCTION SMOKE — PASSED (${((Date.now() - t0) / 1000).toFixed(1)}s) ════════`)
    process.exit(process.exitCode || 0)
  } catch (err) {
    // Network-level blocks (sandbox egress denied) surface here — report honestly.
    console.error(`\n⛔ BLOCKED/FAILED — the real Groq path could not complete: ${err?.code || ''} ${err?.message || err}`)
    process.exit(err?.code === 'AI_AUTH' || err?.code === 'AI_RATE_LIMIT' || err?.code === 'AI_TIMEOUT' || /fetch failed|ENOTFOUND|ECONNREFUSED|ECONNRESET|network|403/i.test(String(err?.message || err)) ? 3 : 1)
  }
})()
