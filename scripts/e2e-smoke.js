/**
 * KinyaBot Agent V1 — E2E SMOKE TEST against the REAL app.js
 * ─────────────────────────────────────────────────────────────
 * Boots the production Express entry (all middleware: authGuard,
 * rate limiter, plans, socket.io, agent orchestrator) with the
 * scripted TEST provider (KINYA_ALLOW_SCRIPTED_PROVIDER=1 — Groq is
 * unreachable from this sandbox), then drives the acceptance task
 * (§38) over plain HTTP exactly like the frontend would:
 *
 *   register/login user → POST /api/agent/tasks (acceptance prompt)
 *   → poll task → verify real file on disk → events → files →
 *   changes → logs → conversation mirror (§26) → task list
 *
 * Run:  node scripts/e2e-smoke.js
 */
const mongoose = require('mongoose')
const { spawn } = require('child_process')
const bcrypt = require('bcryptjs')
const jwt = require('jsonwebtoken')
const http = require('http')

const PORT = 5017
const BASE = `http://127.0.0.1:${PORT}`
const DB_NAME = 'kinyabot-agent-v1-smoke'
const JWT_SECRET = 'kinyabot_jwt_secret_change_me'
const PROMPT = 'Create a simple HTML page about KinyaBot.'

const wait = (ms) => new Promise(r => setTimeout(r, ms))
async function waitFor(fn, label, timeoutMs = 60_000) {
  const start = Date.now()
  while (Date.now() - start < timeoutMs) {
    const v = await fn()
    if (v) return v
    await wait(400)
  }
  throw new Error(`timeout waiting for: ${label}`)
}

async function main() {
  /* 1 ── prepare a verified user in the smoke DB (before app boot) */
  const baseUri = process.env.MONGODB_URI || require('dotenv').config().parsed.MONGODB_URI
  await mongoose.connect(baseUri, { dbName: DB_NAME })
  await mongoose.connection.dropDatabase()
  const { User } = require('../models')
  const user = await User.create({
    username: 'smoketester', email: 'smoke@test.local',
    password_hash: await bcrypt.hash('smoke-password-1', 10),
    onboarded: true, email_verified: true,
  })
  const token = jwt.sign({ id: user._id, username: user.username, email: user.email }, JWT_SECRET, { expiresIn: '1d' })
  await mongoose.disconnect()
  console.log('✓ smoke user created')

  /* 2 ── boot the REAL app.js (production entry, scripted provider) */
  const app = spawn('node', ['app.js'], {
    cwd: require('path').join(__dirname, '..'),
    env: {
      ...process.env,
      PORT: String(PORT),
      MONGODB_URI: `${baseUri}/${DB_NAME}`,
      JWT_SECRET,
      NODE_ENV: process.env.NODE_ENV || 'production',
      AGENT_PROVIDER: 'scripted',
      KINYA_ALLOW_SCRIPTED_PROVIDER: '1',
      AGENT_MAX_CONCURRENT_TASKS: '2',
      GROQ_API_KEY: 'sk-test-placeholder',
    },
    stdio: ['ignore', 'pipe', 'pipe'],
  })
  let serverLog = ''
  app.stdout.on('data', d => { serverLog += d })
  app.stderr.on('data', d => { serverLog += d })

  const call = async (method, path, body) => {
    const res = await fetch(`${BASE}${path}`, {
      method,
      headers: { 'Content-Type': 'application/json', Authorization: `Bearer ${token}` },
      body: body ? JSON.stringify(body) : undefined,
    })
    let json = null
    try { json = await res.json() } catch {}
    return { status: res.status, json }
  }

  try {
    /* 3 ── wait for server up (health endpoint) */
    await waitFor(async () => {
      try { const r = await fetch(`${BASE}/api/health`); return r.ok } catch { return false }
    }, 'server boot', 30_000)
    console.log('✓ real app.js booted (health OK)')

    /* 4 ── agent config (§39 capability discovery) */
    const cfg = await call('GET', '/api/agent/config')
    if (cfg.status !== 200) throw new Error(`agent config: ${cfg.status} ${JSON.stringify(cfg.json)}`)
    console.log(`✓ /api/agent/config → provider=${cfg.json.provider}, tools=${cfg.json.tools?.length}, preview=${cfg.json.previewEnabled}`)

    /* 5 ── the §38 acceptance task, over the real route stack */
    const create = await call('POST', '/api/agent/tasks', { prompt: PROMPT })
    if (create.status !== 201) throw new Error(`create: ${create.status} ${JSON.stringify(create.json)}`)
    const taskRef = create.json.task.task_ref
    const taskId = create.json.task.id
    const conversationId = create.json.conversationId
    console.log(`✓ task created: ${taskRef} (conversation ${conversationId})`)

    /* 6 ── completion with honest result */
    const final = await waitFor(async () => {
      const r = await call('GET', `/api/agent/tasks/${taskRef}`)
      return ['completed', 'failed', 'cancelled'].includes(r.json.task?.status) ? r.json : null
    }, 'task completion', 120_000)
    if (final.task.status !== 'completed') throw new Error(`task ${final.task.status}: ${final.task.error}`)
    console.log(`✓ task completed in ${Math.round(final.task.stats.duration_ms / 1000)}s — verified=${final.task.verified}`)
    console.log(`  result: ${String(final.task.result).slice(0, 90)}…`)

    /* 7 ── §32 no-fake-data: the file really exists on disk */
    const { Workspace } = require('../services/agent/sandbox')
    const ws = new Workspace(taskId)
    const fsp = require('fs').promises
    const html = await fsp.readFile(ws.resolve('index.html'), 'utf8').catch(() => null)
    if (!html || !html.includes('KinyaBot AI')) throw new Error('index.html missing or wrong content on disk')
    console.log('✓ real file on disk contains the expected content')

    /* 8 ── every workspace endpoint the frontend calls */
    const events = await call('GET', `/api/agent/tasks/${taskRef}/events?after=0`)
    const types = (events.json.events || []).map(e => e.type)
    for (const want of ['task.started', 'task.plan_updated', 'task.tool.started', 'task.terminal.completed', 'task.verification.completed', 'task.completed']) {
      if (!types.includes(want)) throw new Error(`event missing: ${want}`)
    }
    console.log(`✓ event timeline: ${events.json.events.length} events, all lifecycle types present`)

    const files = await call('GET', `/api/agent/tasks/${taskRef}/files`)
    if (!files.json.entries?.some(e => e.path === 'index.html')) throw new Error('files tree missing index.html')

    const file = await call('GET', `/api/agent/tasks/${taskRef}/file?path=index.html`)
    if (!String(file.json.content || '').includes('KinyaBot AI')) throw new Error('file read failed')

    const changes = await call('GET', `/api/agent/tasks/${taskRef}/changes`)
    if (!changes.json.changes?.length) throw new Error('no change records')

    const logs = await call('GET', `/api/agent/tasks/${taskRef}/logs`)
    if (!logs.json.logs?.length) throw new Error('no logs')
    console.log(`✓ workspace endpoints: files(${files.json.entries.length}) changes(${changes.json.changes.length}) logs(${logs.json.logs.length})`)

    /* 9 ── §26: conversation integration (user + assistant messages) */
    await mongoose.connect(`${baseUri}/${DB_NAME}`)
    const { Chat, Message } = require('../models')
    const chat = await Chat.findOne({ conversation_id: conversationId })
    if (!chat || chat.mode !== 'agent') throw new Error('conversation not created with mode agent')
    const userMsg = await Message.findOne({ chat_id: chat._id, role: 'user' })
    const aiMsg = await Message.findOne({ chat_id: chat._id, role: 'assistant' })
    if (!userMsg || !aiMsg) throw new Error('conversation messages missing')
    if (String(userMsg.agent_task_id) !== String(taskId)) throw new Error('user message task link wrong')
    if (!String(aiMsg.content).includes('index.html')) throw new Error('assistant mirror missing real work')
    console.log('✓ §26 conversation: mode=agent, user+assistant messages linked to the task')

    /* 10 ── task list (sidebar / restore) */
    const list = await call('GET', '/api/agent/tasks?limit=10')
    if (!list.json.tasks?.some(t => t.task_ref === taskRef)) throw new Error('task list missing the task')
    console.log('✓ task list endpoint OK')

    /* 11 ── deep-link restore: GET task by ref returns conversationId */
    const detail = await call('GET', `/api/agent/tasks/${taskRef}`)
    if (detail.json.conversationId !== conversationId) throw new Error('task detail conversationId mismatch')
    console.log('✓ deep-link restore data OK')

    await ws.remove().catch(() => {})
    console.log('\n════════ E2E SMOKE TEST PASSED ════════')
  } catch (err) {
    console.error('\n════════ E2E SMOKE TEST FAILED ════════')
    console.error(err.message)
    console.error('\n--- last server log ---')
    console.error(serverLog.slice(-1500))
    process.exitCode = 1
  } finally {
    app.kill('SIGKILL')
    await mongoose.disconnect().catch(() => {})
    setTimeout(() => process.exit(process.exitCode || 0), 300)
  }
}

main().catch(e => { console.error('FATAL', e); process.exit(1) })
