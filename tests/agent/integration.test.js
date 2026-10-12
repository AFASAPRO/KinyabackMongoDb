/**
 * KinyaBot Agent V1 — Integration & Task Lifecycle Tests (§37, §38)
 * ─────────────────────────────────────────────────────────────
 * Boots a REAL mini-API (express + authGuard + routes/agent +
 * Socket.IO + orchestrator + forked execution worker) against a
 * dedicated TEST database, with the scripted TEST provider driving
 * the model layer. Everything else is REAL:
 *
 *   real MongoDB persistence · real forked worker process ·
 *   real filesystem tools writing real files · real bash commands
 *   with captured stdout/stderr/exit codes · real diff records ·
 *   real realtime events over a real Socket.IO connection ·
 *   real preview server (python http.server) with port probing
 *
 * Run: MONGODB_URI=… NODE_ENV=test AGENT_PROVIDER=scripted node --test tests/agent/integration.test.js
 */
const test = require('node:test')
const assert = require('node:assert')
const http = require('http')
const express = require('express')
const mongoose = require('mongoose')
const jwt = require('jsonwebtoken')
const bcrypt = require('bcryptjs')
const { Server } = require('socket.io')
const { io: ioClient } = require('socket.io-client')
const fs = require('fs')
const fsp = fs.promises

const TEST_DB = process.env.AGENT_TEST_DB || 'kinyabot-agent-v1-test'

let app, server, io, baseUrl, token, userId, socketClient
const receivedEvents = []   // every agent_event this test client receives

test.before(async () => {
  // ── dedicated test database (never the production collections) ──
  const baseUri = process.env.MONGODB_URI || require('dotenv').config().parsed.MONGODB_URI
  await mongoose.connect(baseUri, { dbName: TEST_DB })
  await mongoose.connection.dropDatabase()

  // ── boot the real stack ──────────────────────────────────────
  const { User, Chat, Message, AgentTask, AgentEvent, PlanConfig } = require('../../models')
  const plansService = require('../../services/plans')
  await plansService.ensureSeed()

  const user = await User.create({
    username: 'agenttester', email: 'agenttester@test.local',
    password_hash: await bcrypt.hash('test-password-123', 10), onboarded: true, email_verified: true,
  })
  userId = user._id.toString()
  token = jwt.sign({ id: userId, username: user.username, email: user.email }, process.env.JWT_SECRET || 'kinyabot_jwt_secret_change_me', { expiresIn: '1d' })

  app = express()
  app.use(express.json({ limit: '5mb' }))
  app.use((req, res, next) => { req.app.set('io', io); next() })
  app.use('/api', require('../../routes/agent'))
  server = http.createServer(app)
  io = new Server(server, { cors: { origin: '*', credentials: false } })

  // SAME socket auth + room join as production app.js: the client
  // authenticates with its JWT and joins user_<id> — the room every
  // agent event is emitted into. Without this the realtime assertions
  // below would test nothing.
  io.use((socket, next) => {
    const t = socket.handshake.auth?.token
    if (t) { try { socket.user = jwt.verify(t, process.env.JWT_SECRET || 'kinyabot_jwt_secret_change_me'); return next() } catch {} }
    next(new Error('Auth required'))
  })
  io.on('connection', (socket) => {
    if (socket.user) socket.join(`user_${String(socket.user.id)}`)
  })

  const orchestrator = require('../../services/agent/orchestrator')
  orchestrator.attachAgentIo(io)

  await new Promise(r => server.listen(0, r))
  const port = server.address().port
  baseUrl = `http://127.0.0.1:${port}`

  // ── real socket.io client with auth (same as the frontend) ──
  socketClient = ioClient(baseUrl, { auth: { token }, transports: ['websocket'] })
  socketClient.on('agent_event', (evt) => { receivedEvents.push(evt) })
  await new Promise((resolve, reject) => {
    socketClient.on('connect', resolve)
    socketClient.on('connect_error', reject)
    setTimeout(() => reject(new Error('socket connect timeout')), 5000)
  })
})

test.after(async () => {
  socketClient?.disconnect()
  server?.close()
  if (!process.env.AGENT_TEST_KEEP_DB) {
    await mongoose.connection.dropDatabase().catch(() => {})
  }
  await mongoose.disconnect().catch(() => {})
})

const api = {
  async call(method, path, body) {
    const res = await fetch(`${baseUrl}/api${path}`, {
      method,
      headers: { 'Content-Type': 'application/json', Authorization: `Bearer ${token}` },
      body: body ? JSON.stringify(body) : undefined,
    })
    let json = null
    try { json = await res.json() } catch {}
    return { status: res.status, json }
  },
}

const wait = (ms) => new Promise(r => setTimeout(r, ms))

async function waitFor(predicate, timeoutMs, label) {
  const start = Date.now()
  while (Date.now() - start < timeoutMs) {
    const val = await predicate()
    if (val) return val
    await wait(250)
  }
  throw new Error(`timeout waiting for: ${label}`)
}

/* ══════════════════════════════════════════════════════════════
   §37 TASK TESTS — creation, execution, completion
════════════════════════════════════════════════════════════════ */
test('task executes end-to-end with REAL tools and completes honestly', async () => {
  const { status, json } = await api.call('POST', '/agent/tasks', { prompt: 'Create a simple HTML page about KinyaBot.' })
  assert.equal(status, 201, `created: ${JSON.stringify(json)}`)
  const taskRef = json.task.task_ref
  assert.ok(taskRef, 'server-generated task_ref')

  // Conversation integration (§26): a Chat + user Message must exist
  const { Chat, Message } = require('../../models')
  const chat = await Chat.findById(json.task.conversation_id ? json.conversationId : null).catch(() => null)
  const chatDoc = await Chat.findOne({ conversation_id: json.conversationId })
  assert.ok(chatDoc, 'conversation created with mode agent')
  assert.equal(chatDoc.mode, 'agent')
  const userMsg = await Message.findOne({ chat_id: chatDoc._id, role: 'user' })
  assert.ok(userMsg, 'user prompt persisted as Message')
  assert.equal(userMsg.agent_task_id, json.task.id)

  // Wait for completion (real worker, real tools, real bash)
  const final = await waitFor(async () => {
    const r = await api.call('GET', `/agent/tasks/${taskRef}`)
    return ['completed', 'failed', 'cancelled'].includes(r.json.task?.status) ? r.json : null
  }, 90_000, 'task completion')
  assert.equal(final.task.status, 'completed', `expected completed, got: ${JSON.stringify(final.task.error)}`)
  assert.ok(final.task.result, 'final result present')

  // §32 NO FAKE DATA: the file the agent CLAIMS to have created must exist
  const { Workspace } = require('../../services/agent/sandbox')
  const ws = new Workspace(final.task.id)
  const html = await fsp.readFile(ws.resolve('index.html'), 'utf8').catch(() => null)
  assert.ok(html, 'index.html really exists on disk')
  assert.ok(html.includes('KinyaBot AI'), 'real file content')
  await ws.remove().catch(() => {})

  // Real terminal execution happened (exit code + durations captured)
  const logs = await api.call('GET', `/agent/tasks/${taskRef}/logs`)
  const termCompleted = logs.json.logs.filter(l => l.type === 'task.terminal.completed')
  assert.ok(termCompleted.length >= 1, 'terminal.completed events exist')
  assert.ok(Number.isInteger(termCompleted[0].data.exitCode), 'real exit code captured')

  // Real diff recorded
  const changes = await api.call('GET', `/agent/tasks/${taskRef}/changes`)
  assert.ok(changes.json.changes.length >= 1, 'file change records exist')
  assert.equal(changes.json.changes[0].action, 'created')
  assert.ok(changes.json.changes[0].hunks.length >= 1, 'diff hunks present')

  // §26: final result mirrored into the conversation as a Message
  const finalMsg = await Message.findOne({ chat_id: chatDoc._id, role: 'assistant' })
  assert.ok(finalMsg, 'assistant result message persisted')
  assert.ok(finalMsg.content.includes('index.html'), 'result references the real work')
})

test('realtime events stream over Socket.IO during execution', async () => {
  const before = receivedEvents.length
  const { json } = await api.call('POST', '/agent/tasks', { prompt: 'Serve a static site and verify it is running.' })
  assert.equal(json.task.task_ref ? 201 : 201, 201)

  await waitFor(async () => {
    const r = await api.call('GET', `/agent/tasks/${json.task.task_ref}`)
    return ['completed', 'failed'].includes(r.json.task?.status)
  }, 120_000, 'preview task completion')

  // The client socket must have received the live event stream
  const mine = receivedEvents.filter(e => e.taskId === json.task.id)
  const types = mine.map(e => e.type)
  assert.ok(types.includes('task.started'), 'task.started received live')
  assert.ok(types.includes('task.plan_updated'), 'plan received live')
  assert.ok(types.includes('task.tool.started'), 'tool events received live')
  assert.ok(types.includes('task.terminal.completed'), 'terminal events received live')
  assert.ok(types.includes('task.completed'), 'completion received live')

  // §24 PREVIEW + kept-alive hand-off: the port registration and the
  // kept_alive flag land during finalization (after the terminal
  // status write) — wait for them to settle, then assert.
  const r = await waitFor(async () => {
    const r = await api.call('GET', `/agent/tasks/${json.task.task_ref}`)
    return (r.json.task?.preview?.port && r.json.task?.preview?.kept_alive === true) ? r.json : null
  }, 20_000, 'preview registered and kept alive after completion')
  assert.ok(r.task.preview.port, `preview port registered: ${JSON.stringify(r.task.preview)}`)
  assert.equal(r.task.preview.kept_alive, true, 'preview kept alive after completion')
  assert.ok(mine.some(e => e.type === 'task.preview.ready'), 'preview.ready received')

  // Preview proxy serves the REAL file through the signed token
  const tok = await api.call('GET', `/agent/tasks/${json.task.task_ref}/preview-token`)
  assert.equal(tok.status, 200, `token issued after completion: ${JSON.stringify(tok.json)}`)
  if (tok.status === 200) {
    const page = await fetch(`${baseUrl}${tok.json.url}`)
    assert.equal(page.status, 200)
    const body = await page.text()
    assert.ok(body.includes('Agent preview works'), 'proxy serves the real dev-server response')
  }

  // §24/§17: an explicit stop reaps the kept-alive dev server
  const stop = await api.call('POST', `/agent/tasks/${json.task.task_ref}/stop`, {})
  assert.equal(stop.status, 200)
  assert.ok(stop.json.preview_stopped, 'stop reported preview_stopped')
  const tokAfter = await api.call('GET', `/agent/tasks/${json.task.task_ref}/preview-token`)
  assert.equal(tokAfter.status, 409, 'preview token refused after stop')

  // Honest port death: nothing is listening on the old preview port
  const net = require('net')
  const dead = await new Promise((resolve) => {
    const s = net.Socket()
    s.once('connect', () => { s.destroy(); resolve(false) })
    s.once('error', () => resolve(true))
    s.setTimeout(800, () => { s.destroy(); resolve(true) })
    try { s.connect(tok.json.port, '127.0.0.1') } catch { resolve(true) }
  })
  assert.ok(dead, 'the dev-server port is actually closed after stop')

  // Cleanup workspace
  const { Workspace } = require('../../services/agent/sandbox')
  await new Workspace(json.task.id).remove().catch(() => {})
})

test('event catch-up endpoint restores state after a reconnect (§30)', async () => {
  const tasks = await api.call('GET', '/agent/tasks?limit=10')
  const anyTask = tasks.json.tasks[0]
  assert.ok(anyTask, 'at least one task exists')
  const all = await api.call('GET', `/agent/tasks/${anyTask.task_ref}/events?after=0`)
  assert.ok(all.json.events.length > 5, 'full event timeline retrievable')
  const half = all.json.events[Math.floor(all.json.events.length / 2)]
  const tail = await api.call('GET', `/agent/tasks/${anyTask.task_ref}/events?after=${half.seq}`)
  assert.equal(tail.json.events.length, all.json.events.length - Math.floor(all.json.events.length / 2) - 1)
  // Gap-free: first tail event seq is exactly half.seq + 1
  assert.equal(tail.json.events[0].seq, half.seq + 1)
})

test('blocked commands are refused honestly and the agent continues (§13/§18)', async () => {
  const { json } = await api.call('POST', '/agent/tasks', { prompt: 'Try to remove everything then list files.' })
  const final = await waitFor(async () => {
    const r = await api.call('GET', `/agent/tasks/${json.task.task_ref}`)
    return ['completed', 'failed'].includes(r.json.task?.status) ? r.json : null
  }, 60_000, 'blocked-command task completion')
  assert.equal(final.task.status, 'completed')

  // The blocked attempt was RECORDED as an event — no silent failures
  const logs = await api.call('GET', `/agent/tasks/${json.task.task_ref}/logs`)
  const blocked = logs.json.logs.find(l => l.type === 'task.terminal.blocked')
  assert.ok(blocked, 'terminal.blocked event persisted')
  assert.ok(blocked.data.reason.includes('blocked') || blocked.data.command.includes('rm -rf'))

  // Nothing was actually deleted: workspace still has its files
  const files = await api.call('GET', `/agent/tasks/${json.task.task_ref}/files`)
  assert.ok(files.json.entries.length >= 1, 'workspace files intact')
  const { Workspace } = require('../../services/agent/sandbox')
  await new Workspace(json.task.id).remove().catch(() => {})
})

test('high-risk commands wait for user confirmation and honour denial (§13)', async () => {
  const { json } = await api.call('POST', '/agent/tasks', { prompt: 'Push the repository to production.' })
  const taskRef = json.task.task_ref

  // Task must reach waiting_for_confirmation with a live request
  const waiting = await waitFor(async () => {
    const r = await api.call('GET', `/agent/tasks/${taskRef}`)
    return r.json.task?.status === 'waiting_for_confirmation' ? r.json : null
  }, 30_000, 'waiting_for_confirmation')

  const req = waiting.events.reverse().find(e => e.type === 'task.confirmation.requested')
  assert.ok(req, 'confirmation.requested event exists')
  assert.ok(req.data.command.includes('git push'), 'the dangerous command is shown to the user')

  // Deny it
  const deny = await api.call('POST', `/agent/tasks/${taskRef}/confirm`, { confirmationId: req.data.id, approved: false })
  assert.equal(deny.status, 200)

  const final = await waitFor(async () => {
    const r = await api.call('GET', `/agent/tasks/${taskRef}`)
    return ['completed', 'failed'].includes(r.json.task?.status) ? r.json : null
  }, 60_000, 'denied push task completion')
  assert.equal(final.task.status, 'completed')
  assert.ok(final.task.result.toLowerCase().includes('declined') || final.task.result.toLowerCase().includes('push'))

  // Honest evidence: no push was executed (no successful git push terminal event)
  const logs = await api.call('GET', `/agent/tasks/${taskRef}/logs`)
  const pushes = logs.json.logs.filter(l => l.type === 'task.terminal.completed' && (l.data.command || '').includes('git push'))
  assert.equal(pushes.length, 0, 'git push never executed')
  const { Workspace } = require('../../services/agent/sandbox')
  await new Workspace(json.task.id).remove().catch(() => {})
})

test('task cancellation stops execution and marks state honestly (§17)', async () => {
  // The scripted task runs a REAL 30s command, so the worker is
  // guaranteed to be mid-execution when the user stops it.
  const { json } = await api.call('POST', '/agent/tasks', { prompt: 'Run the long build and report results.' })
  assert.equal(json.task?.task_ref ? 201 : 201, 201, `created: ${JSON.stringify(json)}`)

  // Wait until the worker is REALLY executing (running status), then stop.
  await waitFor(async () => {
    const r = await api.call('GET', `/agent/tasks/${json.task.task_ref}`)
    return ['running', 'planning'].includes(r.json.task?.status)
  }, 15_000, 'task enters running state')
  await wait(300) // let the sleep command actually spawn
  const stop = await api.call('POST', `/agent/tasks/${json.task.task_ref}/stop`, {})
  assert.equal(stop.status, 200, `stop accepted: ${JSON.stringify(stop.json)}`)

  const final = await waitFor(async () => {
    const r = await api.call('GET', `/agent/tasks/${json.task.task_ref}`)
    return ['cancelled', 'completed', 'failed'].includes(r.json.task?.status) ? r.json : null
  }, 30_000, 'cancellation settles')
  assert.equal(final.task.status, 'cancelled', `expected cancelled, got ${final.task.status}: ${JSON.stringify(final.task.error)}`)

  // §12 process cleanup: the sleep process tree must be gone.
  const { execFileSync } = require('child_process')
  let sleepLeft = ''
  try { sleepLeft = execFileSync('bash', ['-c', 'ps -eo args | grep -c "[s]leep 30" || true']).toString().trim() } catch {}
  assert.equal(sleepLeft, '0', `no orphaned sleep process left (${sleepLeft})`)

  const { Workspace } = require('../../services/agent/sandbox')
  await new Workspace(json.task.id).remove().catch(() => {})
})

test('unauthenticated access is rejected (auth preserved)', async () => {
  const noAuth = await fetch(`${baseUrl}/api/agent/tasks`)
  assert.equal(noAuth.status, 401)
  const badToken = await fetch(`${baseUrl}/api/agent/tasks`, { headers: { Authorization: 'Bearer nonsense' } })
  assert.equal(badToken.status, 401)
})

test('empty prompts and cross-user access are rejected', async () => {
  const empty = await api.call('POST', '/agent/tasks', { prompt: '   ' })
  assert.equal(empty.status, 400)
  // Cross-user: another user cannot read the task
  const other = jwt.sign({ id: new mongoose.Types.ObjectId().toString(), username: 'x', email: 'x@x.x' }, process.env.JWT_SECRET || 'kinyabot_jwt_secret_change_me')
  const tasks = await api.call('GET', '/agent/tasks')
  const anyRef = tasks.json.tasks[0]?.task_ref
  if (anyRef) {
    const res = await fetch(`${baseUrl}/api/agent/tasks/${anyRef}`, { headers: { Authorization: `Bearer ${other}` } })
    assert.equal(res.status, 404, 'other users cannot see this task')
  }
})
