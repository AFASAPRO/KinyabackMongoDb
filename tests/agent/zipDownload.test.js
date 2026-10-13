/**
 * KinyaBot Agent V1.1 — Project ZIP Download Tests (§8)
 * ─────────────────────────────────────────────────────────────
 * Boots the real routes/agent router against a test database and a
 * REAL workspace on disk, then verifies the /download endpoint:
 *
 *   • the archive contains the REAL workspace files (unzipped+checked)
 *   • secrets and junk are excluded (.env*, node_modules, .git, .tmp…)
 *   • symbolic links are never followed or packed
 *   • another user's task cannot be downloaded (ownership, 404)
 *   • an unauthenticated request is rejected (401)
 *   • an empty workspace yields an honest 409, never an empty zip
 *   • the Content-Disposition filename is derived from the task
 *
 * Run: MONGODB_URI=… NODE_ENV=test node --test tests/agent/zipDownload.test.js
 */
const test = require('node:test')
const assert = require('node:assert')
const http = require('http')
const express = require('express')
const mongoose = require('mongoose')
const jwt = require('jsonwebtoken')
const bcrypt = require('bcryptjs')
const fs = require('fs')
const fsp = fs.promises
const path = require('path')
const zlib = require('zlib')

const TEST_DB = process.env.AGENT_TEST_DB || 'kinyabot-agent-v11-zip-test'

let app, server, baseUrl, token, token2, userId, userId2
const createdTasks = []   // task_refs created by this run (cleanup)

test.before(async () => {
  const baseUri = process.env.MONGODB_URI || require('dotenv').config().parsed.MONGODB_URI
  await mongoose.connect(baseUri, { dbName: TEST_DB })
  await mongoose.connection.dropDatabase()

  const { User, PlanConfig } = require('../../models')
  const plansService = require('../../services/plans')
  await plansService.ensureSeed()

  const user = await User.create({
    username: 'ziptester', email: 'ziptester@test.local',
    password_hash: await bcrypt.hash('test-password-123', 10), onboarded: true, email_verified: true,
  })
  const user2 = await User.create({
    username: 'zipintruder', email: 'zipintruder@test.local',
    password_hash: await bcrypt.hash('test-password-123', 10), onboarded: true, email_verified: true,
  })
  userId2 = user2._id.toString()
  userId = user._id.toString()
  const secret = process.env.JWT_SECRET || 'kinyabot_jwt_secret_change_me'
  token = jwt.sign({ id: user._id.toString(), username: user.username, email: user.email }, secret, { expiresIn: '1d' })
  token2 = jwt.sign({ id: userId2, username: user2.username, email: user2.email }, secret, { expiresIn: '1d' })

  app = express()
  app.use(express.json({ limit: '5mb' }))
  app.use((req, res, next) => { req.app.set('io', { to: () => ({ emit: () => {} }) }); next() })
  app.use('/api', require('../../routes/agent'))
  server = http.createServer(app)
  await new Promise(r => server.listen(0, r))
  baseUrl = `http://127.0.0.1:${server.address().port}`
})

test.after(async () => {
  // Remove every workspace this test created.
  const { Workspace } = require('../../services/agent/sandbox')
  for (const ref of createdTasks) {
    try {
      const { AgentTask } = require('../../models')
      const doc = await AgentTask.findOne({ task_ref: ref })
      if (doc) await new Workspace(doc._id.toString()).remove()
    } catch {}
  }
  server?.close()
  await mongoose.connection.dropDatabase().catch(() => {})
  await mongoose.disconnect().catch(() => {})
})

async function call(method, apiPath, { auth = token, raw = false } = {}) {
  const res = await fetch(`${baseUrl}/api${apiPath}`, {
    method,
    headers: { Authorization: auth ? `Bearer ${auth}` : '' },
  })
  if (raw) return res
  let json = null
  try { json = await res.json() } catch {}
  return { status: res.status, json }
}

/** Create an AgentTask directly (no orchestrator — the router only
    needs the document + a workspace on disk for /download). */
async function makeTask({ userId: owner = userId, title, prompt = 'build it' } = {}) {
  const { AgentTask } = require('../../models')
  const crypto = require('crypto')
  const doc = await AgentTask.create({
    user_id: owner, conversation_id: null,
    task_ref: crypto.randomUUID(), title, prompt,
    status: 'completed', workspace_id: null,
    permissions: {},
  })
  doc.workspace_id = doc._id.toString()
  await doc.save()
  createdTasks.push(doc.task_ref)
  return doc
}

const { Workspace } = require('../../services/agent/sandbox')

/* Minimal ZIP reader: parses the central directory, inflates each
   entry, and returns { name → Buffer }. Enough for these tests. */
function readZip(buf) {
  const entries = {}
  // Locate the End of Central Directory record (PK\x05\x06).
  let eocd = -1
  for (let i = buf.length - 22; i >= 0; i--) {
    if (buf.readUInt32LE(i) === 0x06054b50) { eocd = i; break }
  }
  assert.ok(eocd >= 0, 'EOCD found — the response is a real zip')
  const count = buf.readUInt16LE(eocd + 10)
  let off = buf.readUInt32LE(eocd + 16)
  for (let n = 0; n < count; n++) {
    assert.equal(buf.readUInt32LE(off), 0x02014b50, 'central directory entry signature')
    const method = buf.readUInt16LE(off + 10)
    const compSize = buf.readUInt32LE(off + 20)
    const nameLen = buf.readUInt16LE(off + 28)
    const extraLen = buf.readUInt16LE(off + 30)
    const commentLen = buf.readUInt16LE(off + 32)
    const localOff = buf.readUInt32LE(off + 42)
    const name = buf.slice(off + 46, off + 46 + nameLen).toString('utf8')
    // Local header: name/extra lengths may differ from central.
    const lNameLen = buf.readUInt16LE(localOff + 26)
    const lExtraLen = buf.readUInt16LE(localOff + 28)
    const dataStart = localOff + 30 + lNameLen + lExtraLen
    const data = buf.slice(dataStart, dataStart + compSize)
    entries[name] = method === 8 ? zlib.inflateRawSync(data) : Buffer.from(data)
    off += 46 + nameLen + extraLen + commentLen
  }
  return entries
}

/* ══════════════════════════════════════════════════════════════
   §8 TESTS
════════════════════════════════════════════════════════════════ */
test('download returns the REAL workspace files as a valid zip', async () => {
  const doc = await makeTask({ title: 'Portfolio Site Build' })
  const ws = new Workspace(doc._id.toString())
  await ws.ensure()
  await fsp.writeFile(ws.resolve('index.html'), '<h1>real file</h1>\n')
  await fsp.mkdir(ws.resolve('src'), { recursive: true })
  await fsp.writeFile(ws.resolve('src/app.js'), 'console.log("real")\n')
  await fsp.writeFile(ws.resolve('package.json'), '{"name":"portfolio"}\n')
  await fsp.writeFile(ws.resolve('package-lock.json'), '{"lockfileVersion":3}\n')

  const res = await call('GET', `/agent/tasks/${doc.task_ref}/download`, { raw: true })
  assert.equal(res.status, 200, `download ok: ${res.status}`)
  assert.equal(res.headers.get('content-type'), 'application/zip')
  const disposition = res.headers.get('content-disposition') || ''
  assert.match(disposition, /^attachment; filename="portfolio-site-build-[0-9a-f]{8}\.zip"$/)

  const buf = Buffer.from(await res.arrayBuffer())
  const entries = readZip(buf)
  assert.equal(entries['index.html'].toString(), '<h1>real file</h1>\n')
  assert.equal(entries['src/app.js'].toString(), 'console.log("real")\n')
  assert.equal(entries['package.json'].toString(), '{"name":"portfolio"}\n')
  assert.equal(entries['package-lock.json'].toString(), '{"lockfileVersion":3}\n')
})

test('secrets, caches and dependency directories are excluded', async () => {
  const doc = await makeTask({ title: 'Secret Project' })
  const ws = new Workspace(doc._id.toString())
  await ws.ensure()
  await fsp.writeFile(ws.resolve('index.js'), 'keep me\n')
  await fsp.writeFile(ws.resolve('.env'), 'GROQ_API_KEY=gsk_super_secret\n')
  await fsp.writeFile(ws.resolve('.env.local'), 'JWT_SECRET=x\n')
  await fsp.writeFile(ws.resolve('run.log'), 'internal noise\n')
  await fsp.writeFile(ws.resolve('.port'), '34567\n')   // agent-internal bookkeeping
  const nm = ws.resolve('node_modules/left-pad')
  await fsp.mkdir(nm, { recursive: true })
  await fsp.writeFile(path.join(nm, 'index.js'), 'dependency junk')
  const gitDir = ws.resolve('.git/objects')
  await fsp.mkdir(gitDir, { recursive: true })
  await fsp.writeFile(path.join(gitDir, 'pack.bin'), 'binary junk')
  const tmpDir = ws.resolve('.tmp')
  await fsp.mkdir(tmpDir, { recursive: true })
  await fsp.writeFile(path.join(tmpDir, 'bg-1.log'), 'background log\n')

  const res = await call('GET', `/agent/tasks/${doc.task_ref}/download`, { raw: true })
  assert.equal(res.status, 200)
  const entries = readZip(Buffer.from(await res.arrayBuffer()))
  assert.ok(entries['index.js'], 'real file included')
  for (const forbidden of ['.env', '.env.local', 'run.log', 'node_modules/left-pad/index.js', '.git/objects/pack.bin', '.tmp/bg-1.log']) {
    assert.ok(!entries[forbidden], `${forbidden} must NOT be in the archive`)
  }
})

test('symbolic links inside the workspace are never packed', async () => {
  const doc = await makeTask({ title: 'Symlink Trap' })
  const ws = new Workspace(doc._id.toString())
  await ws.ensure()
  await fsp.writeFile(ws.resolve('real.txt'), 'innocent\n')
  // Symlink pointing OUTSIDE the workspace (attack surface §8).
  await fsp.symlink('/etc/passwd', ws.resolve('escape-link')).catch(() => {})
  // Symlink to an inside file — still skipped by policy.
  await fsp.symlink('real.txt', ws.resolve('inside-link')).catch(() => {})

  const res = await call('GET', `/agent/tasks/${doc.task_ref}/download`, { raw: true })
  assert.equal(res.status, 200)
  const entries = readZip(Buffer.from(await res.arrayBuffer()))
  assert.ok(entries['real.txt'], 'the real file is included')
  assert.ok(entries['escape-link'] === undefined, 'escape symlink not packed')
  assert.ok(entries['inside-link'] === undefined, 'inside symlink not packed')
  // No /etc/passwd content may appear ANYWHERE in the archive.
  const allContent = Object.values(entries).map(b => b.toString()).join('\n')
  assert.ok(!allContent.includes('root:'), 'no /etc/passwd content leaked')
})

test("another user's task cannot be downloaded", async () => {
  const doc = await makeTask({ title: 'Private Project', userId })
  const ws = new Workspace(doc._id.toString())
  await ws.ensure()
  await fsp.writeFile(ws.resolve('private.txt'), 'owner only\n')

  const asIntruder = await call('GET', `/agent/tasks/${doc.task_ref}/download`, { auth: token2, raw: true })
  assert.equal(asIntruder.status, 404, 'ownership enforced — 404, not the archive')

  const asOwner = await call('GET', `/agent/tasks/${doc.task_ref}/download`, { raw: true })
  assert.equal(asOwner.status, 200, 'the owner still gets it')
  const entries = readZip(Buffer.from(await asOwner.arrayBuffer()))
  assert.ok(entries['private.txt'])
})

test('unauthenticated requests are rejected', async () => {
  const doc = await makeTask({ title: 'No Auth' })
  const res = await call('GET', `/agent/tasks/${doc.task_ref}/download`, { auth: null, raw: true })
  assert.equal(res.status, 401)
})

test('empty workspace yields an honest 409 — never an empty zip', async () => {
  const doc = await makeTask({ title: 'Nothing Built Yet' })
  const ws = new Workspace(doc._id.toString())
  await ws.ensure()   // exists, but empty
  const { status, json } = await call('GET', `/agent/tasks/${doc.task_ref}/download`)
  assert.equal(status, 409)
  assert.equal(json.code, 'ZIP_EMPTY')
})

test('unknown task ref yields 404', async () => {
  const { status } = await call('GET', '/agent/tasks/00000000-0000-0000-0000-000000000000/download')
  assert.equal(status, 404)
})
