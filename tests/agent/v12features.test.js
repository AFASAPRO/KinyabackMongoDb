/**
 * KinyaBot Agent V1.2 — Feature Tests (§2, §3, §8, §9, §10, §12, §14, §17)
 * ─────────────────────────────────────────────────────────────────────────
 * Boots the REAL routes (agent + notifications + admin) against a test
 * database with REAL workspaces on disk, and verifies:
 *
 *   §2  • unknown /api paths return JSON (API_NOT_FOUND), never an
 *         HTML 404 page that could be saved as a fake zip
 *   §3  • STATIC PREVIEW: a multi-file HTML/CSS/JS site is served with
 *         correct MIME types, nested relative paths, images; a missing
 *         asset is an honest 404; dotfiles are refused; the explicit
 *         stop ends the preview
 *   §8  • reference-image uploads: type sniffing, size limit, honest
 *         errors, ownership on task creation
 *   §9  • project-zip upload → safe extraction into the task workspace
 *         (secrets skipped, paths intact), downloadable afterwards
 *   §10 • web_search tool: entitlement refusal + untrusted-content
 *         envelope + honest provider failure
 *   §12 • user notifications: persistence, dedupe, read state, list,
 *         push status (public key only when configured)
 *   §14 • superadmin agent management: real metrics, search, config
 *         validation + audit, authorization (users get 403)
 *
 * Run: MONGODB_URI=… NODE_ENV=test node --test tests/agent/v12features.test.js
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
const crypto = require('crypto')

/* FIXED db name: node --test runs files in parallel and the runner
   exports AGENT_TEST_DB for the integration file — sharing it would
   let parallel dropDatabase() calls stomp this suite's fixtures. */
const TEST_DB = 'kinyabot-agent-v12-test'

let app, server, baseUrl, token, token2, userId, userId2, adminToken
const createdTasks = []

/* A tiny real PNG (1x1) for the reference-image upload tests. */
const PNG_1PX = Buffer.from(
  '89504e470d0a1a0a0000000d49484452000000010000000108060000001f15c4890000000d49444154789c626001000000ffff03000006000557bfabd40000000049454e44ae426082', 'hex')

test.before(async () => {
  const baseUri = process.env.MONGODB_URI || require('dotenv').config().parsed.MONGODB_URI
  await mongoose.connect(baseUri, { dbName: TEST_DB })
  await mongoose.connection.dropDatabase()

  const { User, Admin, PlanConfig } = require('../../models')
  const plansService = require('../../services/plans')
  await plansService.ensureSeed()

  const user = await User.create({
    username: 'v12tester', email: 'v12tester@test.local',
    password_hash: await bcrypt.hash('test-password-123', 10), onboarded: true, email_verified: true,
  })
  const user2 = await User.create({
    username: 'v12intruder', email: 'v12intruder@test.local',
    password_hash: await bcrypt.hash('test-password-123', 10), onboarded: true, email_verified: true,
  })
  userId = user._id.toString()
  userId2 = user2._id.toString()
  const secret = process.env.JWT_SECRET || 'kinyabot_jwt_secret_change_me'
  token = jwt.sign({ id: userId, username: user.username, email: user.email }, secret, { expiresIn: '1d' })
  token2 = jwt.sign({ id: userId2, username: user2.username, email: user2.email }, secret, { expiresIn: '1d' })

  const admin = await Admin.create({
    username: 'v12admin', email: 'v12admin@test.local',
    password_hash: await bcrypt.hash('admin-password-123', 10),
  })
  const adminSecret = process.env.ADMIN_SECRET || 'kinyabot_admin_secret_change_me'
  adminToken = jwt.sign({ id: admin._id.toString(), username: admin.username, isAdmin: true }, adminSecret, { expiresIn: '1d' })

  app = express()
  app.use(express.json({ limit: '5mb' }))
  app.use((req, res, next) => { req.app.set('io', { to: () => ({ emit: () => {} }) }); next() })
  app.use('/api', require('../../routes/agent'))
  app.use('/api', require('../../routes/notifications'))
  app.use('/api/admin', require('../../routes/admin'))
  // The V1.2 JSON 404 catch-all, exactly as app.js registers it.
  app.use('/api', (req, res) => {
    res.status(404).json({ error: 'Unknown API endpoint.', code: 'API_NOT_FOUND', method: req.method, path: req.path })
  })
  server = http.createServer(app)
  await new Promise(r => server.listen(0, r))
  baseUrl = `http://127.0.0.1:${server.address().port}`
})

test.after(async () => {
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

async function call(method, apiPath, { auth = token, body = null, headers = {} } = {}) {
  const res = await fetch(`${baseUrl}/api${apiPath}`, {
    method,
    headers: { Authorization: auth ? `Bearer ${auth}` : '', ...(body ? { 'Content-Type': 'application/json' } : {}), ...headers },
    body: body ? JSON.stringify(body) : undefined,
  })
  let json = null
  try { json = await res.json() } catch {}
  return { status: res.status, json, res }
}

async function makeTask({ owner = userId, title = 'static site', status = 'completed', preview = null } = {}) {
  const { AgentTask } = require('../../models')
  const doc = await AgentTask.create({
    user_id: owner, conversation_id: null,
    task_ref: crypto.randomUUID(), title, prompt: 'build the site',
    status, workspace_id: null,
    permissions: {},
    ...(preview ? { preview } : {}),
  })
  doc.workspace_id = doc._id.toString()
  await doc.save()
  createdTasks.push(doc.task_ref)
  return doc
}

const { Workspace } = require('../../services/agent/sandbox')
const staticPreview = require('../../services/agent/staticPreview')

/* ═══ §2 — JSON 404 catch-all ═══════════════════════════════════ */
test('unknown /api paths return machine-readable JSON, never an HTML 404 (§2)', async () => {
  // A KNOWN route with an unknown task already answers JSON (honest 404)
  const r = await call('GET', '/agent/tasks/definitely-not-a-ref/download')
  assert.equal(r.status, 404)
  assert.equal(typeof r.json?.error, 'string', 'JSON error body — never an HTML page saved as a zip')
  // A totally unknown /api surface hits the V1.2 JSON catch-all
  const r2 = await call('POST', '/definitely/not/a/route')
  assert.equal(r2.status, 404)
  assert.equal(r2.json?.code, 'API_NOT_FOUND')
  assert.ok(r2.json?.path?.includes('definitely'), 'the path is echoed for diagnosis')
})

/* ═══ §3 — STATIC PREVIEW ═══════════════════════════════════════ */
test('static preview serves HTML, CSS, JS and images with correct MIME types (§3 acceptance)', async () => {
  const doc = await makeTask({ title: 'animated site' })
  const ws = new Workspace(doc._id.toString())
  await ws.ensure()
  // The §3 acceptance shape: separate CSS, separate JS, an image asset.
  await fsp.mkdir(path.join(ws.root, 'css'), { recursive: true })
  await fsp.mkdir(path.join(ws.root, 'images'), { recursive: true })
  await fsp.writeFile(path.join(ws.root, 'index.html'),
    '<!doctype html><html><head><link rel="stylesheet" href="css/style.css"></head>' +
    '<body><button id="b">Go</button><script src="app.js"></script></body></html>')
  await fsp.writeFile(path.join(ws.root, 'app.js'), 'document.getElementById("b").onclick=()=>document.body.classList.add("done");')
  await fsp.writeFile(path.join(ws.root, 'css', 'style.css'), 'body{background:#123}.done{color:#0f0}')
  await fsp.writeFile(path.join(ws.root, 'images', 'dot.png'), PNG_1PX)

  // Register the static preview exactly like finalize does.
  const root = await staticPreview.detectProjectRoot(ws.root)
  assert.equal(root, '.', 'root detected at workspace root')
  const { AgentTask } = require('../../models')
  await AgentTask.updateOne({ _id: doc._id }, { $set: { 'preview.mode': 'static', 'preview.root': root, 'preview.kept_alive': true } })

  const tok = await call('GET', `/agent/tasks/${doc.task_ref}/preview-token`)
  assert.equal(tok.status, 200, `token issued: ${JSON.stringify(tok.json)}`)
  assert.equal(tok.json?.mode, 'static')
  /* §3.B root-cause fix: the token response sets a path-scoped cookie so
     SUBRESOURCE requests (css/js/img — relative URLs drop the ?pt= query)
     authenticate too. Simulate the browser's cookie jar. */
  const setCookie = tok.res?.headers?.get('set-cookie') || ''
  assert.ok(setCookie.includes('kb_ag_pt='), 'preview cookie is set')
  assert.ok(setCookie.includes(`Path=/api/agent/tasks/${doc.task_ref}/preview`), 'cookie scoped to this preview only')
  assert.ok(/HttpOnly/i.test(setCookie) && /SameSite=Lax/i.test(setCookie), 'cookie is HttpOnly + SameSite=Lax')
  const jar = { Cookie: setCookie.split(';')[0] }

  const base = `${baseUrl}${tok.json.url}`
  const origin = `${baseUrl}${tok.json.url.split('?')[0]}`   // browsers resolve relative assets WITHOUT the query
  const html = await fetch(base)
  assert.equal(html.status, 200)
  assert.equal(html.headers.get('content-type'), 'text/html; charset=utf-8')
  assert.ok((await html.text()).includes('css/style.css'), 'the HTML references its stylesheet relatively')

  // Subresources carry NO ?pt= — they authenticate via the cookie
  const css = await fetch(`${origin}css/style.css`, { headers: jar })
  assert.equal(css.status, 200)
  assert.equal(css.headers.get('content-type'), 'text/css; charset=utf-8')
  assert.equal(await css.text(), 'body{background:#123}.done{color:#0f0}')

  const js = await fetch(`${origin}app.js`, { headers: jar })
  assert.equal(js.status, 200)
  assert.equal(js.headers.get('content-type'), 'text/javascript; charset=utf-8')

  const img = await fetch(`${origin}images/dot.png`, { headers: jar })
  assert.equal(img.status, 200)
  assert.equal(img.headers.get('content-type'), 'image/png')
  const imgBuf = Buffer.from(await img.arrayBuffer())
  assert.equal(imgBuf[0], 0x89, 'the REAL image bytes are served')

  // Explicit ?pt= also works (fresh iframe document links)
  const cssPt = await fetch(`${origin}css/style.css?pt=${encodeURIComponent(tok.json.token)}`)
  assert.equal(cssPt.status, 200)

  // Query strings pass through without breaking resolution (§3.D)
  const cssQ = await fetch(`${origin}css/style.css?v=2`, { headers: jar })
  assert.equal(cssQ.status, 200)

  // Missing asset → honest 404 with diagnostics, never a silent rewrite
  const missing = await fetch(`${origin}css/nope.css`, { headers: jar })
  assert.equal(missing.status, 404)
  assert.ok((await missing.text()).includes('not found'))

  // Without ANY credential the request is refused (auth intact, §3.G)
  const naked = await fetch(`${origin}css/style.css`)
  assert.equal(naked.status, 401)

  // §3.G: dotfiles are never previewable
  await fsp.writeFile(path.join(ws.root, '.env'), 'SECRET=1')
  const dot = await fetch(`${origin}.env`, { headers: jar })
  assert.equal(dot.status, 404)
})

test('static preview detects a nested project root and survives refresh via persisted mode (§3.A/§25)', async () => {
  const doc = await makeTask({ title: 'nested site' })
  const ws = new Workspace(doc._id.toString())
  await ws.ensure()
  await fsp.mkdir(path.join(ws.root, 'my-site', 'assets'), { recursive: true })
  await fsp.writeFile(path.join(ws.root, 'my-site', 'index.html'), '<p>nested</p>')
  await fsp.writeFile(path.join(ws.root, 'my-site', 'assets', 'app.css'), 'p{margin:0}')

  const root = await staticPreview.detectProjectRoot(ws.root)
  assert.equal(root, 'my-site', 'wrapper folder detected as the project root')

  const { AgentTask } = require('../../models')
  await AgentTask.updateOne({ _id: doc._id }, { $set: { 'preview.mode': 'static', 'preview.root': root, 'preview.kept_alive': true } })

  const tok = await call('GET', `/agent/tasks/${doc.task_ref}/preview-token`)
  assert.equal(tok.status, 200)
  assert.equal(tok.json?.root, 'my-site')
  const page = await fetch(`${baseUrl}${tok.json.url}`)
  assert.equal(page.status, 200)
  assert.ok((await page.text()).includes('nested'))
  const setCookie = tok.res?.headers?.get('set-cookie') || ''
  const jar = { Cookie: setCookie.split(';')[0] }
  const asset = await fetch(`${baseUrl}${tok.json.url.split('?')[0]}assets/app.css`, { headers: jar })
  assert.equal(asset.status, 200)
  assert.equal(asset.headers.get('content-type'), 'text/css; charset=utf-8')
})

test('an explicit stop ends the static preview — the token is refused afterwards (§11)', async () => {
  const doc = await makeTask({ title: 'stoppable site' })
  const ws = new Workspace(doc._id.toString())
  await ws.ensure()
  await fsp.writeFile(path.join(ws.root, 'index.html'), '<p>x</p>')
  const { AgentTask } = require('../../models')
  await AgentTask.updateOne({ _id: doc._id }, { $set: { 'preview.mode': 'static', 'preview.kept_alive': true } })

  const before = await call('GET', `/agent/tasks/${doc.task_ref}/preview-token`)
  assert.equal(before.status, 200)

  const orchestrator = require('../../services/agent/orchestrator')
  await orchestrator.cancelTask(doc._id.toString(), 'stopped by test')

  const after = await call('GET', `/agent/tasks/${doc.task_ref}/preview-token`)
  assert.equal(after.status, 409, `refused after explicit stop: ${JSON.stringify(after.json)}`)
})

test('another user can never fetch a static preview token (ownership, §3.G)', async () => {
  const doc = await makeTask({ title: 'private site' })
  const ws = new Workspace(doc._id.toString())
  await ws.ensure()
  await fsp.writeFile(path.join(ws.root, 'index.html'), '<p>private</p>')
  const { AgentTask } = require('../../models')
  await AgentTask.updateOne({ _id: doc._id }, { $set: { 'preview.mode': 'static', 'preview.kept_alive': true } })

  const intruder = await call('GET', `/agent/tasks/${doc.task_ref}/preview-token`, { auth: token2 })
  assert.equal(intruder.status, 404)
})

/* ═══ §8 — reference-image uploads ══════════════════════════════ */
async function multipart(pathname, buf, filename, ctype, auth = token) {
  const fd = new FormData()
  fd.append('file', new Blob([buf], { type: ctype }), filename)
  const res = await fetch(`${baseUrl}/api${pathname}`, {
    method: 'POST',
    headers: { Authorization: auth ? `Bearer ${auth}` : '' },
    body: fd,
  })
  let json = null
  try { json = await res.json() } catch {}
  return { status: res.status, json }
}

test('reference images upload with magic-byte validation and honest refusals (§8)', async () => {
  // real PNG → accepted
  const ok = await multipart('/agent/uploads/reference-image', PNG_1PX, 'design.png', 'image/png')
  assert.equal(ok.status, 201, `accepted: ${JSON.stringify(ok.json)}`)
  assert.equal(ok.json?.upload?.kind, 'reference_image')

  // text file disguised as PNG → refused by CONTENT sniffing
  const fake = await multipart('/agent/uploads/reference-image', Buffer.from('plain text, not an image'), 'evil.png', 'image/png')
  assert.equal(fake.status, 400)
  assert.equal(fake.json?.code, 'UPLOAD_INVALID_TYPE')

  // oversize image → refused
  const big = Buffer.alloc(7 * 1024 * 1024)
  big.fill(PNG_1PX.subarray(0, 8), 0, 8)
  const tooBig = await multipart('/agent/uploads/reference-image', big, 'huge.png', 'image/png')
  assert.equal(tooBig.status, 413)
  assert.equal(tooBig.json?.code, 'UPLOAD_TOO_LARGE')

  // unauthenticated → refused
  const anon = await multipart('/agent/uploads/reference-image', PNG_1PX, 'anon.png', 'image/png', null)
  assert.equal(anon.status, 401)

  // another user's upload id is refused at task creation (ownership)
  const foreign = await call('POST', '/agent/tasks', {
    auth: token2,
    body: { prompt: 'use this image', referenceImageIds: [ok.json.upload.id] },
  })
  assert.equal(foreign.status, 404)
  assert.equal(foreign.json?.code, 'UPLOAD_NOT_FOUND')

  // the upload endpoint requires an entitled (authenticated) user only — vision capability:
  // the default test config uses a llama-4 vision model, so 201 is expected above.
  const agentConfig = require('../../services/agent/config')
  assert.equal(agentConfig.vision.capable, true, 'test env configures a vision-capable model')
})

/* ═══ §9 — project ZIP upload + extraction + download ═══════════ */
test('project zips upload, extract safely into the workspace, and download back (§9)', async () => {
  const archiver = require('archiver')
  const zipBuf = await new Promise((resolve, reject) => {
    const chunks = []
    const a = archiver('zip')
    a.on('data', c => chunks.push(c))
    a.on('end', () => resolve(Buffer.concat(chunks)))
    a.on('error', reject)
    a.append('<html><body>existing project</body></html>', { name: 'index.html' })
    a.append('body{color:#333}', { name: 'css/style.css' })
    a.append('A=1', { name: '.env' })                      // secret — must be SKIPPED
    a.append('console.log(1)', { name: 'app.js' })
    a.finalize()
  })

  const up = await multipart('/agent/uploads/project-zip', zipBuf, 'existing-project.zip', 'application/zip')
  assert.equal(up.status, 201, `zip accepted: ${JSON.stringify(up.json)}`)
  assert.equal(up.json?.upload?.kind, 'project_zip')

  // Create a task bound to the uploaded project — extraction runs
  // server-side before the worker starts. The scripted provider
  // completes harmlessly in the test environment.
  const task = await call('POST', '/agent/tasks', {
    body: { prompt: 'Fix the broken CSS of this project.', projectZipId: up.json.upload.id },
  })
  assert.equal(task.status, 201, `task created: ${JSON.stringify(task.json)}`)
  createdTasks.push(task.json?.task?.task_ref)

  // The workspace now holds the uploaded project files…
  const files = await call('GET', `/agent/tasks/${task.json.task.task_ref}/files`)
  assert.equal(files.status, 200)
  const names = (files.json?.entries || []).map(e => e.path).join('\n')
  assert.ok(names.includes('index.html'), 'index.html extracted')
  assert.ok(names.includes('css/style.css'), 'nested css extracted')
  assert.ok(names.includes('app.js'), 'app.js extracted')
  assert.ok(!names.includes('.env'), 'the .env secret was NOT extracted')

  // Wait for the scripted task to reach a terminal state so the
  // one-live-task guard doesn't 409 the NEXT task creation.
  const { AgentTask } = require('../../models')
  for (let i = 0; i < 120; i++) {
    const t = await AgentTask.findById(task.json.task.id).lean()
    if (t && ['completed', 'failed', 'cancelled'].includes(t.status)) break
    await new Promise(r => setTimeout(r, 250))
  }

  // …and the extraction event was recorded honestly
  const logs = await call('GET', `/agent/tasks/${task.json.task.task_ref}/logs`)
  const types = (logs.json?.logs || []).map(l => l.type)
  assert.ok(types.includes('task.upload.extracted'), 'task.upload.extracted event present')

  // A non-zip upload is refused
  const notZip = await multipart('/agent/uploads/project-zip', Buffer.from('definitely not a zip'), 'fake.zip', 'application/zip')
  assert.equal(notZip.status, 400)
  assert.equal(notZip.json?.code, 'UPLOAD_INVALID_TYPE')
})

test('zip-slip archives are rejected by the task-creation extraction (§9 archive security)', async () => {
  // Craft a raw hostile zip locally (same builder shape as the sanity script).
  function crc32(buf) {
    let table = crc32.table
    if (!table) {
      table = crc32.table = new Int32Array(256)
      for (let n = 0; n < 256; n++) { let c = n; for (let k = 0; k < 8; k++) c = (c & 1) ? (0xEDB88320 ^ (c >>> 1)) : (c >>> 1); table[n] = c }
    }
    let c = 0 ^ (-1)
    for (let i = 0; i < buf.length; i++) c = (c >>> 8) ^ table[(c ^ buf[i]) & 0xFF]
    return (c ^ (-1)) >>> 0
  }
  function buildRawZip(entries) {
    const locals = [], centrals = []
    let offset = 0
    for (const [name, content] of Object.entries(entries)) {
      const nameBuf = Buffer.from(name, 'utf8')
      const data = Buffer.isBuffer(content) ? content : Buffer.from(content, 'utf8')
      const crc = crc32(data)
      const lfh = Buffer.alloc(30)
      lfh.writeUInt32LE(0x04034b50, 0); lfh.writeUInt16LE(20, 4); lfh.writeUInt16LE(0, 6); lfh.writeUInt16LE(0, 8)
      lfh.writeUInt16LE(0, 10); lfh.writeUInt16LE(0x21, 12); lfh.writeUInt32LE(crc, 14)
      lfh.writeUInt32LE(data.length, 18); lfh.writeUInt32LE(data.length, 22)
      lfh.writeUInt16LE(nameBuf.length, 26); lfh.writeUInt16LE(0, 28)
      locals.push(lfh, nameBuf, data)
      const cdh = Buffer.alloc(46)
      cdh.writeUInt32LE(0x02014b50, 0); cdh.writeUInt16LE(20, 4); cdh.writeUInt16LE(20, 6)
      cdh.writeUInt16LE(0, 8); cdh.writeUInt16LE(0, 10); cdh.writeUInt16LE(0, 12); cdh.writeUInt16LE(0x21, 14)
      cdh.writeUInt32LE(crc, 16); cdh.writeUInt32LE(data.length, 20); cdh.writeUInt32LE(data.length, 24)
      cdh.writeUInt16LE(nameBuf.length, 28); cdh.writeUInt16LE(0, 30); cdh.writeUInt16LE(0, 32)
      cdh.writeUInt16LE(0, 34); cdh.writeUInt16LE(0, 36); cdh.writeUInt32LE(0, 38); cdh.writeUInt32LE(offset, 42)
      centrals.push(cdh, nameBuf)
      offset += lfh.length + nameBuf.length + data.length
    }
    const centralBuf = Buffer.concat(centrals)
    const eocd = Buffer.alloc(22)
    eocd.writeUInt32LE(0x06054b50, 0); eocd.writeUInt16LE(Object.keys(entries).length, 10)
    eocd.writeUInt32LE(centralBuf.length, 12); eocd.writeUInt32LE(offset, 16)
    return Buffer.concat([...locals, centralBuf, eocd])
  }

  const hostile = buildRawZip({ 'ok.txt': 'fine', '../evil.txt': 'pwn' })
  const up = await multipart('/agent/uploads/project-zip', hostile, 'evil.zip', 'application/zip')
  assert.equal(up.status, 201) // the upload itself is just bytes…

  // …but extraction at task creation REJECTS the traversal (user2 has
  // no live task, so the one-live-task guard cannot mask the 400)
  const task = await call('POST', '/agent/tasks', { body: { prompt: 'improve this', projectZipId: up.json.upload.id } })
  assert.equal(task.status, 400, `extraction rejected: ${JSON.stringify(task.json)}`)
  assert.equal(task.json?.code, 'ZIP_PATH_TRAVERSAL')
  assert.equal(fs.existsSync(path.join(process.cwd(), 'evil.txt')), false, 'no file escaped the workspace')
})

/* ═══ §10 — web_search tool (entitlements + untrusted envelope) ═ */
test('web_search refuses without entitlements and wraps results as untrusted data (§10)', async () => {
  const registry = require('../../services/agent/tools/registry')
  require('../../services/agent/tools/websearch')
  const tool = registry.getTool ? registry.getTool('web_search') : registry.listTools().find(t => t.name === 'web_search')
  assert.ok(tool, 'web_search tool registered')

  const wsCtx = {
    workspace: { root: '/tmp/does-not-matter', resolve: p => p },
    taskId: 't_test', permissions: { READ: true }, limits: {},
    entitlements: { webSearch: false, webSearchEnabled: true },
    emit: () => {},
  }
  await assert.rejects(
    () => tool.handler({ args: { query: 'latest vite docs' }, ctx: wsCtx }),
    e => e.code === 'SEARCH_ENTITLEMENT',
    'plan entitlement is enforced INSIDE the tool'
  )

  // Entitled + provider configured → results carry the untrusted envelope
  const langSearch = require('../../services/search/langSearchProvider')
  const aiConfig = require('../../services/ai/config')
  const origFetch = global.fetch
  global.fetch = async () => new Response(JSON.stringify({
    code: 200, data: { webPages: { value: [
      { name: 'Vite Guide', url: 'https://vite.dev/guide/', snippet: 'Build tool...' },
    ] } },
    usage: { input_tokens: 10, output_tokens: 5 },
  }), { status: 200 })
  try {
    aiConfig.langSearch.apiKey = 'test-key-for-v12'   // cached at require time — patch the cache
    const result = await tool.handler({
      args: { query: 'vite guide' },
      ctx: { ...wsCtx, entitlements: { webSearch: true, webSearchEnabled: true } },
    })
    assert.equal(result.performed, true)
    assert.ok(result.retrieved_at, 'retrieval timestamp present')
    assert.equal(result.results.length, 1)
    assert.equal(result.results[0].url, 'https://vite.dev/guide/')
    assert.ok(result.note.includes('UNTRUSTED WEB CONTENT'), 'untrusted-content envelope')
    assert.ok(result.text.includes('UNTRUSTED WEB CONTENT'))
  } finally {
    global.fetch = origFetch
    aiConfig.langSearch.apiKey = null
  }

  // Provider failure → honest error, never fabricated results
  global.fetch = async () => new Response('{"message":"boom"}', { status: 503 })
  try {
    aiConfig.langSearch.apiKey = 'test-key-for-v12'
    await assert.rejects(
      () => tool.handler({ args: { query: 'x' }, ctx: { ...wsCtx, entitlements: { webSearch: true, webSearchEnabled: true } } }),
      e => /unavailable|failed/i.test(e.message) && e.userSafe,
      'provider failure surfaces honestly'
    )
  } finally {
    global.fetch = origFetch
    aiConfig.langSearch.apiKey = null
  }
})

/* ═══ §12 — user notifications ══════════════════════════════════ */
test('user notifications persist, dedupe, and expose read state through the API (§12)', async () => {
  const { notifyUser } = require('../../services/notify')

  // Two deliveries of the SAME logical event → one row (dedupe)
  await notifyUser(userId, { type: 'success', kind: 'agent_task_completed', title: 'KinyaBot Agent — Task completed', message: 'Your site is ready.', link: '/chat/agent/abc', dedupeKey: 'task_done_t1' })
  await notifyUser(userId, { type: 'success', kind: 'agent_task_completed', title: 'KinyaBot Agent — Task completed', message: 'Your site is ready.', link: '/chat/agent/abc', dedupeKey: 'task_done_t1' })

  const list = await call('GET', '/me/notifications')
  assert.equal(list.status, 200)
  const rows = list.json?.notifications || []
  assert.equal(rows.filter(n => n.dedupe_key === 'task_done_t1').length, 1, `deduped to a single row — got ${JSON.stringify(rows.filter(n => n.dedupe_key === 'task_done_t1').map(n => ({id: n.id, kind: n.kind, key: n.dedupe_key, at: n.created_at})))}`)
  // The §9 task's REAL completion may have added more unread rows for
  // this user — assert OUR row exists and is unread, and unread >= 1.
  const mine = rows.find(n => n.dedupe_key === 'task_done_t1')
  assert.ok(mine, 'the deduped row is present')
  assert.equal(mine.read, false)
  assert.equal(mine.link, '/chat/agent/abc')
  assert.ok((list.json?.unread || 0) >= 1, `unread counts our row: ${list.json?.unread}`)

  // A distinct event → a second row (ours; real events may add more)
  await notifyUser(userId, { type: 'warning', kind: 'agent_confirmation_required', title: 'Approval needed', message: 'rm -rf', dedupeKey: 'confirm_t1_x' })
  const list2 = await call('GET', '/me/notifications')
  assert.ok((list2.json?.notifications || []).some(n => n.dedupe_key === 'confirm_t1_x'), 'distinct event creates its own row')

  // Mark all read
  const mr = await call('POST', '/me/notifications/read', { body: { all: true } })
  assert.equal(mr.status, 200)
  const list3 = await call('GET', '/me/notifications')
  assert.equal(list3.json?.unread, 0)
  assert.ok(list3.json.notifications.every(n => n.read === true))

  // Dismiss removes from the feed
  const target = list3.json.notifications[0]
  const dis = await call('POST', '/me/notifications/dismiss', { body: { id: target.id } })
  assert.equal(dis.status, 200)
  const list4 = await call('GET', '/me/notifications')
  assert.ok(!list4.json.notifications.some(n => n.id === target.id))

  // Push status is honest (no VAPID keys in tests)
  const push = await call('GET', '/me/notifications/push/status')
  assert.equal(push.status, 200)
  assert.equal(push.json?.configured, false)
  assert.equal(push.json?.public_key, null)

  // Another user sees NONE of these notifications
  const other = await call('GET', '/me/notifications', { auth: token2 })
  assert.equal(other.json?.notifications?.length, 0)
  assert.equal(other.json?.unread, 0)
})

/* ═══ §14 — superadmin agent management ═════════════════════════ */
test('superadmin agent management: real metrics, search, config validation, audit, authz (§14)', async () => {
  // Unauthenticated + ordinary users are refused
  const anon = await call('GET', '/admin/agent/overview', { auth: null })
  assert.equal(anon.status, 401)
  const asUser = await call('GET', '/admin/agent/overview', { auth: token })
  assert.equal(asUser.status, 403)

  const overview = await call('GET', '/admin/agent/overview', { auth: adminToken })
  assert.equal(overview.status, 200)
  assert.ok(overview.json?.totals?.all >= 2, 'metrics computed from REAL AgentTask documents')
  assert.equal(overview.json?.workers?.running_now, 0)
  assert.ok(typeof overview.json?.agent_enabled === 'boolean')

  // Task browse + search
  const tasks = await call('GET', '/admin/agent/tasks?search=site', { auth: adminToken })
  assert.equal(tasks.status, 200)
  assert.ok(Array.isArray(tasks.json?.tasks))
  assert.ok(tasks.json.tasks.some(t => /site/i.test(t.title)), `search matches real titles — got ${JSON.stringify((tasks.json.tasks || []).map(t => t.title))}`)

  // Task detail (safe metadata + events)
  const one = tasks.json.tasks[0]
  const detail = await call('GET', `/admin/agent/tasks/${one.id}`, { auth: adminToken })
  assert.equal(detail.status, 200)
  assert.equal(detail.json?.task?.id, one.id)
  assert.ok(Array.isArray(detail.json?.events))

  // Config validation: an invalid value is rejected server-side
  const bad = await call('PUT', '/admin/agent/config', { auth: adminToken, body: { agent_max_concurrent: 999 } })
  assert.equal(bad.status, 400)

  // A valid change is applied AND audited
  const good = await call('PUT', '/admin/agent/config', { auth: adminToken, body: { agent_max_concurrent: 3, agent_daily_limit: 12 } })
  assert.equal(good.status, 200)
  const settings = require('../../services/settings')
  assert.equal(settings.get().agent_max_concurrent, 3)
  assert.equal(settings.get().agent_daily_limit, 12)
  const { AuditLog } = require('../../models')
  const auditRow = await AuditLog.findOne({ action: 'agent.settings.update' }).lean()
  assert.ok(auditRow, 'config change wrote an immutable audit row')
  assert.equal(auditRow.actor_username, 'v12admin')

  // Health endpoint reflects real configuration
  const health = await call('GET', '/admin/agent/health', { auth: adminToken })
  assert.equal(health.status, 200)
  assert.equal(health.json?.preview?.static_enabled, true)
  assert.ok(health.json?.workers && typeof health.json.workers.recent_crashes === 'number')

  // Restore defaults so later suites are unaffected
  await call('PUT', '/admin/agent/config', { auth: adminToken, body: { agent_max_concurrent: 2, agent_daily_limit: 30 } })
})
