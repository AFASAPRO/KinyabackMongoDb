/**
 * KinyaBot Agent V1 — Tool Layer Tests (§37)
 * read/write/edit/search/list/delete + project detection + git.
 * Run: NODE_ENV=test node --test tests/agent/tools.test.js
 */
const test = require('node:test')
const assert = require('node:assert')
const fs = require('fs')
const fsp = fs.promises

const registry = require('../../services/agent/tools/registry')
require('../../services/agent/tools/filesystem')
require('../../services/agent/tools/terminal')
require('../../services/agent/tools/project').registerAll()
require('../../services/agent/tools/git')

const agentConfig = require('../../services/agent/config')
const { Workspace } = require('../../services/agent/sandbox')

let ws, ctx
test.before(async () => {
  ws = new Workspace('tooltest' + Date.now().toString(36))
  await ws.ensure()
  ctx = {
    workspace: ws,
    taskId: 'tooltest',
    permissions: { READ: true, WRITE: true, EXECUTE: true, GIT: true },
    limits: agentConfig.limits,
    events: [],
    emit: (type, data) => ctx.events.push({ type, data }),
    runCommand: async () => { throw new Error('runCommand is wired by the worker — not used here') },
    requireConfirmation: async () => false,
  }
})

test('create_file really writes and emits a change', async () => {
  const res = await registry.executeTool('create_file', { path: 'src/app.js', content: 'console.log("v1")\n' }, ctx)
  assert.equal(res.ok, true)
  const onDisk = await fsp.readFile(ws.resolve('src/app.js'), 'utf8')
  assert.equal(onDisk, 'console.log("v1")\n')
  const ev = ctx.events.find(e => e.type === 'file_changed' && e.data.path === 'src/app.js')
  assert.ok(ev, 'file_changed event emitted')
  assert.equal(ev.data.action, 'created')
  assert.ok(ev.data.change.added >= 1)
})

test('create_file refuses to overwrite existing files', async () => {
  await assert.rejects(
    () => registry.executeTool('create_file', { path: 'src/app.js', content: 'x' }, ctx),
    (e) => e.code === 'TOOL_ALREADY_EXISTS'
  )
})

test('read_file returns real content with line info', async () => {
  const res = await registry.executeTool('read_file', { path: 'src/app.js' }, ctx)
  assert.equal(res.content, 'console.log("v1")\n')  // faithful trailing newline
  assert.equal(res.totalLines, 1)
})

test('edit_file applies a targeted edit and records a real diff', async () => {
  const res = await registry.executeTool('edit_file', {
    path: 'src/app.js', find: 'console.log("v1")', replace: 'console.log("v2")',
  }, ctx)
  assert.equal(res.occurrences, 1)
  const after = await fsp.readFile(ws.resolve('src/app.js'), 'utf8')
  assert.equal(after, 'console.log("v2")\n')
  const ev = ctx.events.filter(e => e.type === 'file_changed' && e.data.path === 'src/app.js').pop()
  assert.equal(ev.data.action, 'modified')
  assert.equal(ev.data.change.removed, 1)
  assert.equal(ev.data.change.added, 1)
})

test('edit_file fails honestly with helpful context when the target is missing', async () => {
  await assert.rejects(
    () => registry.executeTool('edit_file', { path: 'src/app.js', find: 'NOT PRESENT AT ALL', replace: 'x' }, ctx),
    (e) => e.code === 'TOOL_EDIT_MISS'
  )
})

test('write_file full rewrite records before/after diff', async () => {
  await registry.executeTool('write_file', { path: 'src/app.js', content: 'console.log("v3")\nconsole.log("more")\n' }, ctx)
  const after = await fsp.readFile(ws.resolve('src/app.js'), 'utf8')
  assert.ok(after.includes('v3'))
  const ev = ctx.events.filter(e => e.type === 'file_changed').pop()
  assert.equal(ev.data.change.removed >= 1, true)
})

test('search_files finds real matches with line numbers', async () => {
  await registry.executeTool('create_file', { path: 'src/util.js', content: 'export function greet() {\n  return "hi";\n}\n' }, ctx)
  const res = await registry.executeTool('search_files', { query: 'greet' }, ctx)
  assert.ok(res.matches.some(m => m.path === 'src/util.js' && m.line === 1))
})

test('search_files regex mode works', async () => {
  const res = await registry.executeTool('search_files', { query: 'console\\.log\\("v\\d"\\)', isRegex: true }, ctx)
  assert.ok(res.matches.length >= 1)
})

test('list_files returns a sorted tree with types and sizes', async () => {
  const res = await registry.executeTool('list_files', { path: '.', depth: 2 }, ctx)
  assert.ok(res.entries.some(e => e.path === 'src' && e.type === 'dir'))
  assert.ok(res.entries.some(e => e.path === 'src/app.js' && e.type === 'file' && e.size > 0))
})

test('delete_file removes files and refuses non-empty dirs', async () => {
  await assert.rejects(
    () => registry.executeTool('delete_file', { path: 'src' }, ctx),
    (e) => e.code === 'TOOL_DIR_NOT_EMPTY'
  )
  const res = await registry.executeTool('delete_file', { path: 'src/util.js' }, ctx)
  assert.equal(res.deleted, true)
  assert.equal(await ws.exists('src/util.js'), false)
})

test('permission enforcement: WRITE tools denied without WRITE', async () => {
  const readCtx = { ...ctx, permissions: { READ: true, WRITE: false, EXECUTE: false, GIT: false } }
  await assert.rejects(
    () => registry.executeTool('create_file', { path: 'x.txt', content: 'x' }, readCtx),
    (e) => e.code === 'TOOL_PERMISSION_DENIED'
  )
  await assert.rejects(
    () => registry.executeTool('run_command', { command: 'ls' }, readCtx),
    (e) => e.code === 'TOOL_PERMISSION_DENIED'
  )
})

test('unknown tools and invalid arguments are rejected', async () => {
  await assert.rejects(() => registry.executeTool('no_such_tool', {}, ctx), (e) => e.code === 'TOOL_UNKNOWN')
  await assert.rejects(
    () => registry.executeTool('read_file', { path: 12345 }, ctx),
    (e) => e.code === 'TOOL_INVALID_ARGS'
  )
  await assert.rejects(
    () => registry.executeTool('read_file', {}, ctx),
    (e) => e.code === 'TOOL_INVALID_ARGS'
  )
  await assert.rejects(
    () => registry.executeTool('read_file', { path: 'a.txt', bogus: true }, ctx),
    (e) => e.code === 'TOOL_INVALID_ARGS'
  )
})

test('tools cannot escape the workspace via the registry', async () => {
  await assert.rejects(
    () => registry.executeTool('read_file', { path: '../secrets' }, ctx),
    (e) => e.code === 'SANDBOX_VIOLATION'
  )
  await assert.rejects(
    () => registry.executeTool('write_file', { path: '/tmp/escape.txt', content: 'x' }, ctx),
    (e) => e.code === 'SANDBOX_VIOLATION'
  )
})

/* ── Project detection (§23) ─────────────────────────────────── */
test('detect_project identifies a Node/Vite/Vue project', async () => {
  await registry.executeTool('create_file', {
    path: 'package.json',
    content: JSON.stringify({
      name: 'demo', scripts: { dev: 'vite', build: 'vite build', test: 'vitest run' },
      dependencies: { vue: '^3.4.0', vite: '^5.0.0' }, devDependencies: { vitest: '^1.0.0' },
    }, null, 2),
  }, ctx)
  await registry.executeTool('create_file', { path: 'src/main.js', content: "import { createApp } from 'vue'\n" }, ctx)

  const res = await registry.executeTool('detect_project', {}, ctx)
  assert.equal(res.hasProject, true)
  assert.ok(res.frameworks.some(f => f.id === 'vue'))
  assert.ok(res.frameworks.some(f => f.id === 'vite'))
  assert.equal(res.language, 'javascript')
  assert.equal(res.packageManager, 'npm')
  assert.equal(res.devServerCommand, 'npm run dev')
  assert.equal(res.buildCommand, 'npm run build')
  assert.equal(res.testCommand, 'npm test')
  assert.ok(res.entryPoints.includes('src/main.js'))
})

test('focused detectors agree with the full profile', async () => {
  const pm = await registry.executeTool('detect_package_manager', {}, ctx)
  assert.equal(pm.packageManager, 'npm')
  const fw = await registry.executeTool('detect_framework', {}, ctx)
  assert.ok(fw.frameworks.some(f => f.id === 'vue'))
  const ds = await registry.executeTool('detect_dev_server', {}, ctx)
  assert.equal(ds.devServerCommand, 'npm run dev')
})

test('empty workspace is reported honestly as no project', async () => {
  const ws2 = new Workspace('empty' + Date.now().toString(36))
  await ws2.ensure()
  const ctx2 = { ...ctx, workspace: ws2 }
  const res = await registry.executeTool('detect_project', {}, ctx2)
  assert.equal(res.hasProject, false)
  await ws2.remove()
})

/* ── Git tools (§8) ──────────────────────────────────────────── */
test('git tools report "not a repository" honestly in a fresh workspace', async () => {
  const ws2 = new Workspace('gitless' + Date.now().toString(36))
  await ws2.ensure()
  const ctx2 = { ...ctx, workspace: ws2 }
  const status = await registry.executeTool('git_status', {}, ctx2)
  assert.equal(status.isRepository, false)
  await ws2.remove()
})

test('git tools read real repository state', async () => {
  // init a real repo with one commit through the terminal tool path
  const { runRealCommand } = require('../../services/agent/tools/terminal')
  const { buildCommandEnv } = require('../../services/agent/sandbox')
  await registry.executeTool('write_file', { path: 'committed.txt', content: 'tracked\n' }, ctx)
  const init = await runRealCommand({ command: 'git init -q && git config user.email a@b.c && git config user.name T && git add -A && git commit -qm init', cwd: ws.root, env: buildCommandEnv(ws.root), timeoutMs: 20000, maxOutputBytes: 20000 })
  assert.equal(init.exitCode, 0, `git init chain succeeded — stderr: ${init.stderr.slice(0, 200)}`)

  const status = await registry.executeTool('git_status', {}, ctx)
  assert.equal(status.isRepository, true)
  assert.ok(status.branch)

  const log = await registry.executeTool('git_log', {}, ctx)
  assert.ok(log.commits.length >= 1)
  assert.equal(log.commits[0].message, 'init')

  // Modification of a TRACKED file → git_diff reports it
  // (untracked files honestly never appear in git diff)
  await registry.executeTool('write_file', { path: 'committed.txt', content: 'modified\n' }, ctx)
  const diff = await registry.executeTool('git_diff', {}, ctx)
  assert.equal(diff.empty, false)
  assert.ok(diff.diff.includes('committed.txt'))
})

test.after(async () => {
  await ws.remove().catch(() => {})
})
