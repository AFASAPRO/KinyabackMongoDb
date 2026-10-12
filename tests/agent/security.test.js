/**
 * KinyaBot Agent V1 — Sandbox & Security Tests (§12, §37)
 * Workspace boundary · traversal · symlinks · secret protection.
 * Run: NODE_ENV=test node --test tests/agent/security.test.js
 */
const test = require('node:test')
const assert = require('node:assert')
const fs = require('fs')
const fsp = fs.promises
const path = require('path')
const os = require('os')

const { Workspace, buildCommandEnv, resolveInsideWorkspace } = require('../../services/agent/sandbox')
const { runRealCommand } = require('../../services/agent/tools/terminal')
const agentConfig = require('../../services/agent/config')

async function mkWorkspace() {
  const id = 'w' + Math.random().toString(36).slice(2, 12)
  const ws = new Workspace(id)
  await ws.ensure()
  return ws
}

test('workspace paths resolve inside the root', async () => {
  const ws = await mkWorkspace()
  const p = ws.resolve('src/app.js')
  assert.ok(p.startsWith(ws.root))
  assert.ok(p.includes(path.join(ws.taskId, 'src', 'app.js')))
  await ws.remove()
})

test('traversal attempts are rejected with SANDBOX_VIOLATION', async () => {
  const ws = await mkWorkspace()
  for (const bad of ['../other/file', '....//escape', 'a/../../b', '../../backend/.env']) {
    assert.throws(() => ws.resolve(bad), (e) => e.code === 'SANDBOX_VIOLATION', `should reject: ${bad}`)
  }
  await ws.remove()
})

test('absolute paths outside the workspace are rejected', async () => {
  const ws = await mkWorkspace()
  assert.throws(() => ws.resolve('/etc/passwd'), (e) => e.code === 'SANDBOX_VIOLATION')
  assert.throws(() => ws.resolve('/home/z/my-project/kinyabot/Kinyabot/backend/.env'), (e) => e.code === 'SANDBOX_VIOLATION')
  await ws.remove()
})

test('symlink escapes are rejected', async () => {
  const ws = await mkWorkspace()
  const outsideDir = await fsp.mkdtemp(path.join(os.tmpdir(), 'kinya-out-'))
  await fsp.writeFile(path.join(outsideDir, 'secret.txt'), 'TOPSECRET')
  // A symlink INSIDE the workspace pointing OUT
  await fsp.symlink(outsideDir, path.join(ws.root, 'leak'))
  assert.throws(() => ws.resolve('leak/secret.txt'), (e) => e.code === 'SANDBOX_VIOLATION')
  await fsp.rm(outsideDir, { recursive: true, force: true })
  await ws.remove()
})

test('command env contains no secrets and no inherited vars', () => {
  const env = buildCommandEnv('/tmp/fake-workspace')
  const keys = Object.keys(env)
  for (const forbidden of ['GROQ_API_KEY', 'JWT_SECRET', 'ADMIN_SECRET', 'MONGODB_URI', 'SMTP_PASS', 'NODE_ENV']) {
    assert.ok(!keys.includes(forbidden), `command env must not contain ${forbidden}`)
  }
  assert.equal(env.HOME, '/tmp/fake-workspace')
  assert.ok(env.PATH)
})

test('commands cannot read backend secrets through the sandboxed env', async () => {
  const ws = await mkWorkspace()
  const result = await runRealCommand({
    command: 'env | sort; echo "---"; cat ../.env 2>&1 || true',
    cwd: ws.root,
    env: buildCommandEnv(ws.root),
    timeoutMs: 10_000,
    maxOutputBytes: 10_000,
  })
  assert.equal(result.exitCode, 0)
  // The env listing must not contain any production secret names.
  for (const secret of ['GROQ_API_KEY', 'JWT_SECRET', 'ADMIN_SECRET', 'MONGODB_URI', 'SMTP_PASS']) {
    assert.ok(!result.stdout.includes(secret + '='), `stdout leaked ${secret}`)
    assert.ok(!result.stderr.includes(secret), `stderr leaked ${secret}`)
  }
  await ws.remove()
})

test('commands run with the workspace as cwd and home', async () => {
  const ws = await mkWorkspace()
  const result = await runRealCommand({
    command: 'pwd && echo $HOME',
    cwd: ws.root,
    env: buildCommandEnv(ws.root),
    timeoutMs: 10_000,
    maxOutputBytes: 5_000,
  })
  assert.equal(result.exitCode, 0)
  assert.ok(result.stdout.includes(ws.root))
  await ws.remove()
})

test('command timeout kills the process tree and reports honestly', async () => {
  const ws = await mkWorkspace()
  const result = await runRealCommand({
    command: 'sleep 30',
    cwd: ws.root,
    env: buildCommandEnv(ws.root),
    timeoutMs: 1200,
    maxOutputBytes: 5_000,
  })
  assert.equal(result.timedOut, true)
  assert.equal(result.exitCode, 124)
  assert.ok(result.durationMs < 10_000)
  await ws.remove()
})

test('output is captured and capped honestly', async () => {
  const ws = await mkWorkspace()
  const result = await runRealCommand({
    command: 'seq 1 100000',
    cwd: ws.root,
    env: buildCommandEnv(ws.root),
    timeoutMs: 15_000,
    maxOutputBytes: 2048,
  })
  assert.equal(result.truncated, true)
  assert.ok(result.stdout.length <= 2048 + 100)
  await ws.remove()
})

test('workspace id is validated against path injection', () => {
  assert.throws(() => new Workspace('../../etc'), (e) => e.code === 'SANDBOX_VIOLATION')
  assert.throws(() => new Workspace('a b/c'), (e) => e.code === 'SANDBOX_VIOLATION')
})
