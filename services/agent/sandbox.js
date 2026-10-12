/**
 * KinyaBot Agent V1 — Sandbox & Workspace isolation (§11, §12)
 * ─────────────────────────────────────────────────────────────
 * Every Agent operation — file tool, command cwd, preview path —
 * MUST go through this module. It owns three guarantees:
 *
 *   1. BOUNDARY   — a workspace path can never resolve outside
 *                   its own directory (traversal, absolute paths,
 *                   symlinks are all caught).
 *   2. SECRECY    — the worker env never leaks into commands: the
 *                   terminal child env is rebuilt from scratch with
 *                   a minimal, secret-free variable set.
 *   3. LIFECYCLE  — workspaces are created per task and cleaned up
 *                   by the orchestrator when idle.
 *
 * Threat model: the LLM inside the worker is treated as untrusted.
 * It is given a shell and filesystem access INSIDE one directory
 * and must not be able to escape it or read backend secrets.
 */
const fs = require('fs')
const path = require('path')
const crypto = require('crypto')

const agentConfig = require('./config')

const BACKEND_ROOT = path.resolve(__dirname, '..', '..')
const WORKSPACES_ROOT = path.resolve(BACKEND_ROOT, agentConfig.workspaceRoot)

/* ── Path boundary ─────────────────────────────────────────── */

function isInside(parent, child) {
  const rel = path.relative(parent, child)
  return rel === '' || (!rel.startsWith('..') && !path.isAbsolute(rel))
}

/**
 * Resolve a task-relative path to an absolute path, enforcing the
 * workspace boundary. Throws coded errors on violation.
 *
 * Symlink defense: after lexical resolution we walk the EXISTING
 * ancestor chain and re-resolve it with realpath; any link that
 * jumps outside the workspace is rejected. For not-yet-existing
 * paths the deepest existing ancestor is the anchor.
 */
function resolveInsideWorkspace(workspaceRoot, relPath, { forWrite = false } = {}) {
  const root = fs.realpathSync(workspaceRoot) // the real root (workspace itself may sit behind a symlink)
  const raw = String(relPath ?? '')
  if (raw.includes('\0')) { const e = new Error('Invalid path'); e.code = 'SANDBOX_VIOLATION'; throw e }

  // Lexical resolution first — catches ../ and absolute escapes cheaply.
  const joined = path.resolve(root, raw === '' ? '.' : raw)
  if (!isInside(root, joined)) {
    const e = new Error(`Path escapes the workspace sandbox: ${raw}`)
    e.code = 'SANDBOX_VIOLATION'
    e.userSafe = true
    throw e
  }

  // Realpath defense: verify every existing ancestor stays inside.
  let anchor = joined
  const missing = []
  while (!fs.existsSync(anchor)) {
    missing.push(path.basename(anchor))
    const parent = path.dirname(anchor)
    if (isInside(root, parent) === false || parent === path.parse(parent).root) {
      const e = new Error(`Path escapes the workspace sandbox: ${raw}`)
      e.code = 'SANDBOX_VIOLATION'; e.userSafe = true; throw e
    }
    anchor = parent
  }
  const realAnchor = fs.realpathSync(anchor)
  if (!isInside(root, realAnchor)) {
    const e = new Error(`Path escapes the workspace sandbox: ${raw}`)
    e.code = 'SANDBOX_VIOLATION'; e.userSafe = true; throw e
  }

  const resolved = missing.length
    ? path.join(realAnchor, ...missing.reverse())
    : realAnchor
  if (!isInside(root, resolved)) {
    const e = new Error(`Path escapes the workspace sandbox: ${raw}`)
    e.code = 'SANDBOX_VIOLATION'; e.userSafe = true; throw e
  }
  return resolved
}

/* ── Workspace lifecycle ────────────────────────────────────── */

class Workspace {
  constructor(taskId) {
    if (!/^[A-Za-z0-9_-]{6,64}$/.test(String(taskId))) {
      // taskId comes from Mongo ObjectId or server-generated UUID — never user input.
      // This guard is defense-in-depth against injection into filesystem paths.
      const e = new Error('Invalid workspace id'); e.code = 'SANDBOX_VIOLATION'; throw e
    }
    this.taskId = String(taskId)
    this.root = path.join(WORKSPACES_ROOT, this.taskId)
  }

  /** Create (idempotently) and return the workspace root. */
  async ensure() {
    await fs.promises.mkdir(this.root, { recursive: true })
    // A few standard subdirs every workspace gets.
    for (const d of ['.tmp']) {
      await fs.promises.mkdir(path.join(this.root, d), { recursive: true }).catch(() => {})
    }
    return this.root
  }

  /** Resolve + validate a workspace-relative path. */
  resolve(relPath, opts) { return resolveInsideWorkspace(this.root, relPath, opts) }

  toRelative(absPath) {
    const root = fs.realpathSync(this.root)
    const rel = path.relative(root, absPath)
    return rel === '' ? '.' : rel.split(path.sep).join('/')
  }

  async exists(relPath) {
    try { await fs.promises.stat(this.resolve(relPath)); return true } catch { return false }
  }

  async remove() {
    // The workspace root itself is only ever removed through here.
    await fs.promises.rm(this.root, { recursive: true, force: true }).catch(() => {})
  }

  static get rootBase() { return WORKSPACES_ROOT }
}

/**
 * Build the environment for terminal commands (§12 secret protection).
 * The worker process itself holds GROQ_API_KEY to talk to the model,
 * but NOTHING from the worker env is inherited by tool commands:
 * the child env is rebuilt from scratch and contains zero secrets.
 */
function buildCommandEnv(workspaceRoot) {
  const path = require('path')
  return {
    PATH: '/usr/local/bin:/usr/bin:/bin:/usr/local/sbin:/usr/sbin:/sbin',
    HOME: workspaceRoot,
    TMPDIR: path.join(workspaceRoot, '.tmp'),
    LANG: 'C.UTF-8',
    LC_ALL: 'C.UTF-8',
    TERM: 'dumb',
    NO_COLOR: '1',
    /* Piped stdout is block-buffered in many runtimes — a dev server
       would sit on its "listening on :PORT" line until killed, so
       live preview detection would never see it. Force line-friendly
       behavior for the common ones (python, node, php, grep). */
    PYTHONUNBUFFERED: '1',
    NODE_NO_WARNINGS: '1',
    PHP_OUTPUT_HANDLER: 'user',
    /* Git isolation: discovery must NEVER walk above the workspace
       (a parent .git would silently make the agent operate on the
       host's repository — a real sandbox escape). */
    GIT_CEILING_DIRECTORIES: path.dirname(path.resolve(workspaceRoot)),
    GIT_CONFIG_NOSYSTEM: '1',
    GIT_TERMINAL_PROMPT: '0',
    // npm/pnpm behavior inside the sandbox
    npm_config_update_notifier: 'false',
    npm_config_fund: 'false',
    npm_config_audit: 'false',
    npm_config_loglevel: 'warn',
    CI: '1',
  }
}

/** Signed preview token — lets an <iframe> authenticate without headers. */
function signPreviewToken(secret, taskId, userId, ttlMs = agentConfig.preview.tokenTtlMs) {
  const exp = Date.now() + ttlMs
  const body = `${taskId}.${userId}.${exp}`
  const sig = crypto.createHmac('sha256', secret).update(body).digest('base64url')
  return `${body}.${sig}`
}

function verifyPreviewToken(secret, token) {
  if (!token || typeof token !== 'string') return null
  const parts = token.split('.')
  if (parts.length !== 4) return null
  const [taskId, userId, exp, sig] = parts
  const body = `${taskId}.${userId}.${exp}`
  const expected = crypto.createHmac('sha256', secret).update(body).digest('base64url')
  const a = Buffer.from(sig); const b = Buffer.from(expected)
  if (a.length !== b.length || !crypto.timingSafeEqual(a, b)) return null
  if (Number(exp) < Date.now()) return null
  return { taskId, userId, exp: Number(exp) }
}

module.exports = {
  Workspace,
  resolveInsideWorkspace,
  buildCommandEnv,
  isInside,
  signPreviewToken,
  verifyPreviewToken,
  WORKSPACES_ROOT,
}
