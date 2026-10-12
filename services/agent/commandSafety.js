/**
 * KinyaBot Agent V1 — Command Safety Classification (§13)
 * ─────────────────────────────────────────────────────────────
 * Every terminal command the Agent wants to run is classified
 * BEFORE execution:
 *
 *   low    — read-only inspection + build/test/dev-server commands.
 *            Executes immediately.
 *   medium — package installs, git mutations, network fetches.
 *            Executes, but is always surfaced in the UI and logs.
 *   high   — destructive filesystem ops, sudo, deploys, git push,
 *            credential access, piped remote scripts.
 *            REQUIRES explicit user confirmation (§13) — the agent
 *            can never silently perform these.
 *   blocked— can never run at all: commands that touch paths outside
 *            the workspace, read backend env/secrets, or would shut
 *            the host down.
 *
 * Classification is max-risk across every segment of the pipeline
 * (&&, ||, ;, |) so `echo hi && rm -rf /` is as dangerous as the
 * rm itself.
 */

/* shell-like word splitting respecting quotes — enough for risk
   classification (the shell itself remains the parser of truth). */
function splitWords(cmd) {
  const words = []
  let cur = ''
  let quote = null
  for (let i = 0; i < cmd.length; i++) {
    const c = cmd[i]
    if (quote) {
      if (c === quote && cmd[i - 1] !== '\\') quote = null
      else cur += c
      continue
    }
    if (c === '"' || c === "'") { quote = c; continue }
    if (c === '\\' && i + 1 < cmd.length) { cur += cmd[i + 1]; i++; continue }
    if (/\s/.test(c)) { if (cur) { words.push(cur); cur = '' } continue }
    cur += c
  }
  if (cur) words.push(cur)
  return words
}

/* Split a command line into its pipeline/sequence segments.
   NOTE: single '&' is NOT a separator — it appears inside `2>&1`
   redirections and background operators; only `&&` and `;` split. */
function splitSegments(cmd) {
  // Normalise line continuations first
  const line = String(cmd || '').replace(/\\\n/g, ' ')
  const segments = []
  let cur = ''
  let quote = null
  for (let i = 0; i < line.length; i++) {
    const c = line[i]
    if (quote) {
      if (c === quote && line[i - 1] !== '\\') quote = null
      cur += c
      continue
    }
    if (c === '"' || c === "'") { quote = c; cur += c; continue }
    if (c === ';') {
      if (cur.trim()) segments.push(cur.trim())
      cur = ''
      continue
    }
    if (c === '&' && line[i + 1] === '&') {
      if (cur.trim()) segments.push(cur.trim())
      cur = ''; i++; continue
    }
    if (c === '|') {
      if (line[i + 1] === '|') { // || — treat like ;
        if (cur.trim()) segments.push(cur.trim())
        cur = ''; i++; continue
      }
      if (cur.trim()) segments.push(cur.trim())
      cur = ''
      continue
    }
    cur += c
  }
  if (cur.trim()) segments.push(cur.trim())
  return segments
}

/* ── Pattern tables ─────────────────────────────────────────── */

const HIGH_RISK_PATTERNS = [
  { re: /(^|\s)rm\s+(-[a-zA-Z]*r[a-zA-Z]*f|-[a-zA-Z]*f[a-zA-Z]*r|-rf|--recursive)/, why: 'Recursive forced deletion' },
  { re: /(^|\s)sudo\b/, why: 'Privilege escalation' },
  { re: /(^|\s)(shutdown|reboot|halt|poweroff|init\s+[06])\b/, why: 'Host power control' },
  { re: /(^|\s)(mkfs(\.\w+)?|fsck|fdisk|parted)\b/, why: 'Destructive disk operation' },
  { re: /(^|\s)dd\b[^|;&]*(\bif=|\bof=)/, why: 'Raw disk/device copy' },
  /* Nested shells hide payloads inside quotes — `bash -c "rm -rf src"`
     must never slip through as medium just because rm is quoted. */
  { re: /(^|\s)((ba|z|da|k)?sh|eval)\b[^|;&]*\b(rm|dd|mkfs|shutdown|reboot|chmod|chown|kill|sudo|git\s+push)\b/, why: 'Shell wrapper around a destructive operation' },
  { re: /\b(curl|wget)\b[^|;&]*\|\s*(sudo\s+)?(ba)?sh\b/, why: 'Piping remote content into a shell' },
  { re: /(^|\s)(git\s+push|git\s+remote\s+add)\b/, why: 'git push / remote mutation requires confirmation' },
  { re: /(^|\s)(deploy|kctl|kubectl|helm\s+(install|upgrade|uninstall)|vercel\s+--prod|netlify\s+deploy|surge)\b/, why: 'Deployment command' },
  { re: /(^|\s)docker\s+(rm|rmi|system\s+prune|stop|kill)\b/, why: 'Docker mutation' },
  { re: /(^|\s)chmod\s+(-R\s+)?777\b/, why: 'World-writable permission change' },
  { re: /(^|\s)(kill|killall|pkill)\b.*-9?\s*$/, why: 'Process kill' },
  { re: /(^|\s)truncate\b|(^|\s)shred\b/, why: 'Destructive file operation' },
  { re: />\s*\/dev\/(sd|nvme|hd)/, why: 'Writing directly to a device' },
  { re: /(^|\s)(history\s+-c|unset\s+HISTFILE)\b/, why: 'Audit trail erasure' },
  { re: /(^|\s)(printenv|env)\b(?![^|;&]*\|\s*(grep|head|tail|wc))/, why: 'Environment inspection' },
  { re: /(^|\s)(whoami|id)\b/, why: 'Identity probing' },
]

const BLOCKED_PATTERNS = [
  { re: /(^|\s)cd\s+\/etc\b/, why: 'Host system directory access is outside the workspace' },
  { re: /(^|\s)(cat|less|more|head|tail|nl)\s+~?\/*(\.env|\.env\.\w+)$/, why: 'Backend configuration files are outside the sandbox' },
  { re: /(^|\s)(cat|less|more|head|tail|nl)\s+[^|;&]*\/\.env(\.\w+)?\s*$/, why: 'Reading .env files outside the workspace is not permitted' },
  { re: /\/proc\/(self\/)?environ/, why: 'Process environment scraping is not permitted' },
  { re: /(^|\s)(shutdown|reboot|halt)\b/, why: 'Cannot run inside the sandbox' },
  { re: /(^|\s)sudo\b/, why: 'No privilege escalation inside the sandbox' },
  { re: /(^|\s)rm\s+(-[a-zA-Z]*r[a-zA-Z]*f|-[a-zA-Z]*f[a-zA-Z]*r|-rf)\s+\/(\s|$)/, why: 'Recursive deletion of a root-level path' },
  { re: /(^|\s)(nc|ncat|netcat|socat)\b/, why: 'Raw network socket tools are not permitted in V1' },
  { re: /(^|\s)(ssh|scp|sftp|telnet)\b/, why: 'Remote access tools are not permitted in V1' },
  { re: /(^|\s)(crontab|systemctl|service)\b/, why: 'Host service management is not permitted' },
]

/* Absolute-path tokens that are benign and appear in legitimate commands. */
const ABSOLUTE_PATH_ALLOWLIST = [
  '/dev/null', '/dev/stdin', '/dev/stdout', '/dev/stderr', '/dev/tty',
  '/usr/bin/env', '/tmp', '/bin/bash', '/bin/sh', '/bin/true', '/bin/false',
]

/**
 * Absolute paths in command text that do not point INSIDE the task
 * workspace are blocked (§12 filesystem boundary for the terminal).
 * `workspaceRoot` is passed by the terminal tool at runtime.
 */
function checkAbsolutePaths(segment, workspaceRoot) {
  if (!workspaceRoot) return null
  const root = String(workspaceRoot)
  // find /path-like tokens
  const tokens = segment.match(/(?:^|[\s"'=;(])(\/[A-Za-z0-9._/-]+)/g) || []
  for (const raw of tokens) {
    const p = raw.replace(/^[\s"'=;(]+/, '')
    if (!p || !p.startsWith('/')) continue
    if (ABSOLUTE_PATH_ALLOWLIST.some(a => p === a || p.startsWith(a + '/'))) continue
    if (p.startsWith(root + '/') || p === root) continue
    return { risk: 'blocked', reason: `Absolute path outside the workspace is not permitted: ${p}` }
  }
  return null
}

/* Full-line patterns that only make sense BEFORE segment splitting
   (pipe-to-shell payloads span segments). */
const FULL_LINE_PATTERNS = [
  { re: /\b(curl|wget)\b[^\n]*\|\s*(sudo\s+)?((ba|z|da|k)?sh|bash)\b/i, why: 'Piping remote content into a shell', risk: 'blocked' },
  { re: /\b(curl|wget)\b[^\n]*;\s*(sudo\s+)?((ba|z|da|k)?sh)\b/i, why: 'Fetching and executing remote content', risk: 'blocked' },
  { re: /\$\((.|\n)*\b(rm\s+-[a-z]*r|mkfs|dd\s+if=)/, why: 'Command substitution hides a destructive operation', risk: 'high' },
]

const MEDIUM_RISK_PATTERNS = [
  { re: /(^|\s)(npm|pnpm|yarn|bun)\s+(i|install|uninstall|add|remove|rm|update|upgrade|ci|create|init)\b/, why: 'Package modification' },
  { re: /(^|\s)npx\s+(?!--yes\s+-p\s+)?(create|install)\b/, why: 'Package fetching' },
  { re: /(^|\s)(pip3?|pipx)\s+install\b/, why: 'Python package installation' },
  { re: /(^|\s)(curl|wget)\b/, why: 'Network fetch' },
  { re: /(^|\s)git\s+(add|commit|checkout|switch|reset|revert|merge|rebase|stash|clone|fetch|pull)\b/, why: 'Git mutation' },
  { re: /(^|\s)(npm|pnpm|yarn)\s+(link|publish|owner)\b/, why: 'Registry mutation' },
  { re: /(^|\s)(apt|apt-get|brew)\s+(install|remove|purge)\b/, why: 'System package mutation' },
]

const LOW_RISK_FIRST_WORDS = new Set([
  'ls', 'pwd', 'cat', 'find', 'grep', 'rg', 'head', 'tail', 'wc', 'echo', 'printf',
  'which', 'whoami', 'node', 'npm', 'npx', 'pnpm', 'yarn', 'bun', 'git', 'python',
  'python3', 'pip', 'pip3', 'mkdir', 'touch', 'cp', 'mv', 'diff', 'sort', 'uniq',
  'sed', 'awk', 'tr', 'cut', 'stat', 'file', 'du', 'df', 'tree', 'true', 'false',
  'test', 'expr', 'basename', 'dirname', 'realpath', 'readlink', 'md5sum', 'sha256sum',
  'tar', 'unzip', 'zip', 'gzip', 'gunzip', 'sleep', 'date', 'env', 'printenv', 'tsc',
  'eslint', 'prettier', 'jest', 'vitest', 'mocha', 'pytest', 'vite', 'tsc', 'exit', 'cd',
])

/* Absolute paths that refer outside the workspace are blocked at
   classification time already (cwd-relative work is the norm).   */
function classifySegment(segment) {
  const words = splitWords(segment)
  const first = (words[0] || '').split('/').pop()

  for (const { re, why } of BLOCKED_PATTERNS) {
    if (re.test(segment)) return { risk: 'blocked', reason: why }
  }
  for (const { re, why } of HIGH_RISK_PATTERNS) {
    if (re.test(segment)) return { risk: 'high', reason: why }
  }
  for (const { re, why } of MEDIUM_RISK_PATTERNS) {
    if (re.test(segment)) return { risk: 'medium', reason: why }
  }
  if (first && LOW_RISK_FIRST_WORDS.has(first)) return { risk: 'low', reason: null }
  // Unknown binary — treat as medium so it is at least always visible.
  return { risk: 'medium', reason: `Unrecognized command: ${first || segment.slice(0, 30)}` }
}

/**
 * Classify a full command line (all segments) with workspace awareness.
 * @param {string} command
 * @param {object} opts { workspaceRoot } — enables the absolute-path
 *        boundary check (§12) for the terminal tool.
 * @returns {{ risk: 'low'|'medium'|'high'|'blocked', reason: string|null, segments: number }}
 */
function classifyCommand(command, opts = {}) {
  const cmd = String(command || '').trim()
  if (!cmd) return { risk: 'blocked', reason: 'Empty command', segments: 0 }
  if (cmd.length > 8000) return { risk: 'blocked', reason: 'Command too long', segments: 0 }

  // Full-line checks first: cross-segment payloads (curl|sh, $(rm …)).
  for (const { re, why, risk } of FULL_LINE_PATTERNS) {
    if (re.test(cmd)) return { risk, reason: why, segments: 1 }
  }

  const segments = splitSegments(cmd)
  const order = { low: 0, medium: 1, high: 2, blocked: 3 }
  let worst = { risk: 'low', reason: null }
  for (const seg of segments) {
    // Absolute-path boundary check first (hard block).
    const absHit = opts.workspaceRoot ? checkAbsolutePaths(seg, opts.workspaceRoot) : null
    const c = absHit || classifySegment(seg)
    if (order[c.risk] > order[worst.risk]) worst = c
    if (worst.risk === 'blocked') break
  }
  return { ...worst, segments: segments.length }
}

module.exports = { classifyCommand, classifySegment, splitSegments, splitWords, checkAbsolutePaths }
