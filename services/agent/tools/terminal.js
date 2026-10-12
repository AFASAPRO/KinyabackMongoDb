/**
 * KinyaBot Agent V1 — Real Terminal Tool (§10, §12, §13)
 * ─────────────────────────────────────────────────────────────
 * run_command — the ONLY terminal primitive. It is REAL:
 *
 *   • spawns `bash -c <command>` with cwd = the task workspace
 *   • env rebuilt from scratch by sandbox.buildCommandEnv() —
 *     never inherits the worker/API env, so no secret can leak
 *   • streams stdout/stderr chunks as events while running
 *   • captures exit code, duration and start/finish timestamps
 *   • enforces per-command timeout with process-GROUP kill so
 *     children (npm run dev → vite…) actually die
 *   • classifies risk BEFORE running (commandSafety) — high risk
 *     requires explicit user confirmation, blocked commands never
 *     run, and every invocation is capped + output-bounded
 *
 * There is NO fake output anywhere in this file.
 */
const { spawn } = require('child_process')
const path = require('path')

const { registerTool } = require('./registry')
const { classifyCommand } = require('../commandSafety')
const { buildCommandEnv } = require('../sandbox')

/* Port patterns used for live preview detection (§24). Only ports
   that actually LISTEN are ever reported (verified by the bridge). */
const PORT_PATTERNS = [
  /(?:https?:\/\/|http:\/\/)?(?:localhost|127\.0\.0\.1|0\.0\.0\.0|\[::1?\])[:\s](\d{2,5})/gi,
  /listening\s+(?:on\s+)?(?:port\s+)?(\d{2,5})/gi,
  /(?:port|PORT)\s*[=:]\s*(\d{2,5})\b/g,
  /ready\s+(?:on|at)\s+(?:https?:\/\/)?(?:localhost|127\.0\.0\.1)?[:]?(\d{2,5})/gi,
]

function extractPorts(text) {
  const found = new Set()
  for (const re of PORT_PATTERNS) {
    re.lastIndex = 0
    let m
    while ((m = re.exec(text)) !== null) {
      const p = Number(m[1])
      if (p >= 1024 && p <= 65535) found.add(p)
    }
  }
  return [...found]
}

/**
 * Spawn a real command. Returns a promise resolving to the honest
 * result object. Used by the tool handler AND by the worker for
 * internal verification runs.
 *
 * @param {object} p
 *   command, cwd, env, timeoutMs, maxOutputBytes,
 *   onOutput({ stream, chunk })   streaming callback (optional)
 *   signal                        AbortSignal (optional)
 *   logFd                         Number — file descriptor to redirect
 *                                 BOTH stdout and stderr into instead
 *                                 of pipes (§24 background servers:
 *                                 a pipe to a dead worker EPIPE-kills
 *                                 the server on its first log write;
 *                                 a file descriptor never does).
 */
function runRealCommand({ command, cwd, env, timeoutMs, maxOutputBytes, onOutput, signal, onSpawn, logFd }) {
  return new Promise((resolve) => {
    const startedAt = Date.now()
    const usingLogFile = Number.isInteger(logFd)
    let stdout = ''
    let stderr = ''
    let truncated = false
    let killed = false
    let settled = false

    // detached:true → own process group → we can kill the whole tree
    const child = spawn('bash', ['-c', command], {
      cwd,
      env,
      detached: process.platform !== 'win32',
      stdio: ['ignore', usingLogFile ? logFd : 'pipe', usingLogFile ? logFd : 'pipe'],
    })
    onSpawn?.(child)

    const cap = maxOutputBytes || 100 * 1024
    const append = (stream, text) => {
      if (!text) return
      const slot = stream === 'stderr' ? 'stderr' : 'stdout'
      if (stdout.length + stderr.length >= cap) { truncated = true; return }
      if (stdout.length + stderr.length + text.length > cap) {
        text = text.slice(0, cap - (stdout.length + stderr.length))
        truncated = true
      }
      if (slot === 'stdout') stdout += text; else stderr += text
      onOutput?.({ stream: slot, chunk: text })
    }

    if (!usingLogFile) {
      child.stdout.setEncoding('utf8')
      child.stderr.setEncoding('utf8')
      child.stdout.on('data', d => { stdoutBuf += d })
      child.stderr.on('data', d => { stderrBuf += d })
    }
    let stdoutBuf = '', stderrBuf = ''
    const FLUSH_MS = 60
    const flush = (slot) => {
      if (slot === 'stdout' && stdoutBuf) { append('stdout', stdoutBuf); stdoutBuf = '' }
      if (slot === 'stderr' && stderrBuf) { append('stderr', stderrBuf); stderrBuf = '' }
    }
    const t1 = usingLogFile ? null : setInterval(() => { flush('stdout'); flush('stderr') }, FLUSH_MS)

    const killTree = (reason) => {
      if (killed) return
      killed = true
      try {
        if (process.platform === 'win32') spawn('taskkill', ['/pid', String(child.pid), '/T', '/F'])
        else process.kill(-child.pid, 'SIGKILL')
      } catch {
        try { child.kill('SIGKILL') } catch {}
      }
    }

    /* Infinity = no timeout (kept-alive background preview servers,
       §24 — the orchestrator owns their lifetime by PID group).
       NOTE: setTimeout(Infinity) fires after ~1ms in Node, so an
       unbounded timeout must skip the timer entirely. */
    const timeoutMsNum = Number.isFinite(timeoutMs) ? (timeoutMs || 120000) : null
    const timeout = timeoutMsNum
      ? setTimeout(() => { killTree('timeout') }, timeoutMsNum)
      : null
    const onAbort = () => killTree('aborted')
    signal?.addEventListener('abort', onAbort, { once: true })

    const finish = (exitCode, signalName) => {
      if (settled) return
      settled = true
      clearTimeout(timeout)
      if (t1) clearInterval(t1)
      flush('stdout'); flush('stderr')
      signal?.removeEventListener?.('abort', onAbort)
      resolve({
        command,
        exitCode: exitCode === null ? (killed ? 124 : 130) : exitCode,
        signal: signalName || null,
        stdout: stdout.slice(0, cap),
        stderr: stderr.slice(0, cap),
        truncated,
        durationMs: Date.now() - startedAt,
        startedAt: new Date(startedAt).toISOString(),
        completedAt: new Date().toISOString(),
        timedOut: killed && exitCode === null,
        logFile: usingLogFile || null,
      })
    }

    child.on('error', (err) => {
      append('stderr', `spawn error: ${err.message}\n`)
      finish(-1, null)
    })
    child.on('close', (code, sig) => finish(code, sig))
  })
}

/* ── The run_command tool ───────────────────────────────────── */
registerTool({
  name: 'run_command',
  description: 'Run a shell command inside the task workspace and receive the real stdout, stderr, exit code and duration. Low-risk commands (ls, cat, npm test, npm run build, npm run dev…) run immediately. Dangerous commands (rm -rf, sudo, git push, deploy) require the user to approve them first. Working directory is always the workspace root unless you pass cwd. Commands must reference files relative to the workspace.',
  parameters: {
    type: 'object',
    properties: {
      command: { type: 'string', description: 'The shell command to execute' },
      timeoutMs: { type: 'integer', description: 'Optional timeout in milliseconds (capped by the sandbox)' },
      cwd: { type: 'string', description: 'Subdirectory to run in (relative to workspace root). Default "."' },
      background: { type: 'boolean', description: 'Set true for long-running processes like dev servers. Returns after startup output is captured and keeps the process running.' },
    },
    required: ['command'],
  },
  permission: 'EXECUTE',
  risk: 'medium', // real classification happens per-command below
  category: 'terminal',
  handler: async ({ args, ctx }) => {
    const command = String(args.command || '').trim()
    const classification = classifyCommand(command, { workspaceRoot: ctx.workspace.root })
    if (classification.risk === 'blocked') {
      const e = new Error(`Command blocked by the safety policy: ${classification.reason}`)
      e.code = 'COMMAND_BLOCKED'; e.userSafe = true
      ctx.emit('terminal_blocked', { command, reason: classification.reason })
      throw e
    }
    if (classification.risk === 'high') {
      // §13 — never silently run dangerous operations.
      const decision = await ctx.requireConfirmation({
        command,
        reason: classification.reason,
        segments: classification.segments,
      })
      if (!decision) {
        const e = new Error('The user declined this command. Ask what to do instead or proceed with a safer approach.')
        e.code = 'COMMAND_DECLINED'; e.userSafe = true
        throw e
      }
    }

    const cwdRel = args.cwd && args.cwd !== '.' ? args.cwd : '.'
    const cwdAbs = ctx.workspace.resolve(cwdRel)
    const timeoutMs = Math.min(ctx.limits.commandTimeoutMs, Math.max(3000, Number(args.timeoutMs) || ctx.limits.commandTimeoutMs))
    const cmdId = `cmd_${Date.now().toString(36)}_${Math.random().toString(36).slice(2, 7)}`

    ctx.emit('terminal_started', {
      id: cmdId, command, cwd: cwdRel, risk: classification.risk,
      reason: classification.reason, startedAt: new Date().toISOString(),
    })

    let outputAccum = ''
    const result = await ctx.runCommand({
      command,
      cwd: cwdAbs,
      env: buildCommandEnv(ctx.workspace.root),
      timeoutMs,
      maxOutputBytes: ctx.limits.commandMaxOutputBytes,
      background: args.background === true,
      id: cmdId,
      onOutput: ({ stream, chunk }) => {
        outputAccum += chunk
        ctx.emit('terminal_output', { id: cmdId, stream, chunk })
      },
    })

    ctx.emit('terminal_completed', {
      id: cmdId, command,
      exitCode: result.exitCode,
      durationMs: result.durationMs,
      truncated: result.truncated,
      timedOut: result.timedOut,
      completedAt: result.completedAt,
    })

    // Live preview detection (§24) — ports are verified as LISTENING
    // by the bridge before they are ever surfaced as "ready".
    const ports = extractPorts(outputAccum)
    if (ports.length) ctx.emit('ports_detected', { id: cmdId, ports })

    return {
      command,
      exitCode: result.exitCode,
      stdout: result.stdout,
      stderr: result.stderr,
      truncated: result.truncated,
      timedOut: result.timedOut,
      durationMs: result.durationMs,
      startedAt: result.startedAt,
      completedAt: result.completedAt,
      ports,
    }
  },
})

module.exports = { runRealCommand, extractPorts }
