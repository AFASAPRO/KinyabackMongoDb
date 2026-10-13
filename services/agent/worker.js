/**
 * KinyaBot Agent V1 — Execution Worker (§7, §11, §18, §29)
 * ─────────────────────────────────────────────────────────────
 * A SEPARATE Node process, forked by workerBridge. It runs the
 * full agent loop against an isolated workspace:
 *
 *     UNDERSTAND → PLAN → SELECT TOOL → EXECUTE → OBSERVE →
 *     EVALUATE → CORRECT → VERIFY → COMPLETE
 *
 * Why a separate process (§11/§35): unrestricted command execution
 * never happens inside the production API process. The worker is
 * given a minimal env (model key only), talks to the bridge over
 * IPC, and is killable as a unit — which also makes it deployable
 * as a standalone sandbox service later without changing the
 * protocol.
 *
 * IPC protocol (message-based, transport-agnostic):
 *   bridge → worker : { type: 'run', task, limits }   start a task
 *                     { type: 'cancel', reason }      cooperative stop
 *                     { type: 'confirm', id, approved }
 *                     { type: 'shutdown' }
 *   worker → bridge : { type: 'event', event }        every real event
 *                     { type: 'confirmation_request', id, command, reason }
 *                     { type: 'heartbeat', at }
 *                     { type: 'done', ok, error, code, result, stats }
 *
 * NO FAKE DATA (§32): every event this process emits is caused by
 * a real operation — a real tool call, a real command, a real
 * provider response. Failures propagate as failures.
 */
/* ── Task-scoped state (declared BEFORE crash handlers so the
     handlers can never hit a temporal-dead-zone) ───────────────── */
let task = null
let limits = null
let workspace = null
let cancelled = false
let cancelReason = null
let finished = false
let abortController = new AbortController()
const backgroundProcs = new Set()          // live background children
const pendingConfirmations = new Map()     // id -> {resolve, timer}
const stats = { steps: 0, tool_calls: 0, commands_run: 0, files_changed: 0, tokens: 0, retries: 0, model: null }

process.on('unhandledRejection', (err) => {
  try {
    finish({ ok: false, error: err?.message || 'Unhandled worker error', code: err?.code || 'WORKER_CRASH' })
  } catch { process.exit(7) }
})
process.on('uncaughtException', (err) => {
  try {
    finish({ ok: false, error: err?.message || 'Unhandled worker exception', code: err?.code || 'WORKER_CRASH' })
  } catch { process.exit(7) }
})

const path = require('path')
const crypto = require('crypto')
const fs = require('fs')
const fsp = fs.promises

/* Tool registration happens on import.
   V1.1 (§11): the read-only Git tools (git_status/git_diff/git_log) were
   REMOVED from the Agent-facing registry — they are not required for the
   V1 execution experience and removing them shrinks the tool surface the
   model must call correctly (fewer malformed-tool-call failure modes).
   Git commands remain available through run_command with the same command
   safety classification — nothing about Git usage elsewhere in KinyaBot
   is affected.                                                              */
require('./tools/filesystem')
require('./tools/terminal')
require('./tools/project').registerAll()

const registry = require('./tools/registry')
const agentProviderModule = require('./agentProvider')
const contextManager = require('./contextManager')
const { parseToolCallArguments } = require('./toolCallRepair')
const { Workspace } = require('./sandbox')
const { runRealCommand } = require('./tools/terminal')
const { scanProject } = require('./tools/project')

function send(msg) { try { process.send(msg) } catch { /* channel closed — bridge is gone */ } }
function emit(type, data = {}) {
  if (type === 'file_changed') stats.files_changed += 1
  send({ type: 'event', event: { type, data } })
}
function heartbeatLoop() { const t = setInterval(() => send({ type: 'heartbeat', at: Date.now() }), 10_000); t.unref?.(); }

function checkCancelled() {
  if (cancelled) {
    const e = new Error(cancelReason || 'Task cancelled by the user')
    e.code = 'TASK_CANCELLED'; e.userSafe = true
    throw e
  }
}

/* ── Confirmation flow (§13) ─────────────────────────────────── */
function requireConfirmation({ command, reason }) {
  return new Promise((resolve) => {
    if (cancelled) return resolve(false)
    const id = `cf_${crypto.randomBytes(8).toString('hex')}`
    const timer = setTimeout(() => {
      if (pendingConfirmations.delete(id)) {
        emit('confirmation_resolved', { id, approved: false, auto: 'timeout' })
        resolve(false)
      }
    }, limits.confirmationTimeoutMs)
    pendingConfirmations.set(id, {
      resolve: (approved) => { clearTimeout(timer); resolve(approved) },
    })
    send({ type: 'confirmation_request', id, command, reason })
  })
}

/* ── Background / foreground real command execution (§10) ────── */
async function executeCommand({ command, cwd, env, timeoutMs, maxOutputBytes, background, id, onOutput }) {
  if (!background) {
    stats.commands_run += 1
    return runRealCommand({ command, cwd, env, timeoutMs, maxOutputBytes, onOutput, signal: abortController.signal })
  }

  /* Background (dev servers, §24): the process keeps running while
     the task continues — and OUTLIVES the worker on success so the
     user can inspect the live preview. Its lifetime is owned by the
     orchestrator (stop endpoint / failure paths / idle cleanup kill
     it by PID group), so it is deliberately NOT tied to this
     worker's abort signal or the task timeout.

     STDOUT/STDERR go to a LOG FILE, never to pipes: a pipe whose
     read-end dies with this worker would EPIPE-kill the server on
     its first log write after we exit. A file descriptor is dup'd
     into the child and stays valid — the server writes happily
     forever, and a tail loop streams the log to the Terminal tab
     for as long as this worker lives.                               */
  stats.commands_run += 1
  const startedAt = Date.now()
  const captureMs = Math.min(15_000, timeoutMs)

  const logDir = path.join(workspace.root, '.tmp')
  const logPath = path.join(logDir, `bg-${id || Date.now().toString(36)}.log`)
  await fsp.mkdir(logDir, { recursive: true }).catch(() => {})
  const logFd = fs.openSync(logPath, 'a')

  let tailOffset = 0
  const tailLog = async () => {
    try {
      const st = await fsp.stat(logPath).catch(() => null)
      if (st && st.size > tailOffset) {
        const fh = await fsp.open(logPath, 'r').catch(() => null)
        if (fh) {
          const len = Math.min(st.size - tailOffset, maxOutputBytes || 262144)
          const buf = Buffer.alloc(len)
          await fh.read(buf, 0, len, tailOffset)
          await fh.close().catch(() => {})
          tailOffset += len
          const text = buf.toString('utf8')
          if (text) onOutput?.({ stream: 'stdout', chunk: text })
        }
      }
    } catch {}
  }
  const tailTimer = setInterval(tailLog, 300)
  tailTimer.unref?.()

  runRealCommand({
    command,
    cwd, env,
    timeoutMs: Infinity,          // no timeout: orchestrator owns the lifetime
    logFd,                        // file-backed stdio — survives this worker
    onSpawn: (child) => {
      // The child dup'd the fd at spawn; our copy can close now.
      try { fs.closeSync(logFd) } catch {}
      backgroundProcs.add(child)
      child.on('close', () => { clearInterval(tailTimer); backgroundProcs.delete(child) })
      emit('background_process_started', { command, pid: child.pid, log: `.tmp/bg-${id || ''}.log` })
    },
  }).catch(() => {})

  // Do not await full lifetime; await only the capture window, then
  // read whatever the server has logged so far (port banners etc).
  await new Promise(r => setTimeout(r, captureMs))
  await tailLog()
  return {
    command,
    background: true,
    exitCode: 0,                 // still running — honest label below
    running: true,
    stdout: '',
    stderr: '',
    truncated: false,
    durationMs: Date.now() - startedAt,
    startedAt: new Date(startedAt).toISOString(),
    completedAt: new Date().toISOString(),
    logFile: `.tmp/bg-${id || ''}.log`,
    note: 'Process is running in the background — output keeps streaming to the Terminal tab.',
  }
}

/* Kill background trees (task end / cancel, §12 process cleanup). */
function killBackgroundProcs() {
  for (const c of backgroundProcs) {
    try { process.kill(-c.pid, 'SIGKILL') } catch { try { c.kill('SIGKILL') } catch {} }
  }
  backgroundProcs.clear()
}

/* ── ToolContext (what every tool receives) ──────────────────── */
function buildToolContext() {
  return {
    workspace,
    taskId: task.taskId,
    permissions: task.permissions,
    limits,
    emit,
    runCommand: executeCommand,
    requireConfirmation,
    signal: abortController.signal,
  }
}

/* ── The agent loop (§7) ─────────────────────────────────────── */
async function runTask(t, l) {
  task = t
  limits = l
  workspace = new Workspace(task.taskId)
  await workspace.ensure()

  heartbeatLoop()
  emit('task_started', { taskId: task.taskId, prompt: task.prompt })
  const startedAt = Date.now()

  const provider = agentProviderModule.getAgentProvider()

  /* 1 ─ UNDERSTAND: inspect what is already in the workspace. */
  let detection = null
  const existing = await registry.executeTool('list_files', { path: '.', depth: 2 }, buildToolContext()).catch(() => null)
  if (existing && existing.count > 0) {
    detection = await scanProject(buildToolContext()).catch(err => ({ error: `project detection failed: ${err.message}` }))
  }

  /* 2 ─ PLAN (§16): concise, high-level — never chain-of-thought. */
  emit('task_planning', {})
  const plan = await provider.plan({ task: { prompt: task.prompt }, detection })
  emit('plan_updated', { steps: plan.steps })
  checkCancelled()

  /* 3 ─ EXECUTION LOOP: select tool → execute → observe → evaluate. */
  const messages = [
    { role: 'system', content: agentProviderModule.AGENT_SYSTEM },
    { role: 'user', content: buildTaskMessage(task.prompt, detection, plan.steps) },
  ]

  let finalAnswer = null
  let repairCycle = 0

  while (!finalAnswer) {
    checkCancelled()
    enforceTaskTimeout(startedAt)

    const visible = contextManager.trimToBudget(messages, limits.contextCharBudget, 2)
    stats.steps += 1
    if (stats.steps > limits.maxSteps) {
      const e = new Error(`The task reached the maximum of ${limits.maxSteps} execution steps without completing.`)
      e.code = 'STEP_LIMIT'; e.userSafe = true
      throw e
    }

    emit('agent_step', { step: stats.steps, max: limits.maxSteps })
    const response = await provider.step({
      messages: visible,
      tools: registry.toModelTools(),
      task: { prompt: task.prompt },
      phase: 'execution',
    })
    stats.tokens += response.tokens || 0
    stats.model = response.model || stats.model
    checkCancelled()

    const { message } = response
    messages.push({ role: 'assistant', content: message.content || '', tool_calls: message.tool_calls?.length ? message.tool_calls : undefined })

    if (message.tool_calls?.length) {
      for (const call of message.tool_calls) {
        checkCancelled()
        const result = await executeToolCall(call)
        messages.push({ role: 'tool', tool_call_id: call.id, name: call.function.name, content: result })
      }
      continue
    }

    if ((message.content || '').trim()) {
      // Candidate final answer → verification phase decides.
      finalAnswer = message.content.trim()
    } else {
      // Degenerate empty response — nudge the model once, fail on repeat.
      messages.push({ role: 'user', content: 'Continue with the task using tools, or give your final answer.' })
      if (stats.steps >= limits.maxSteps - 1) {
        const e = new Error('The model stopped producing actions before the task completed.')
        e.code = 'EMPTY_RESPONSE'; e.userSafe = true
        throw e
      }
    }
  }

  /* 4 ─ VERIFY (§7): the agent must prove its own work. */
  let verificationOutcome = await verify(provider, messages, task, finalAnswer)

  /* 5 ─ CORRECT (§18): one bounded repair round when issues found. */
  while (verificationOutcome.issues && repairCycle < limits.maxRepairCycles) {
    repairCycle += 1
    emit('repair_started', { cycle: repairCycle, issues: verificationOutcome.summary })
    messages.push({ role: 'user', content: `Verification found issues that you MUST fix now:\n${verificationOutcome.summary}\n\nFix them with tools, then give your corrected final answer.` })
    finalAnswer = await repairRound(provider, messages)
    verificationOutcome = await verify(provider, messages, task, finalAnswer)
  }

  const verified = !verificationOutcome.issues
  emit('verification_completed', { verified, summary: verificationOutcome.summary })

  stats.duration_ms = Date.now() - startedAt
  return { result: finalAnswer, verified, verification: verificationOutcome.summary, stats: { ...stats } }
}

/* ── Tool call with retry + honest error returns (§18) ───────── */
async function executeToolCall(call) {
  const name = call.function?.name
  /* V1.1: arguments are normalized+repaired upstream (provider) but this
     is the last line of defense — a scripted or future provider may still
     hand us raw malformed JSON. Repair is conservative: it only closes
     what the model left open, never invents content.                    */
  const parsed = parseToolCallArguments(call.function?.arguments ?? '{}')
  if (!parsed.ok) {
    stats.retries += 1
    return JSON.stringify({
      error: 'TOOL_INVALID_ARGS',
      message: 'Arguments were not valid JSON. Call the tool again with a single complete JSON object as arguments.',
    })
  }
  const args = parsed.value

  emit('tool_started', { name, args })
  stats.tool_calls += 1

  let attempt = 0
  let lastErr = null
  while (attempt <= limits.maxToolRetries) {
    checkCancelled()
    try {
      const result = await registry.executeTool(name, args, buildToolContext())
      emit('tool_completed', { name, ok: true })
      return JSON.stringify(result).slice(0, 24_000)
    } catch (err) {
      lastErr = err
      // Network/auth/config errors are NOT retryable — fail the task honestly.
      const fatal = ['AI_AUTH', 'AI_RATE_LIMIT', 'AI_MODEL_UNAVAILABLE', 'GROQ_NOT_CONFIGURED', 'PROVIDER_MISCONFIGURED', 'TASK_CANCELLED']
      if (fatal.includes(err.code)) throw err

      const retryable = ['TOOL_EDIT_MISS', 'TOOL_TARGET_MISSING', 'TOOL_ALREADY_EXISTS', 'TOOL_DIR_NOT_EMPTY', 'SANDBOX_VIOLATION', 'COMMAND_BLOCKED', 'COMMAND_DECLINED']
      const transient = !retryable.includes(err.code)

      if (!transient || attempt === limits.maxToolRetries) break
      // The model gets the error immediately on non-transient failures so it
      // can choose a different approach; transient ones are retried with backoff.
      attempt += 1
      stats.retries += 1
      emit('tool_retry', { name, attempt, code: err.code, message: err.message })
      await new Promise(r => setTimeout(r, limits.retryBackoffMs * attempt))
    }
  }

  emit('tool_failed', { name, code: lastErr?.code || null, message: lastErr?.message })
  // Tool errors go BACK TO THE MODEL as tool results — that's how the
  // observe→correct part of the loop works. No fake success ever.
  return JSON.stringify({ error: lastErr?.code || 'TOOL_ERROR', message: lastErr?.message || 'Tool execution failed' })
}

/* ── Verification phase (§7 VERIFY) ──────────────────────────── */
async function verify(provider, messages, task, finalAnswer) {
  emit('verification_started', {})
  const vMessages = [
    { role: 'system', content: agentProviderModule.VERIFICATION_SYSTEM },
    { role: 'user', content: `Task: ${task.prompt}\n\nProposed final answer:\n${finalAnswer.slice(0, 3000)}\n\nThe workspace and tools are available. Verify the work really satisfies the task, then answer VERIFIED: or ISSUES:.` },
  ]
  let steps = 0
  while (steps < limits.maxVerificationSteps) {
    checkCancelled()
    steps += 1
    const response = await provider.step({ messages: vMessages, tools: registry.toModelTools(), task: { prompt: task.prompt }, phase: 'verification' })
    stats.tokens += response.tokens || 0
    const { message } = response
    vMessages.push({ role: 'assistant', content: message.content || '', tool_calls: message.tool_calls?.length ? message.tool_calls : undefined })

    if (message.tool_calls?.length) {
      for (const call of message.tool_calls) {
        checkCancelled()
        const result = await executeToolCall(call)
        vMessages.push({ role: 'tool', tool_call_id: call.id, name: call.function.name, content: result })
      }
      continue
    }
    const text = (message.content || '').trim()
    if (/^VERIFIED:/i.test(text)) return { issues: false, summary: text.replace(/^VERIFIED:\s*/i, '').slice(0, 500) }
    if (/^ISSUES:/i.test(text)) return { issues: true, summary: text.replace(/^ISSUES:\s*/i, '').slice(0, 800) }
    // Unparseable verification reply: ask once more, then treat as unverified.
    if (steps >= limits.maxVerificationSteps - 1) {
      return { issues: true, summary: 'The verifier could not produce a definitive result — reported as unverified, never as success.' }
    }
    vMessages.push({ role: 'user', content: 'Reply with EXACTLY one line starting with VERIFIED: or ISSUES:.' })
  }
  return { issues: true, summary: 'Verification step budget exhausted without a definitive result.' }
}

/* ── Repair round after failed verification (§18) ────────────── */
async function repairRound(provider, messages) {
  while (true) {
    checkCancelled()
    enforceTaskTimeout(Date.now())
    stats.steps += 1
    if (stats.steps > limits.maxSteps) {
      const e = new Error(`The task reached the maximum of ${limits.maxSteps} execution steps during repair.`)
      e.code = 'STEP_LIMIT'; e.userSafe = true
      throw e
    }
    const visible = contextManager.trimToBudget(messages, limits.contextCharBudget, 2)
    const response = await provider.step({ messages: visible, tools: registry.toModelTools(), task: { prompt: task.prompt }, phase: 'repair' })
    stats.tokens += response.tokens || 0
    const { message } = response
    messages.push({ role: 'assistant', content: message.content || '', tool_calls: message.tool_calls?.length ? message.tool_calls : undefined })
    if (message.tool_calls?.length) {
      for (const call of message.tool_calls) {
        checkCancelled()
        const result = await executeToolCall(call)
        messages.push({ role: 'tool', tool_call_id: call.id, name: call.function.name, content: result })
      }
      continue
    }
    if ((message.content || '').trim()) return message.content.trim()
    messages.push({ role: 'user', content: 'Continue fixing the issues with tools, then give the corrected final answer.' })
  }
}

function enforceTaskTimeout(startedAt) {
  if (Date.now() - startedAt > limits.taskTimeoutMs) {
    const e = new Error(`The task exceeded the maximum duration of ${Math.round(limits.taskTimeoutMs / 60000)} minutes.`)
    e.code = 'TASK_TIMEOUT'; e.userSafe = true
    throw e
  }
}

function buildTaskMessage(prompt, detection, planSteps) {
  let msg = `TASK: ${prompt}\n\nExecution plan:\n${planSteps.map((s, i) => `${i + 1}. ${s}`).join('\n')}`
  if (detection) msg += `\n\nExisting project detected in the workspace:\n${JSON.stringify(detection).slice(0, 2000)}`
  msg += `\n\nBegin executing the plan now using tools.`
  return msg
}

/* ── Lifecycle ───────────────────────────────────────────────── */
function finish(payload) {
  if (finished) return
  finished = true
  try { abortController.abort(new Error('task finished')) } catch {}
  /* §24: on SUCCESS, background dev servers are LEFT RUNNING (they
     are detached process groups and survive this worker) so the user
     can inspect the live preview after completion. Their PIDs are
     reported to the bridge, which takes ownership of cleanup. On
     failure/cancel they are killed here — no leaking on errors. */
  const keepBackground = payload.ok === true
  const backgroundPids = keepBackground ? [...backgroundProcs].map(c => c.pid).filter(Boolean) : []
  if (!keepBackground) killBackgroundProcs()
  send({ type: 'done', ...payload, backgroundPids, stats: payload.stats || { ...stats } })
  // Give the IPC channel a moment to flush before exiting.
  setTimeout(() => process.exit(0), 250)
  // If the bridge disconnects first, exit immediately.
  process.on('disconnect', () => process.exit(0))
}

process.on('message', (msg) => {
  if (!msg || typeof msg !== 'object') return
  if (msg.type === 'run') {
    runTask(msg.task, msg.limits)
      .then(({ result, verified, verification, stats: s }) => finish({ ok: true, result, verified, verification, stats: s }))
      .catch(err => finish({
        ok: false,
        error: err?.userSafe ? err.message : (err?.message || 'The agent task failed.'),
        code: err?.code || 'AGENT_ERROR',
        userSafe: !!err?.userSafe,
        stats: { ...stats },
      }))
  }
  if (msg.type === 'cancel') {
    cancelled = true
    cancelReason = msg.reason || 'Task cancelled by the user'
    try { abortController.abort(new Error(cancelReason)) } catch {}
    const pending = [...pendingConfirmations.values()]
    pendingConfirmations.clear()
    for (const p of pending) p.resolve(false)
  }
  if (msg.type === 'confirm') {
    const p = pendingConfirmations.get(msg.id)
    if (p) { pendingConfirmations.delete(msg.id); p.resolve(msg.approved === true) }
  }
  if (msg.type === 'shutdown') {
    cancelled = true
    process.exit(0)
  }
})
