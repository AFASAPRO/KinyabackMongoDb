/**
 * KinyaBot Agent V1 — Orchestrator (§7, §14, §17, §18, §29, §30)
 * ─────────────────────────────────────────────────────────────
 * Owns the lifecycle of every Agent task INSIDE the API process:
 *
 *   • enforces the global concurrency cap (§29) with a real queue
 *   • starts Execution Workers through workerBridge (never runs
 *     tools itself — §11)
 *   • relays worker events → MongoDB (AgentEvent) + Socket.IO
 *   • handles confirmation requests / cancel / pause-resume
 *   • watchdogs stuck workers (§18) and marks crash recovery
 *   • mirrors the final result into the linked conversation (§26)
 *   • cleans idle workspaces (§12 process + disk hygiene)
 *
 * Single point of truth: `running` map is authoritative for live
 * tasks; MongoDB is authoritative for persisted state. On boot,
 * tasks stuck in running/planning/waiting states (from a crash)
 * are honestly marked failed with a recovery note (§30).
 */
const mongoose = require('mongoose')
const crypto = require('crypto')
const pathMod = require('path')

const agentConfig = require('./config')
const { AgentTask, AgentEvent, Chat, Message, SecurityEvent } = require('../../models')
const { recordEvent } = require('./events')
const bridge = require('./workerBridge')
const { Workspace } = require('./sandbox')
const staticPreview = require('./staticPreview')
const { notifyUser, notifyAdmins } = require('../notify')

/* Kill a detached background process group (kept-alive preview
   servers, §24). Killing -PID targets the whole group — the bash
   wrapper AND the server it spawned. PID reuse is a theoretical
   concern; the idle-cleanup window (hours) makes it negligible. */
function killPidGroups(pids) {
  for (const pid of (pids || [])) {
    try { process.kill(-pid, 'SIGKILL') } catch { try { process.kill(pid, 'SIGKILL') } catch {} }
  }
}

/* PIDs of background processes this task started — from the done
   payload, falling back to persisted background_process_started
   events (covers the hard-kill path where no done message arrives). */
async function backgroundPidsFor(taskId) {
  const doc = await AgentTask.findById(taskId, { 'preview.pids': 1 }).lean().catch(() => null)
  if (doc?.preview?.pids?.length) return doc.preview.pids
  const evts = await AgentEvent.find({ task_id: taskId, type: 'task.terminal.background_started' }, { data: 1 }).limit(10).lean().catch(() => [])
  return evts.map(e => e.data?.pid).filter(Number.isInteger)
}

const running = new Map()      // taskId -> { handle, task, stopWatchdog, limits, confirmations:Map }
const queue = []               // taskId[] waiting for a free slot
let ioRef = null

/* ── Serialized per-task state mutation ──────────────────────
   IPC messages arrive in order, but every handler is async and
   unawaited — without serialization their DB writes interleave and
   a stale patch (e.g. task_planning → 'planning') can land AFTER
   a newer one (confirmation → 'waiting_for_confirmation') and
   overwrite it. One promise chain per task guarantees DB writes
   happen in the exact order the worker produced them.        */
const taskChains = new Map()   // taskId -> Promise (tail of the chain)

function enqueueTaskMutation(taskId, fn) {
  const id = String(taskId)
  const prev = taskChains.get(id) || Promise.resolve()
  const next = prev
    .catch(() => {})   // a failed link never breaks the chain
    .then(fn)
    .catch(err => console.error(`[Agent] serialized mutation failed (${id}):`, err.message))
  taskChains.set(id, next)
  return next
}

function dropTaskChain(taskId) { taskChains.delete(String(taskId)) }

function attachAgentIo(io) { ioRef = io }

function getIo() { return ioRef }

function runningCount() { return running.size }

/* ── Persistence helpers ────────────────────────────────────── */
async function patchTask(taskId, patch) {
  try { return await AgentTask.findByIdAndUpdate(taskId, { $set: patch }, { new: true }) } catch { return null }
}

async function emitAndPersist(task, type, data) {
  return recordEvent({ taskId: task._id.toString(), userId: task.user_id.toString(), type, data }, ioRef)
}

/* ── Start / queue a task ───────────────────────────────────── */
function startOrQueueTask(taskDoc) {
  const task = {
    taskId: taskDoc._id.toString(),
    prompt: taskDoc.prompt,
    permissions: taskDoc.permissions || agentConfig.defaultPermissions,
    /* V1.2: server-resolved facts the worker needs — the client never
       supplies these (§10 entitlements, §8 reference images, §9 upload). */
    entitlements: taskDoc.entitlements || { webSearch: false, webSearchEnabled: true },
    referenceImages: (taskDoc.reference_images || []).map(r => ({
      path: pathMod.resolve(process.cwd(), agentConfig.uploads?.rootDir || 'agent-uploads', r.storage_path),
      mime: r.mime_type, name: r.original_name,
    })),
    sourceUpload: taskDoc.source_upload && taskDoc.source_upload.upload_id ? {
      name: taskDoc.source_upload.name,
      files: taskDoc.source_upload.files,
      bytes: taskDoc.source_upload.bytes,
      rootDir: taskDoc.source_upload.root_dir,
      skippedSecrets: (taskDoc.source_upload.skipped?.secrets || []).length,
    } : null,
  }
  if (running.size >= agentConfig.orchestration.maxConcurrentTasks) {
    queue.push(task.taskId)
    return 'queued'
  }
  launchWorker(taskDoc, task)
  return 'started'
}

function launchWorker(taskDoc, task) {
  /* The worker needs BOTH the sandbox limits and the loop bounds —
     flattened into one serializable object for the IPC message. */
  const limits = { ...agentConfig.limits, ...agentConfig.loop }

  const confirmations = new Map() // id -> { command, reason, requestedAt }
  const taskId = task.taskId

  const handle = bridge.startWorker({
    task,
    limits,

    onEvent: (evt) => {
      // Route events THROUGH THE SERIALIZED CHAIN: task state patches
      // are applied strictly in worker-event order. Events arriving
      // after the task left the running map (finalize raced IPC) are
      // dropped — the terminal state is authoritative.
      if (!running.has(taskId)) return
      enqueueTaskMutation(taskId, () => routeEvent(taskDoc, evt))
    },

    onConfirmation: ({ id, command, reason }) => {
      enqueueTaskMutation(taskId, async () => {
        confirmations.set(id, { command, reason, requestedAt: Date.now() })
        await patchTask(taskId, { status: 'waiting_for_confirmation' })
        await emitAndPersist(taskDoc, 'confirmation_requested', { id, command, reason })
        /* V1.2 §12.E: the user's attention is REQUIRED — this is the
           one mid-task event worth a real notification (deduped). */
        notifyUser(String(taskDoc.user_id), {
          type: 'warning', kind: 'agent_confirmation_required',
          title: 'KinyaBot Agent — approval needed',
          message: `A command needs your approval: ${String(command || '').slice(0, 120)}`,
          link: taskDoc.task_ref ? `/chat/agent/${taskDoc.task_ref}` : null,
          dedupeKey: `confirm_${taskId}_${id}`,
          meta: { taskId, confirmationId: id },
        }).catch(() => {})
      })
    },

    onPortsDetected: ({ ports }) => {
      // Only verified-listening ports reach here (bridge probed them).
      enqueueTaskMutation(taskId, async () => {
        const port = ports[0]
        await patchTask(taskId, {
          'preview.mode': 'dev',
          'preview.port': port,
          'preview.url_path': '/',
          'preview.started_at': new Date(),
          'preview.pid': handle.pid,
        })
        await emitAndPersist(taskDoc, 'preview_ready', { port, url: `/api/agent/tasks/${taskDoc.task_ref}/preview/`, mode: 'dev' })
      })
    },

    onDone: (payload) => finalizeTask(taskDoc, task, payload),
  })

  const stopWatchdog = bridge.startWatchdog(handle, () => {
    // §18: a silent worker is killed and reported honestly.
    handle.kill()
    finalizeTask(taskDoc, task, {
      ok: false,
      code: 'WORKER_STUCK',
      error: 'The execution worker stopped responding and was terminated by the watchdog.',
      stats: {},
    })
  })

  running.set(taskId, { handle, task, stopWatchdog, confirmations, taskDoc })
  enqueueTaskMutation(taskId, async () => {
    await patchTask(taskId, { status: 'running', started_at: new Date() })
  })
  /* The worker emits its own task_started (with the prompt) — one
     authoritative lifecycle event, no duplicate emission here. */
}

/* ── Event routing: keep the task document in sync ───────────── */
async function routeEvent(taskDoc, evt) {
  const type = evt?.type
  const data = evt?.data || {}
  const taskId = taskDoc._id.toString()

  switch (type) {
    case 'task_planning': {
      await patchTask(taskId, { status: 'planning' })
      break
    }
    case 'plan_updated': {
      await patchTask(taskId, { plan: (data.steps || []).map(title => ({ title, status: 'pending' })) })
      break
    }
    case 'tool_started': {
      // Mark the first still-pending plan step in_progress (§16 UI).
      const t = await AgentTask.findById(taskId)
      if (t) {
        const plan = [...(t.plan || [])]
        const idx = plan.findIndex(s => s.status === 'pending')
        if (idx !== -1) {
          plan[idx] = { ...plan[idx], status: 'in_progress' }
          await patchTask(taskId, { plan, current_step: idx })
        }
      }
      break
    }
    case 'tool_completed': {
      const t2 = await AgentTask.findById(taskId)
      if (t2) {
        const plan = [...(t2.plan || [])]
        const idx = plan.findIndex(s => s.status === 'in_progress')
        if (idx !== -1) {
          plan[idx] = { ...plan[idx], status: 'done' }
          await patchTask(taskId, { plan, current_step: Math.min(idx + 1, plan.length - 1) })
        }
      }
      break
    }
    case 'file_changed': {
      await AgentTask.findByIdAndUpdate(taskId, { $inc: { 'stats.files_changed': 1 } }).catch(() => {})
      break
    }
    case 'terminal_blocked': {
      /* V1.2 §13: a command the safety policy BLOCKED is a real
         security-relevant event — record telemetry and (throttled)
         surface it to Superadmins. Never noisy: one alert per 5 min. */
      try {
        await SecurityEvent.create({
          type: 'agent_command_blocked', severity: 'warning',
          message: `Agent blocked command: ${String(data.command || '').slice(0, 200)}`,
          meta: { taskId, reason: data.reason || null, taskRef: taskDoc.task_ref },
        })
        await notifyAdmins({
          title: 'Blocked command attempt in Agent task',
          message: `The command safety policy blocked a command in task ${taskDoc.task_ref || taskId}: ${String(data.reason || '').slice(0, 160)}`,
          type: 'warning', category: 'agent',
          link: '/admin/agent',
          resource: { kind: 'agent_task', id: taskId },
          dedupeKey: `agent_cmd_blocked_${Math.floor(Date.now() / (5 * 60 * 1000))}`,
          push: false,   // visible in the control center; not a PWA push (avoid alert storms)
        })
      } catch {}
      break
    }
    case 'background_process_started': {
      await emitAndPersist(taskDoc, 'preview_started', { command: data.command })
      break
    }
    case 'verification_started': {
      await patchTask(taskId, { status: 'running' })
      break
    }
    case 'confirmation_resolved': {
      await patchTask(taskId, { status: 'running' })
      break
    }
  }

  await emitAndPersist(taskDoc, type, data)
}

/* ── Finalization: persist outcome + mirror to conversation ──── */
async function finalizeTask(taskDoc, task, payload) {
  const taskId = task.taskId
  const entry = running.get(taskId)
  if (!entry) return // already finalized (cancel raced done)
  running.delete(taskId)
  entry.stopWatchdog?.()
  entry.handle.kill() // idempotent; also kills background procs inside worker

  // Drain the serialized chain BEFORE writing the terminal state so
  // no in-flight event patch can overwrite the final status.
  const chain = taskChains.get(taskId)
  if (chain) await chain.catch(() => {})
  dropTaskChain(taskId)

  const stats = payload.stats || {}
  const completedAt = new Date()

  if (payload.ok) {
    await patchTask(taskId, {
      status: 'completed',
      result: payload.result,
      completed_at: completedAt,
      'stats.steps': stats.steps ?? 0,
      'stats.tool_calls': stats.tool_calls ?? 0,
      'stats.commands_run': stats.commands_run ?? 0,
      'stats.files_changed': stats.files_changed ?? 0,
      'stats.duration_ms': stats.duration_ms ?? null,
      'stats.tokens': stats.tokens ?? null,
      'stats.model': stats.model ?? null,
      'stats.retries': stats.retries ?? 0,
    })
    await emitAndPersist(taskDoc, 'task_completed', { result: payload.result, verified: payload.verified === true })
    await mirrorResultToConversation(taskDoc, payload)
  } else if (payload.code === 'TASK_CANCELLED') {
    await patchTask(taskId, { status: 'cancelled', completed_at: completedAt, error: payload.error, error_code: 'TASK_CANCELLED' })
    await emitAndPersist(taskDoc, 'task_cancelled', { reason: payload.error })
    await mirrorResultToConversation(taskDoc, { ...payload, cancelled: true })
  } else {
    await patchTask(taskId, {
      status: 'failed',
      completed_at: completedAt,
      error: payload.userSafe ? payload.error : friendlyAgentError(payload),
      error_code: payload.code || 'AGENT_ERROR',
    })
    await emitAndPersist(taskDoc, 'task_failed', { error: payload.userSafe ? payload.error : friendlyAgentError(payload), code: payload.code })
    await mirrorResultToConversation(taskDoc, payload)
  }

  // ── Preview ownership hand-off (§24) ─────────────────────
  // On SUCCESS the dev server stays alive for inspection: the task
  // keeps its registered port + owning PIDs; the idle workspace
  // cleaner (or an explicit stop) reaps it later. On failure/cancel
  // every background process is killed right now — no leaks.
  const keepPreview = payload.ok === true
  const fresh = await AgentTask.findById(taskId).catch(() => null)
  if (fresh?.preview?.port) {
    if (keepPreview) {
      await patchTask(taskId, { 'preview.pids': payload.backgroundPids || [], 'preview.kept_alive': true }).catch(() => {})
    } else {
      killPidGroups(payload.backgroundPids || [])
      await emitAndPersist(taskDoc, 'preview_stopped', { port: fresh.preview.port }).catch(() => {})
      await patchTask(taskId, { preview: { mode: null, port: null, root: null, url_path: null, started_at: null, pid: null, pids: [], kept_alive: false } }).catch(() => {})
    }
  } else if (!keepPreview) {
    // No registered preview, but background procs may still exist
    // (worker crashed before port detection) — reap them honestly.
    killPidGroups(payload.backgroundPids || [])
  }

  /* ── V1.2 §3/§11: STATIC PREVIEW engage on completion ──────
     A finished task stops executing, but the preview must stay
     inspectable. When no dev-server port was ever registered and the
     workspace contains an index.html, the platform serves the files
     directly (no process to keep alive, no port to probe). The
     preview then lives exactly as long as the workspace — an
     explicit stop (§11) or the idle cleaner ends it.       */
  if (payload.ok === true && !fresh?.preview?.port && agentConfig.preview.staticEnabled) {
    try {
      const ws = new Workspace(taskId)
      const root = await staticPreview.detectProjectRoot(ws.root)
      if (root) {
        await patchTask(taskId, {
          'preview.mode': 'static',
          'preview.root': root,
          'preview.kept_alive': true,
          'preview.started_at': new Date(),
        }).catch(() => {})
        await emitAndPersist(taskDoc, 'preview_ready', {
          mode: 'static', root,
          url: `/api/agent/tasks/${taskDoc.task_ref}/preview/`,
          note: 'Served directly from the workspace — stays available while the workspace exists.',
        }).catch(() => {})
      }
    } catch {}
  }

  /* ── V1.2 §12: REAL user notifications on terminal states ──
     Persistent + realtime + Web Push where subscribed. Task events
     are the ONLY trigger — no synthetic rows, dedupe by task id. */
  try {
    const link = taskDoc.task_ref ? `/chat/agent/${taskDoc.task_ref}` : null
    if (payload.ok === true) {
      await notifyUser(String(taskDoc.user_id), {
        type: 'success', kind: 'agent_task_completed',
        title: 'KinyaBot Agent — Task completed',
        message: (String(payload.result || 'Your task finished.').slice(0, 240)) || 'Your task finished.',
        link, dedupeKey: `task_done_${taskId}`,
        meta: { taskRef: taskDoc.task_ref, taskId },
      })
    } else if (payload.code !== 'TASK_CANCELLED') {
      await notifyUser(String(taskDoc.user_id), {
        type: 'error', kind: 'agent_task_failed',
        title: 'KinyaBot Agent — Task failed',
        message: (payload.userSafe ? payload.error : friendlyAgentError(payload)).slice(0, 240),
        link, dedupeKey: `task_fail_${taskId}`,
        meta: { taskRef: taskDoc.task_ref, taskId, code: payload.code },
      })
    }
  } catch {}

  /* ── V1.2 §13: admin notifications from REAL system events ──
     Worker crashes and failure-rate spikes surface in the Superadmin
     control center (throttled + deduped; never per-task noise for
     ordinary user-level failures). */
  try {
    if (['WORKER_CRASHED', 'WORKER_STUCK'].includes(payload.code)) {
      await notifyAdmins({
        title: 'Agent worker terminated unexpectedly',
        message: `${friendlyAgentError(payload)} (task ${taskDoc.task_ref || taskId})`,
        type: 'error', category: 'agent',
        link: '/admin/agent',
        resource: { kind: 'agent_task', id: taskId },
        dedupeKey: `agent_worker_crash_${new Date().toISOString().slice(0, 13)}`,
        meta: { code: payload.code },
      })
    }
    await checkAgentFailureRate().catch(() => {})
  } catch {}

  pumpQueue()
}

/* ── V1.2 §13: honest failure-rate alerting ─────────────────
   Computed from REAL AgentTask documents over the last hour. Only
   fires when there were enough tasks for the rate to be meaningful
   (≥5) — a single user failure never raises a system alert.   */
const failureRateNotifiedAt = { ts: 0 }
async function checkAgentFailureRate() {
  const since = new Date(Date.now() - 60 * 60 * 1000)
  const [total, failed] = await Promise.all([
    AgentTask.countDocuments({ created_at: { $gte: since } }),
    AgentTask.countDocuments({ created_at: { $gte: since }, status: 'failed' }),
  ])
  if (total < 5 || failed === 0) return
  const rate = failed / total
  // Throttle: at most one rate alert per 30 minutes.
  if (Date.now() - failureRateNotifiedAt.ts < 30 * 60 * 1000) return
  if (rate >= 0.5) {
    failureRateNotifiedAt.ts = Date.now()
    await notifyAdmins({
      title: 'High Agent task failure rate',
      message: `${failed}/${total} agent tasks failed in the last hour (${Math.round(rate * 100)}%). Recent failures may share a root cause — inspect task logs.`,
      type: 'warning', category: 'agent',
      link: '/admin/agent',
      dedupeKey: `agent_failure_rate_${new Date().toISOString().slice(0, 13)}`,
    })
  }
}

function friendlyAgentError(payload) {
  const code = payload.code
  if (code === 'AI_AUTH') return 'The AI provider rejected the configured credentials (AI_AUTH). Check GROQ_API_KEY.'
  if (code === 'GROQ_NOT_CONFIGURED') return 'The AI provider is not configured (GROQ_API_KEY missing).'
  if (code === 'AI_RATE_LIMIT') return 'The AI provider rate limit was hit. Please retry the task in a moment.'
  if (code === 'AI_MODEL_UNAVAILABLE') return 'The configured agent model is unavailable (GROQ_AGENT_MODEL).'
  if (code === 'AI_TIMEOUT') return 'The AI provider timed out.'
  if (code === 'TASK_TIMEOUT') return payload.error || 'The task exceeded its maximum duration.'
  if (code === 'STEP_LIMIT') return payload.error || 'The task reached its maximum number of steps.'
  return payload.error || 'The agent task failed.'
}

/** §26: agent conversations behave like conversations. */
async function mirrorResultToConversation(taskDoc, payload) {
  try {
    if (!taskDoc.conversation_id) return
    const chat = await Chat.findById(taskDoc.conversation_id).catch(() => null)
    if (!chat) return

    if (payload.cancelled) {
      const cancelled = await Message.create({
        chat_id: chat._id,
        role: 'assistant',
        content: `**Agent task cancelled.** ${payload.error || ''}\n\nPartial work remains in the task workspace — reopen the task to inspect what was completed before cancellation.`.trim(),
        agent_task_id: taskDoc._id.toString(),
        model: 'agent',
        provider: 'kinyabot-agent',
        status: 'completed',
      })
      notifyChatRoom(chat, cancelled)
      return
    }

    if (!payload.ok) {
      const failed = await Message.create({
        chat_id: chat._id,
        role: 'assistant',
        content: `**Agent task failed.**\n\n\`${payload.code || 'AGENT_ERROR'}\` — ${payload.userSafe ? payload.error : friendlyAgentError(payload)}`,
        agent_task_id: taskDoc._id.toString(),
        model: 'agent',
        provider: 'kinyabot-agent',
        status: 'failed',
      })
      notifyChatRoom(chat, failed)
      return
    }

    const result = await Message.create({
      chat_id: chat._id,
      role: 'assistant',
      content: payload.result || '',
      agent_task_id: taskDoc._id.toString(),
      model: payload.stats?.model || 'agent',
      provider: 'kinyabot-agent',
      tokens: payload.stats?.tokens || null,
      status: 'completed',
    })
    chat.updated_at = new Date()
    await chat.save()
    notifyChatRoom(chat, result)
  } catch (err) {
    console.error('[Agent] mirror to conversation failed:', err.message)
  }
}

function notifyChatRoom(chat, message) {
  if (!ioRef) return
  const payload = { aiMessage: { id: message._id.toString(), role: 'assistant', content: message.content, agent_task_id: message.agent_task_id, model: message.model, status: message.status, created_at: message.created_at }, chatId: chat._id.toString() }
  ioRef.to(`chat_${chat._id.toString()}`).emit('new_message', payload)
  ioRef.to(`user_${chat.user_id.toString()}`).emit('chat_updated', { chatId: chat._id.toString() })
}

/* ── Task controls (§17) ────────────────────────────────────── */
async function cancelTask(taskId, reason = 'Task cancelled by the user') {
  const entry = running.get(String(taskId))
  const id = String(taskId)
  if (entry) {
    entry.handle.send({ type: 'cancel', reason })
    // The worker will emit done → finalizeTask. But also arm a hard
    // fallback: if it doesn't settle in 8s, kill + finalize here.
    setTimeout(() => {
      if (running.has(id)) {
        entry.handle.kill()
        finalizeTask(entry.taskDoc, entry.task, { ok: false, code: 'TASK_CANCELLED', error: reason, userSafe: true, stats: {} })
      }
    }, 8000).unref?.()
    return { stopping: true }
  }
  // Not running: either queued or already terminal — set state directly.
  const doc = await AgentTask.findById(id).catch(() => null)
  if (!doc) return { stopping: false, error: 'Task not found' }
  if (doc.status === 'queued') {
    const qi = queue.indexOf(id)
    if (qi !== -1) queue.splice(qi, 1)
    await patchTask(id, { status: 'cancelled', completed_at: new Date(), error: reason })
    await emitAndPersist(doc, 'task_cancelled', { reason })
    return { stopping: true, cancelled: 'queued' }
  }
  // Terminal task with a kept-alive preview: an explicit stop also
  // reaps its background dev server (§17 user intent is "shut it down").
  // V1.2 §11: an explicit stop ends the STATIC preview too — the user
  // asked for "no preview", and that intent outlives the process model.
  if (['completed', 'failed', 'cancelled'].includes(doc.status) && (doc.preview?.port || doc.preview?.mode === 'static')) {
    const pids = await backgroundPidsFor(id)
    killPidGroups(pids)
    await emitAndPersist(doc, 'preview_stopped', { port: doc.preview.port || null, mode: doc.preview.mode || null }).catch(() => {})
    await patchTask(id, { preview: { mode: null, port: null, root: null, url_path: null, started_at: null, pid: null, pids: [], kept_alive: false } }).catch(() => {})
    return { stopping: true, preview_stopped: true }
  }
  return { stopping: false, error: `Task is already ${doc.status}` }
}

async function resolveConfirmation(taskId, confirmationId, approved) {
  const entry = running.get(String(taskId))
  if (!entry) return { ok: false, error: 'Task is not running' }
  if (!entry.confirmations.has(confirmationId)) return { ok: false, error: 'Unknown or expired confirmation' }
  entry.confirmations.delete(confirmationId)
  entry.handle.send({ type: 'confirm', id: confirmationId, approved: approved === true })
  enqueueTaskMutation(String(taskId), async () => {
    await patchTask(String(taskId), { status: 'running' })
    await emitAndPersist(entry.taskDoc, 'confirmation_resolved', { id: confirmationId, approved: approved === true })
  })
  return { ok: true }
}

/* ── Queue pump ─────────────────────────────────────────────── */
async function pumpQueue() {
  while (queue.length && running.size < agentConfig.orchestration.maxConcurrentTasks) {
    const nextId = queue.shift()
    const doc = await AgentTask.findById(nextId).catch(() => null)
    if (!doc || doc.status !== 'queued') continue
    launchWorker(doc, { taskId: doc._id.toString(), prompt: doc.prompt, permissions: doc.permissions || agentConfig.defaultPermissions })
  }
}

/* ── Boot recovery (§30) + workspace cleanup (§12) ───────────── */
async function recoverOnBoot() {
  // Tasks left mid-flight by a previous process crash: honestly failed.
  const res = await AgentTask.updateMany(
    { status: { $in: ['queued', 'planning', 'running', 'waiting_for_confirmation', 'paused'] } },
    { $set: { status: 'failed', error: 'The server restarted while this task was running. Re-run the task to continue.', error_code: 'SERVER_RESTART', completed_at: new Date() } }
  ).catch(() => null)
  if (res?.modifiedCount) {
    console.log(`[Agent] boot recovery: ${res.modifiedCount} interrupted task(s) marked failed`)
  }
  // Their background dev servers (if any started before the crash)
  // are orphaned — reap them by the PIDs recorded in events (§12).
  try {
    const interrupted = await AgentTask.find(
      { error_code: 'SERVER_RESTART', completed_at: { $gte: new Date(Date.now() - 24 * 3600 * 1000) } },
      { _id: 1 }
    ).limit(100).lean()
    let reaped = 0
    for (const t of interrupted) {
      const pids = await backgroundPidsFor(t._id.toString())
      if (pids.length) { killPidGroups(pids); reaped += 1 }
    }
    if (reaped) console.log(`[Agent] boot recovery: reaped preview servers of ${reaped} interrupted task(s)`)
  } catch {}
}

async function cleanupIdleWorkspaces() {
  const cutoff = new Date(Date.now() - agentConfig.orchestration.workspaceIdleCleanupMin * 60 * 1000)
  const stale = await AgentTask.find({ updated_at: { $lt: cutoff } }, { _id: 1, workspace_id: 1, 'preview.pids': 1, 'preview.port': 1 }).limit(200).lean().catch(() => [])
  let removed = 0
  for (const t of stale) {
    // Reap kept-alive preview servers along with the workspace (§24).
    if (t.preview?.pids?.length) killPidGroups(t.preview.pids)
    if (t.preview?.port) {
      await patchTask(t._id.toString(), { preview: { port: null, url_path: null, started_at: null, pid: null, pids: [], kept_alive: false } }).catch(() => {})
    }
    const ws = new Workspace(t._id.toString())
    const exists = await ws.exists('.').catch(() => false)
    if (exists) { await ws.remove().catch(() => {}); removed++ }
  }
  if (removed) console.log(`[Agent] cleaned ${removed} idle workspace(s)`)
}

/* ── Preview registry lookup (used by the proxy route) ──────── */
function isTaskRunning(taskId) { return running.has(String(taskId)) }

module.exports = {
  attachAgentIo,
  startOrQueueTask,
  cancelTask,
  resolveConfirmation,
  recoverOnBoot,
  cleanupIdleWorkspaces,
  pumpQueue,
  isTaskRunning,
  runningCount,
  running,
  queue,
  getIo,
}
