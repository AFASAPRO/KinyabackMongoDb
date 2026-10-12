/**
 * KinyaBot Agent V1 — Event Service (§15, §30, §31)
 * ─────────────────────────────────────────────────────────────
 * Every agent event is (a) persisted to the AgentEvent collection
 * with a per-task sequence number and (b) pushed in realtime over
 * the EXISTING Socket.IO infrastructure to the user's room
 * (user_<id>) — the same channel KinyaBot already uses for plan
 * updates and notifications, so reconnection behaviour is
 * inherited for free (§30 fault tolerance).
 *
 * Event names follow §15 exactly:
 *   task.created · task.started · task.planning · task.plan_updated
 *   task.tool.started/completed/failed/retried · task.file.changed
 *   task.terminal.started/output/completed/blocked
 *   task.preview.ready/stopped · task.verification.started/completed
 *   task.confirmation.requested/resolved
 *   task.completed · task.failed · task.cancelled
 * (internal worker names are mapped to the public wire names here)
 */
const mongoose = require('mongoose')
const { AgentEvent } = require('../../models')

const EVENT_MAP = {
  task_started: 'task.started',
  task_planning: 'task.planning',
  plan_updated: 'task.plan_updated',
  agent_step: 'task.step',
  tool_started: 'task.tool.started',
  tool_completed: 'task.tool.completed',
  tool_failed: 'task.tool.failed',
  tool_retry: 'task.tool.retried',
  file_changed: 'task.file.changed',
  terminal_started: 'task.terminal.started',
  terminal_output: 'task.terminal.output',
  terminal_completed: 'task.terminal.completed',
  terminal_blocked: 'task.terminal.blocked',
  background_process_started: 'task.terminal.background_started',
  ports_detected: 'task.ports.detected',
  preview_started: 'task.preview.started',
  preview_ready: 'task.preview.ready',
  preview_stopped: 'task.preview.stopped',
  verification_started: 'task.verification.started',
  verification_completed: 'task.verification.completed',
  repair_started: 'task.repair.started',
  confirmation_requested: 'task.confirmation.requested',
  confirmation_resolved: 'task.confirmation.resolved',
  task_completed: 'task.completed',
  task_failed: 'task.failed',
  task_cancelled: 'task.cancelled',
  task_created: 'task.created',
}

/* Events whose payloads may contain content worth bounding before
   persisting (terminal chunks can be high-frequency). */
const MAX_DATA_CHARS = 8000

function boundData(data) {
  try {
    const s = JSON.stringify(data ?? {})
    if (s.length <= MAX_DATA_CHARS) return data ?? {}
    return { truncated: true, preview: s.slice(0, MAX_DATA_CHARS) }
  } catch {
    return { unpersistable: true }
  }
}

/* Per-task sequence allocation. A DB findOne-then-create would race
   whenever orchestrator lifecycle events and worker events interleave
   (duplicate seq numbers → gap-free catch-up breaks). V1 runs a
   single API process, so an in-process counter seeded ONCE from the
   persisted maximum is both atomic and contiguous. The compound
   unique index on (task_id, seq) guards against regressions. */
const seqCounters = new Map() // taskId -> last allocated seq
const seqSeeds = new Map()   // taskId -> Promise resolving once seeded from DB

async function nextSeq(taskId) {
  // Single-flight seeding: concurrent callers must not both read the
  // DB maximum and both start counting from the same number.
  let seed = seqSeeds.get(taskId)
  if (!seed) {
    seed = AgentEvent.findOne({ task_id: taskId }, { seq: 1 }, { sort: { seq: -1 } }).lean()
      .then(last => { seqCounters.set(taskId, last?.seq ?? 0) })
      .catch(() => { if (!seqCounters.has(taskId)) seqCounters.set(taskId, 0) })
    seqSeeds.set(taskId, seed)
  }
  await seed
  // Increment + read + write run synchronously after the await — the
  // JS event loop guarantees no interleaving between these statements.
  const next = seqCounters.get(taskId) + 1
  seqCounters.set(taskId, next)
  return next
}

/** Test/diagnostic hook: drop cached counters (no effect on prod). */
function resetSeqCounters() { seqCounters.clear(); seqSeeds.clear() }

/**
 * Record + broadcast one event.
 * @param {object} p { taskId, userId, type (worker name), data }
 * @param {object} io  Socket.IO server (from app.get('io'))
 * @returns the persisted event (lean) or null on write failure
 */
async function recordEvent({ taskId, userId, type, data }, io) {
  const wireType = EVENT_MAP[type] || type
  let doc = null
  try {
    const seq = await nextSeq(taskId)
    doc = await AgentEvent.create({
      task_id: taskId,
      user_id: userId,
      type: wireType,
      data: boundData(data),
      seq,
    })
  } catch (err) {
    // Persistence must never break execution — but it IS logged (§31).
    console.error(`[Agent] event persist failed (${type}):`, err.message)
  }
  const payload = {
    taskId: String(taskId),
    type: wireType,
    data: data ?? {},
    seq: doc?.seq ?? null,
    at: doc?.created_at || new Date().toISOString(),
  }
  try { io?.to(`user_${String(userId)}`).emit('agent_event', payload) } catch {}
  return doc ? { ...doc.toObject(), id: doc._id.toString() } : null
}

/** Restore endpoint support (§25): fetch events after a sequence. */
async function listEvents(taskId, { after = 0, limit = 500 }) {
  const docs = await AgentEvent.find({ task_id: taskId, seq: { $gt: Number(after) || 0 } })
    .sort({ seq: 1 })
    .limit(Math.min(2000, Math.max(1, Number(limit) || 500)))
    .lean()
  return docs.map(d => ({
    id: d._id.toString(),
    taskId: d.task_id.toString(),
    type: d.type,
    data: d.data,
    seq: d.seq,
    at: d.created_at,
  }))
}

module.exports = { recordEvent, listEvents, EVENT_MAP, resetSeqCounters }
