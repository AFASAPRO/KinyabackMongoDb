/**
 * KinyaBot — Real Activity & Presence (shared service)
 * ─────────────────────────────────────────────────────────────────
 * Event-sourced live activity: every call is made at the exact moment
 * a real thing happens (a real login, a real message, a real ban…)
 * and is both persisted (SystemLog, so a fresh page load has real
 * history) and pushed instantly over Socket.IO to every Superadmin
 * dashboard in `admin_room`.
 *
 * Online/offline state is derived from real Socket.IO connections —
 * a user only ever shows as active while a socket is actually open.
 * Nothing here is randomized or sampled.
 */
let ioRef = null

/** Called once from app.js after Socket.IO is wired up. */
function attachIo(io) { ioRef = io }

const onlinePresence = new Map() // userId(string) -> { username, sockets:Set<string>, since:Date }

function emitToAdmins(event, payload) {
  if (ioRef) ioRef.to('admin_room').emit(event, payload)
}

/** Emit to every live socket connection of one user (user_<id> room).
 *  Used for realtime user notifications (plan updates, usage alerts). */
function emitToUser(userId, event, payload) {
  if (ioRef && userId) ioRef.to(`user_${String(userId)}`).emit(event, payload)
}

/**
 * Record a real activity event.
 * @param {string} action  machine name, e.g. 'register', 'ai_request_failed'
 * @param {object} opts   { username, user_id, meta }
 */
async function logActivity(action, { username = null, user_id = null, meta = null } = {}) {
  const entry = { action, username, meta, created_at: new Date() }
  try {
    const { SystemLog } = require('../models')
    const doc = await SystemLog.create({ level: 'info', source: 'activity', message: action, data: { username, meta }, user_id: user_id || null })
    entry.id = doc._id.toString()
  } catch { entry.id = `tmp_${Date.now()}_${Math.random().toString(36).slice(2, 7)}` }
  emitToAdmins('admin_activity', entry)
  return entry
}

module.exports = { attachIo, onlinePresence, logActivity, emitToAdmins, emitToUser }
