/**
 * KinyaBot — Admin + User Notification service (V1.2 §12/§13)
 * ─────────────────────────────────────────────────────────────────
 * notifyAdmins — control-center notifications from REAL system events
 *   only: AI failures, security events, moderation flags, config
 *   changes, system health, usage milestones, AGENT events (V1.2:
 *   worker crashes, failure-rate spikes, blocked-command attempts,
 *   preview trouble, push delivery failures…).
 *   Each is persisted (AdminNotification), pushed live to every
 *   connected Superadmin dashboard, and — when CRITICAL/WARNING —
 *   delivered as web push to the Superadmin PWA with a deep link.
 *
 * notifyUser — V1.2 UPGRADE: REAL persistent per-user notifications.
 *   Every call: dedupes on (user, kind, dedupe_key), PERSISTS a
 *   UserNotification (history + read state + deep link), emits the
 *   live socket event, and sends real Web Push to that user's
 *   devices when push is configured AND subscribed AND the user has
 *   not muted the notification kind. Nothing synthetic, ever.  */
const { AdminNotification, UserNotification, User } = require('../models')
const { emitToAdmins, emitToUser } = require('./activity')
const pushService = require('./push')

// In-memory throttle so a burst of the same failure (e.g. provider
// down while 50 messages stream) creates ONE notification, not 50.
const recent = new Map() // key -> ts
const THROTTLE_MS = 60 * 1000
function throttled(key) {
  const now = Date.now()
  const last = recent.get(key) || 0
  if (now - last < THROTTLE_MS) return true
  recent.set(key, now)
  // opportunistic cleanup
  if (recent.size > 500) for (const [k, t] of recent) if (now - t > THROTTLE_MS * 10) recent.delete(k)
  return false
}

/**
 * @param {object} n { title, message, type, category, link, resource, meta, dedupeKey, push }
 *   type:     info | success | warning | error | critical
 *   category: system | ai | security | user | moderation | config | usage
 *   link:     deep-link path inside the Superadmin app
 */
async function notifyAdmins(n) {
  const {
    title, message,
    type = 'info', category = 'system',
    link = null, resource = null, meta = null,
    dedupeKey = null, push = null,
  } = n
  if (!title || !message) return null
  if (dedupeKey && throttled(dedupeKey)) return null

  let doc = null
  try {
    doc = await AdminNotification.create({ title, message, type, category, link, resource, meta })
  } catch (err) { console.error('[Notify] persist failed:', err.message); return null }

  const payload = {
    id: doc._id.toString(), title, message, type, category, link, resource, meta,
    read: false, created_at: doc.created_at,
  }
  emitToAdmins('admin_notification_new', payload)

  // Push only important events to the Superadmin PWA.
  const shouldPush = push !== null ? push : ['critical', 'error', 'warning'].includes(type)
  if (shouldPush) {
    pushService.sendToAll({
      title,
      body: message,
      tag: dedupeKey || `kinyabot-${category}`,
      url: link || '/admin/dashboard',
      priority: type === 'critical' ? 'critical' : (type === 'warning' ? 'warning' : 'information'),
    }).catch(() => {})
  }
  return payload
}

/**
 * notifyUser — REAL persistent user notification (V1.2 §12).
 * @param {string} userId target user id
 * @param {object} n { type, kind, title, message, link, meta, dedupeKey, push }
 *   type: info | success | warning | error
 *   kind: semantic event, e.g. 'agent_task_completed'
 *   link: deep link (e.g. /chat/agent/<task_ref>)
 *   dedupeKey: optional — identical events collapse into ONE row
 *   push: force push on/off (default: push for warning/error/success
 *         kinds the user has enabled — agent events default ON)
 * @returns the persisted payload (or null when deduped/failed)
 */
async function notifyUser(userId, n = {}) {
  if (!userId) return null
  const {
    type = 'info', kind = 'generic', title = '', message = '',
    link = null, meta = null, dedupeKey = null, push = null,
  } = n
  if (!title || !message) return null

  // ── 1. Deduped persistence (retried events never spam) ──
  // A dedupe_key makes (user, kind, key) unique — the same logical
  // event delivered twice updates the SAME row instead of spamming.
  // Without a key every call is a distinct notification by design.
  let doc
  try {
    const { Types } = require('mongoose')
    const key = dedupeKey || new Types.ObjectId().toString()
    doc = await UserNotification.findOneAndUpdate(
      { user_id: userId, kind, dedupe_key: key },
      { $setOnInsert: { user_id: userId, type, kind, title, message, link, meta, dedupe_key: key, delivery: { inapp: false, push: null } } },
      { upsert: true, new: true }
    )
  } catch (err) { console.error('[Notify] user persist failed:', err.message); return null }

  const payload = {
    id: doc._id.toString(), type, kind, title, message, link, meta,
    read: doc.read === true, created_at: doc.created_at,
  }

  // ── 2. Live in-app delivery (existing user room — no polling) ──
  try {
    await UserNotification.updateOne({ _id: doc._id }, { $set: { 'delivery.inapp': true } }).catch(() => {})
    emitToUser(userId, 'user_notification', payload)
  } catch {}

  // ── 3. Real Web Push to the user's devices (V1.2 §12.C) ──
  const wantsPush = push !== null ? push : ['success', 'warning', 'error'].includes(type)
  if (wantsPush) {
    const r = await pushService.sendToUser(userId, {
      title, body: message, tag: dedupeKey || `kinyabot-${kind}`,
      url: link || '/chat/', priority: type === 'error' ? 'critical' : (type === 'warning' ? 'warning' : 'information'),
      kind,
    }).catch(() => null)
    const state = !r ? 'failed' : (r.sent > 0 ? 'sent' : 'skipped')
    await UserNotification.updateOne({ _id: doc._id }, { $set: { 'delivery.push': state } }).catch(() => {})
    payload.delivery = { inapp: true, push: state }
  }
  return payload
}

module.exports = { notifyAdmins, notifyUser }
