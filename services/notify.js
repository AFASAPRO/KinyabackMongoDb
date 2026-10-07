/**
 * KinyaBot — Admin Notification service
 * ─────────────────────────────────────────────────────────────────
 * Creates control-center notifications from REAL system events only:
 *   • AI request failures / provider trouble      (ai)
 *   • Security events (failed logins, bans…)      (security)
 *   • Moderation flags                            (moderation)
 *   • Config changes made by the Superadmin       (config)
 *   • System health changes                       (system)
 *   • Significant usage milestones                (usage)
 *
 * Each notification is persisted (AdminNotification), pushed live to
 * every connected Superadmin dashboard, and — when the event is
 * CRITICAL or a WARNING — delivered as a web push to the Superadmin
 * PWA with a deep link. Normal informational events never trigger a
 * push (push is prioritized, not noisy).
 */
const { AdminNotification } = require('../models')
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
 * notifyUser — realtime in-app notification for ONE user (§22).
 * Uses the existing Socket.IO `user_<id>` room (no polling, no new
 * infrastructure). Delivered live when the user is online; users who
 * are offline see the durable state on next load (plan page, usage
 * bar, modals all read /api/subscription).
 * @param {string} userId  target user id
 * @param {object} n { type, title, message, kind, meta }
 *   type: info | success | warning | error
 *   kind: semantic event, e.g. 'plan_updated', 'usage_limit_reached'
 */
function notifyUser(userId, n = {}) {
  try {
    emitToUser(userId, 'user_notification', {
      id: `un_${Date.now()}_${Math.random().toString(36).slice(2, 7)}`,
      type: n.type || 'info',
      title: n.title || '',
      message: n.message || '',
      kind: n.kind || null,
      meta: n.meta || null,
      created_at: new Date().toISOString(),
    })
  } catch {}
}

module.exports = { notifyAdmins, notifyUser }
