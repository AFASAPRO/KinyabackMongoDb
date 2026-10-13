/**
 * KinyaBot Agent V1.2 — User Notifications API (§12)
 * ─────────────────────────────────────────────────────────────
 * Real notification endpoints for the in-app notification center,
 * desktop notifications and Web Push subscription management.
 *
 * ROUTING NOTE: these live under /api/me/notifications — the legacy
 * PUBLIC broadcast endpoint (app.js GET /api/notifications, used by
 * the ChatWindow announcement banner) keeps its path untouched.
 * Same-origin routing previously shadowed this router on the shared
 * /api/notifications path; the distinct namespace fixes that for real
 * deployments, not just tests.
 *
 *   GET    /api/me/notifications                  list + unread count
 *   POST   /api/me/notifications/read             mark ids (or all) read
 *   POST   /api/me/notifications/dismiss          dismiss one notification
 *   GET    /api/me/notifications/push/status      VAPID key + push capability
 *   POST   /api/me/notifications/push/subscribe   register a push subscription
 *   POST   /api/me/notifications/push/unsubscribe remove a push subscription
 *
 * All routes are JWT-protected; every query is scoped to req.user.id
 * server-side — one user can never see or mutate another's rows.
 */
const express = require('express')
const authGuard = require('../services/authGuard')
const { UserNotification } = require('../models')
const pushService = require('../services/push')

const router = express.Router()
const userOnly = [authGuard]

function fmt(doc) {
  return {
    id: doc._id.toString(),
    type: doc.type, kind: doc.kind,
    title: doc.title, message: doc.message,
    link: doc.link, meta: doc.meta,
    read: doc.read === true,
    dedupe_key: doc.dedupe_key || null,
    delivery: doc.delivery || null,
    created_at: doc.created_at,
  }
}

/* ── List + unread count (the notification center's backbone) ── */
router.get('/me/notifications', ...userOnly, async (req, res) => {
  try {
    const limit = Math.min(100, Math.max(1, Number(req.query.limit) || 30))
    const unreadOnly = req.query.unread === '1' || req.query.unread === 'true'
    const q = { user_id: req.user.id, dismissed: { $ne: true } }
    if (unreadOnly) q.read = false
    const [docs, unread] = await Promise.all([
      UserNotification.find(q).sort({ created_at: -1 }).limit(limit).lean(),
      UserNotification.countDocuments({ user_id: req.user.id, read: false, dismissed: { $ne: true } }),
    ])
    res.json({ notifications: docs.map(fmt), unread, push: pushStatus(req) })
  } catch {
    res.status(500).json({ error: 'Notifications could not be loaded.' })
  }
})

/* ── Mark read: { ids: [...] } or { all: true } ────────────────── */
router.post('/me/notifications/read', ...userOnly, async (req, res) => {
  try {
    const ids = Array.isArray(req.body?.ids) ? req.body.ids.map(String).slice(0, 200) : null
    const all = req.body?.all === true
    if (!ids && !all) return res.status(400).json({ error: 'Provide ids or all:true.' })
    const q = { user_id: req.user.id, read: false }
    if (!all && ids?.length) q._id = { $in: ids }
    const r = await UserNotification.updateMany(q, { $set: { read: true } })
    res.json({ ok: true, updated: r.modifiedCount || 0 })
  } catch {
    res.status(500).json({ error: 'Notifications could not be updated.' })
  }
})

/* ── Dismiss (archive) one notification ────────────────────────── */
router.post('/me/notifications/dismiss', ...userOnly, async (req, res) => {
  try {
    const id = String(req.body?.id || '')
    if (!id) return res.status(400).json({ error: 'id is required.' })
    const r = await UserNotification.updateOne({ _id: id, user_id: req.user.id }, { $set: { dismissed: true, read: true } })
    if (!r.matchedCount) return res.status(404).json({ error: 'Notification not found.' })
    res.json({ ok: true })
  } catch {
    res.status(500).json({ error: 'The notification could not be dismissed.' })
  }
})

/* ── Push capability + PUBLIC key (client subscribes with this) ── */
function pushStatus() {
  const st = pushService.status()
  return {
    configured: st.enabled === true,          // server has VAPID keys
    public_key: pushService.publicKey(),      // null when unconfigured
  }
}
router.get('/me/notifications/push/status', ...userOnly, (_req, res) => {
  res.json(pushStatus())
})

/* ── Register a Web Push subscription for THIS user ────────────── */
router.post('/me/notifications/push/subscribe', ...userOnly, async (req, res) => {
  try {
    const sub = req.body?.subscription || req.body
    const endpoint = String(sub?.endpoint || '')
    const keys = sub?.keys || null
    if (!endpoint.startsWith('https://') || !keys?.p256dh || !keys?.auth) {
      return res.status(400).json({ error: 'A valid push subscription is required.' })
    }
    await pushService.subscribe({
      endpoint, keys,
      user_agent: req.headers['user-agent'],
      ownerType: 'user', userId: req.user.id,
    })
    res.json({ ok: true, ...pushStatus() })
  } catch (err) {
    res.status(err?.status || 500).json({ error: err?.userSafe ? err.message : 'The push subscription could not be registered.' })
  }
})

/* ── Remove a Web Push subscription (unsubscribe is honored) ───── */
router.post('/me/notifications/push/unsubscribe', ...userOnly, async (req, res) => {
  try {
    const endpoint = String(req.body?.endpoint || '')
    if (!endpoint) return res.status(400).json({ error: 'endpoint is required.' })
    await pushService.unsubscribe({ endpoint })
    res.json({ ok: true })
  } catch {
    res.status(500).json({ error: 'The push subscription could not be removed.' })
  }
})

module.exports = router
