/**
 * KinyaBot — Web Push service (Superadmin PWA)
 * ─────────────────────────────────────────────────────────────────
 * Real web-push (VAPID) delivery to every registered Superadmin PWA
 * subscription. Enabled ONLY when VAPID_PUBLIC_KEY / VAPID_PRIVATE_KEY
 * are configured — otherwise the service reports `disabled` honestly
 * and no push is attempted (the dashboard notification center and
 * realtime socket still work without it).
 *
 * Generate keys once with:  npm run generate-vapid
 */
let webpush = null
try { webpush = require('web-push') } catch { webpush = null }

const { PushSubscription } = require('../models')

const VAPID_PUBLIC_KEY  = process.env.VAPID_PUBLIC_KEY  || null
const VAPID_PRIVATE_KEY = process.env.VAPID_PRIVATE_KEY || null
const VAPID_SUBJECT     = process.env.VAPID_SUBJECT     || 'mailto:admin@kinyabot.ai'

let configured = false
if (webpush && VAPID_PUBLIC_KEY && VAPID_PRIVATE_KEY) {
  try {
    webpush.setVapidDetails(VAPID_SUBJECT, VAPID_PUBLIC_KEY, VAPID_PRIVATE_KEY)
    configured = true
  } catch (err) { console.error('[Push] VAPID config invalid:', err.message) }
}

function status() {
  return {
    enabled: configured,
    library: !!webpush,
    public_key: configured ? VAPID_PUBLIC_KEY : null,
    subscriptions: null, // filled by callers when needed
  }
}

/**
 * Send a push to every stored subscription. Dead endpoints (410/404)
 * are pruned automatically so the subscription list stays real.
 * Payload: { title, body, tag, url, priority } — the service worker
 * turns this into a notification and `url` becomes the deep link.
 */
async function sendToAll(payload) {
  if (!configured) return { sent: 0, skipped: 'push_not_configured' }
  const subs = await PushSubscription.find().lean()
  if (!subs.length) return { sent: 0, skipped: 'no_subscriptions' }

  const body = JSON.stringify({
    title: payload.title || 'KinyaBot',
    body: payload.body || '',
    tag: payload.tag || 'kinyabot',
    url: payload.url || '/admin/dashboard',
    priority: payload.priority || 'information',
    ts: Date.now(),
  })

  let sent = 0
  await Promise.all(subs.map(async (s) => {
    try {
      await webpush.sendNotification(
        { endpoint: s.endpoint, keys: s.keys },
        body,
        { TTL: 3600, urgency: payload.priority === 'critical' ? 'high' : 'normal' }
      )
      sent++
    } catch (err) {
      const code = err?.statusCode
      if (code === 404 || code === 410) {
        try { await PushSubscription.deleteOne({ _id: s._id }) } catch {}
      }
    }
  }))
  return { sent, total: subs.length }
}

async function subscribe({ endpoint, keys, user_agent }) {
  if (!endpoint || !keys?.p256dh || !keys?.auth) throw Object.assign(new Error('Invalid subscription'), { status: 400 })
  await PushSubscription.findOneAndUpdate(
    { endpoint },
    { endpoint, keys, user_agent: user_agent || null },
    { upsert: true, new: true }
  )
  const total = await PushSubscription.countDocuments()
  return { ok: true, total }
}

async function unsubscribe({ endpoint }) {
  if (!endpoint) throw Object.assign(new Error('Endpoint required'), { status: 400 })
  await PushSubscription.deleteOne({ endpoint })
  return { ok: true }
}

async function subscriptionCount() {
  return PushSubscription.countDocuments()
}

module.exports = { status, sendToAll, subscribe, unsubscribe, subscriptionCount }
