/**
 * KinyaBot — Rate Limiter & Quota Guard
 * ─────────────────────────────────────────────────────────────
 * In-memory sliding-window rate limiting per user per capability
 * (chat, uploads, STT, TTS) + enforcement of the existing daily
 * message quota (UserPlan / admin free_daily_limit) using the
 * already-collected UsageTracking data. Configurable through env
 * (see services/ai/config.js → rateLimits).
 *
 * NOTE: the existing backend authGuard remains the authentication
 * layer; this only protects AI resource spend (§20).
 */
const mongoose = require('mongoose')
const { UsageTracking, UserPlan } = require('../models')

const buckets = new Map() // key `${userId}:${bucket}` -> timestamps[]

function allow(userId, bucket, { limit, windowMs }) {
  const key = `${userId}:${bucket}`
  const now = Date.now()
  const arr = (buckets.get(key) || []).filter(ts => now - ts < windowMs)
  if (arr.length >= limit) {
    buckets.set(key, arr)
    return { ok: false, retryAfterSec: Math.ceil((arr[0] + windowMs - now) / 1000) }
  }
  arr.push(now)
  buckets.set(key, arr)
  // opportunistic cleanup
  if (buckets.size > 5000) {
    for (const [k, v] of buckets) if (!v.length) buckets.delete(k)
  }
  return { ok: true }
}

/* Daily quota: reuse the plan/admin limits the app already had. */
async function dailyQuotaOk(userId, freeDailyLimit) {
  try {
    const uid = new mongoose.Types.ObjectId(userId)
    const start = new Date(); start.setHours(0, 0, 0, 0)
    const [today, plan] = await Promise.all([
      UsageTracking.countDocuments({ user_id: uid, created_at: { $gte: start } }),
      UserPlan.findOne({ user_id: uid }).lean(),
    ])
    const limit = plan?.daily_limit || freeDailyLimit || 50
    if (today >= limit) return { ok: false, limit, today }
    return { ok: true, limit, today }
  } catch { return { ok: true, limit: null, today: 0 } } // quota check must not hard-block on DB hiccups
}

function tooMany(res, retryAfterSec) {
  res.set('Retry-After', String(Math.max(1, retryAfterSec || 5)))
  return res.status(429).json({ error: 'You are sending requests too quickly. Please take a short break and try again.' })
}

module.exports = { allow, dailyQuotaOk, tooMany }
