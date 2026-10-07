/**
 * KinyaBot — Daily Usage Service (§3, §4, §36)
 * ═══════════════════════════════════════════════════════════════
 * Real, backend-enforced daily chat accounting.
 *
 *  • ONE authoritative counter per user per day: `usagedaily`
 *    documents keyed by an application-timezone date string.
 *  • Reservation is ATOMIC: findOneAndUpdate with a
 *    `chats_used < limit` guard + $inc — two simultaneous requests
 *    at 49/50 can never both succeed (§36).
 *  • Failed AI requests are refunded (§36) — only AI turns that
 *    actually reached the model count.
 *  • Days roll over automatically: a new date string simply starts
 *    a new document at 0 — no cron, no manual reset (§4).
 *  • Near-limit / limit-reached notifications fire once per day,
 *    guarded by per-document flags (no repeat spam).
 *
 * Timezone strategy: the day boundary is computed with Intl in
 * APP_TIMEZONE (env, default UTC) and stored as 'YYYY-MM-DD'.
 * Every part of the app derives "today" through todayKey() so the
 * whole system shares one consistent definition of a day.
 */
const mongoose = require('mongoose')
const { UsageDaily, SecurityEvent } = require('../models')
const plans = require('./plans')

const APP_TIMEZONE = (process.env.APP_TIMEZONE || 'UTC').trim()
const NEAR_LIMIT_RATIO = 0.8

/** 'YYYY-MM-DD' for "now" in the configured application timezone. */
function todayKey(now = new Date()) {
  try {
    return new Intl.DateTimeFormat('en-CA', {
      timeZone: APP_TIMEZONE, year: 'numeric', month: '2-digit', day: '2-digit',
    }).format(now) // en-CA gives YYYY-MM-DD
  } catch {
    // Invalid APP_TIMEZONE env — fall back to UTC
    return now.toISOString().slice(0, 10)
  }
}

/** Usage doc for a user today (creates nothing). */
async function getTodayDoc(userId, dateKey = null) {
  const date = dateKey || todayKey()
  return UsageDaily.findOne({ user_id: userId, date }).lean()
}

/** Full usage snapshot for a user (plan-aware). */
async function getUsage(userId) {
  const planDoc = await plans.getUserPlanDoc(userId).catch(() => null)
  const plan = await plans.getPlan(planDoc?.plan || 'free')
  const date = todayKey()
  const today = await getTodayDoc(userId, date)
  const used = Math.max(0, today?.chats_used || 0)
  const limit = plan?.dailyChatLimit || 50
  const remaining = Math.max(0, limit - used)
  const ratio = limit ? used / limit : 0
  return {
    date,
    timezone: APP_TIMEZONE,
    plan: plan?.plan_id || 'free',
    planName: plan?.name || 'Free',
    status: planDoc?.status || 'active',
    used,
    limit,
    remaining,
    percent: Math.min(100, Math.round(ratio * 100)),
    state: used >= limit ? 'limit' : (ratio >= NEAR_LIMIT_RATIO ? 'warning' : 'normal'),
    resetAt: null, // frontend renders "resets tomorrow" — day boundary handled by date key
  }
}

/**
 * Atomically reserve one chat. Returns { ok, usage } — when ok is
 * false the caller must NOT call the AI provider (§3).
 */
async function consume(userId, { count = 1 } = {}) {
  const date = todayKey()
  const usageBefore = await getUsage(userId)
  const limit = usageBefore.limit
  const planCfg = await plans.getPlan(usageBefore.plan)
  if (usageBefore.used + count > limit) {
    await markReached(userId, date, usageBefore)
    return { ok: false, usage: usageBefore, planCfg, count }
  }
  // Atomic guard: the update only applies while the counter is still
  // below the limit. Upsert creates the day document on first use.
  let doc
  try {
    doc = await UsageDaily.findOneAndUpdate(
      { user_id: userId, date, chats_used: { $lte: Math.max(0, limit - count) } },
      { $inc: { chats_used: count } },
      { upsert: true, new: true, setDefaultsOnInsert: true }
    )
  } catch (err) {
    // Rare race on the upsert (duplicate key) — retry once as a plain
    // guarded update; the atomic condition still protects the limit.
    doc = await UsageDaily.findOneAndUpdate(
      { user_id: userId, date, chats_used: { $lte: Math.max(0, limit - count) } },
      { $inc: { chats_used: count } },
      { new: true }
    ).catch(() => null)
    if (!doc) {
      const usage = await getUsage(userId)
      return { ok: false, usage, planCfg, count }
    }
  }
  const used = doc.chats_used
  const usage = { ...usageBefore, used, remaining: Math.max(0, limit - used), percent: Math.min(100, Math.round((used / limit) * 100)) }
  usage.state = used >= limit ? 'limit' : (usage.percent >= NEAR_LIMIT_RATIO * 100 ? 'warning' : 'normal')

  // One-shot side effects (best-effort, never block the chat path)
  if (used >= limit) await markReached(userId, date, usage)
  else if (usage.percent >= NEAR_LIMIT_RATIO * 100) await markNearLimit(userId, date, usage)

  return { ok: true, usage, planCfg, count }
}

/** Refund a reservation — the AI request never reached the model. */
async function refund(userId, { count = 1 } = {}) {
  const date = todayKey()
  try {
    const doc = await UsageDaily.findOneAndUpdate(
      { user_id: userId, date, chats_used: { $gt: 0 } },
      { $inc: { chats_used: -count } },
      { new: true }
    )
    if (doc && doc.chats_used < 0) {
      await UsageDaily.updateOne({ _id: doc._id }, { $set: { chats_used: 0 } })
    }
  } catch {}
}

/* ── One-shot notifications / telemetry (§21, §22) ───────────── */
async function markNearLimit(userId, date, usage) {
  try {
    const res = await UsageDaily.updateOne(
      { user_id: userId, date, near_notified: false },
      { $set: { near_notified: true } }
    )
    if (res.modifiedCount) {
      const { notifyUser } = require('./notify')
      notifyUser(userId, {
        type: 'warning',
        title: 'Running low on chats',
        message: `You have ${usage.remaining} of ${usage.limit} chats left on your ${usage.planName} plan today.`,
        kind: 'usage_near_limit',
      })
      await SecurityEvent.create({
        type: 'plan_usage_near_limit', severity: 'info',
        message: `User near daily chat limit (${usage.used}/${usage.limit})`,
        meta: { user_id: String(userId), plan: usage.plan },
      }).catch(() => {})
    }
  } catch {}
}

async function markReached(userId, date, usage) {
  try {
    const res = await UsageDaily.updateOne(
      { user_id: userId, date, reached_notified: false },
      { $set: { reached_notified: true } }
    )
    if (res.modifiedCount) {
      const { notifyUser } = require('./notify')
      notifyUser(userId, {
        type: 'error',
        title: 'Daily chat limit reached',
        message: `You have used all ${usage.limit} chats available on your ${usage.planName} plan today. Your limit resets tomorrow.`,
        kind: 'usage_limit_reached',
      })
      // §21 — real telemetry for the Superadmin security/audit trail
      await SecurityEvent.create({
        type: 'plan_limit_reached', severity: 'info',
        message: `User reached the daily chat limit (${usage.used}/${usage.limit})`,
        meta: { user_id: String(userId), plan: usage.plan, date },
      }).catch(() => {})
    }
  } catch {}
}

module.exports = { todayKey, getUsage, getTodayDoc, consume, refund, APP_TIMEZONE, NEAR_LIMIT_RATIO }
