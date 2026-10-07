/**
 * KinyaBot — Subscription & Plan Requests API (user-facing, §33)
 * ═══════════════════════════════════════════════════════════════
 *   GET  /api/plans                      public plan catalog
 *   GET  /api/subscription               current user's plan + usage + pending request
 *   GET  /api/subscription/usage         live daily usage only (cheap)
 *   POST /api/subscription/requests      submit an upgrade request (validated, deduped)
 *   GET  /api/subscription/requests      the user's own request history
 *   POST /api/subscription/ack-plan      acknowledge a plan-change celebration
 *
 * Security (§20):
 *   • Every plan attribute shown here is resolved SERVER-SIDE.
 *   • currentPlan is NEVER taken from the request body.
 *   • requestedPlan must be a valid upgrade path from the user's
 *     actual current plan.
 *   • Users can only ever read/modify their own rows.
 */
const express  = require('express')
const mongoose = require('mongoose')

const { PlanRequest, UserPlan } = require('../models')
const plans   = require('../services/plans')
const usage   = require('../services/usage')
const rateLimiter = require('../services/rateLimiter')
const { notifyUser } = require('../services/notify')
const { logActivity } = require('../services/activity')

const authGuard = require('../services/authGuard')

const router = express.Router()

/* ── helpers ─────────────────────────────────────────────────── */
function escapeRegex(s) { return String(s).replace(/[.*+?^${}()|[\]\\]/g, '\\$&') }

function fmtRequest(doc) {
  const obj = doc.toObject ? doc.toObject({ virtuals: false }) : { ...doc }
  obj.id = obj._id?.toString()
  delete obj._id; delete obj.__v
  if (obj.user_id instanceof mongoose.Types.ObjectId) obj.user_id = obj.user_id.toString()
  return obj
}

/* ══════════════════════════════════════════════════════════════
   PLAN CATALOG — public (no PII). Used by pricing UIs.
══════════════════════════════════════════════════════════════ */
router.get('/plans', async (_req, res) => {
  try {
    const all = await plans.getPlans()
    res.json({ plans: all, timezone: usage.APP_TIMEZONE })
  } catch {
    res.status(500).json({ error: 'Could not load plans' })
  }
})

/* Everything below requires a normal user session. NOTE: the guard is
   applied per-route (NOT via router.use) so this mounted router never
   intercepts unrelated /api/* routes (health, chats, …). */
const userOnly = [authGuard]

/* ══════════════════════════════════════════════════════════════
   SUBSCRIPTION STATE — one call powering the whole plans UI
══════════════════════════════════════════════════════════════ */
router.get('/subscription', userOnly, async (req, res) => {
  try {
    const planDoc = await plans.getUserPlanDoc(req.user.id)
    const plan = await plans.getPlan(planDoc.plan)
    const currentUsage = await usage.getUsage(req.user.id)

    const [pendingRequest, latestRequest] = await Promise.all([
      PlanRequest.findOne({ user_id: req.user.id, status: 'pending' }).sort({ created_at: -1 }).lean(),
      PlanRequest.findOne({ user_id: req.user.id }).sort({ created_at: -1 }).lean(),
    ])

    res.json({
      plan: planDoc.plan,
      planName: plan?.name || 'Free',
      tagline: plan?.tagline || '',
      status: planDoc.status || 'active',
      dailyLimit: currentUsage.limit,
      features: plan?.features || {},
      contextMessages: plan?.contextMessages || 10,
      docSizeMultiplier: plan?.docSizeMultiplier || 1,
      burstMultiplier: plan?.burstMultiplier || 1,
      activationSource: planDoc.activation_source || 'manual_admin_approval',
      activatedAt: planDoc.activated_at || null,
      activatedBy: planDoc.activated_by || null,
      previousPlan: planDoc.previous_plan || null,
      lastChange: planDoc.last_change?.ack === false && planDoc.last_change?.to
        ? { from: planDoc.last_change.from, to: planDoc.last_change.to, at: planDoc.last_change.at, ack: false }
        : null,
      usage: {
        date: currentUsage.date, used: currentUsage.used, limit: currentUsage.limit,
        remaining: currentUsage.remaining, percent: currentUsage.percent, state: currentUsage.state,
      },
      pendingRequest: pendingRequest ? fmtRequest(pendingRequest) : null,
      latestRequest: latestRequest ? fmtRequest(latestRequest) : null,
      upgradePaths: plans.UPGRADE_PATHS[planDoc.plan] || [],
    })
  } catch (err) {
    console.error('[Subscription]', err)
    res.status(500).json({ error: 'Could not load your subscription' })
  }
})

/* Live usage only — cheap call for the sidebar indicator. */
router.get('/subscription/usage', userOnly, async (req, res) => {
  try { res.json(await usage.getUsage(req.user.id)) }
  catch { res.status(500).json({ error: 'Could not load usage' }) }
})

/* ══════════════════════════════════════════════════════════════
   UPGRADE REQUESTS (manual workflow until a payment provider is
   integrated — §25 keeps User → Subscription → Plan → Payment
   separable)
══════════════════════════════════════════════════════════════ */
router.post('/subscription/requests', userOnly, async (req, res) => {
  const { fullName, email, country, countryCode, phone, requestedPlan, message } = req.body || {}

  // Burst protection on top of duplicate-request logic
  const rl = rateLimiter.allow(req.user.id, 'plan_request', { limit: 5, windowMs: 24 * 3600 * 1000 })
  if (!rl.ok) return res.status(429).json({ error: 'Too many requests. Please try again later.' })

  /* ── Validation (server-side truth only) ─────────────────── */
  const errors = {}
  const name = String(fullName || '').trim()
  if (name.length < 2 || name.length > 120) errors.fullName = 'Please enter your full name (2-120 characters).'

  const emailStr = String(email || '').trim().toLowerCase()
  if (!/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(emailStr) || emailStr.length > 200) errors.email = 'Please enter a valid email address.'

  const countryStr = String(country || '').trim()
  if (!countryStr || countryStr.length > 80) errors.country = 'Please select your country.'

  const phoneStr = String(phone || '').trim()
  if (!/^\+?[0-9\s().-]{7,20}$/.test(phoneStr)) errors.phone = 'Please enter a valid phone number.'

  const msgStr = String(message || '').trim()
  if (msgStr.length > 1000) errors.message = 'Message must be at most 1000 characters.'

  if (Object.keys(errors).length)
    return res.status(400).json({ error: 'Please fix the highlighted fields.', fields: errors })

  // Plan must be a real upgrade of the user's CURRENT plan (§20)
  try {
    const planDoc = await plans.getUserPlanDoc(req.user.id)
    const currentPlan = planDoc.plan
    const target = String(requestedPlan || '').toLowerCase().trim()
    const allowed = plans.UPGRADE_PATHS[currentPlan] || []
    if (!allowed.includes(target))
      return res.status(400).json({ error: `${target ? 'That plan is' : 'A target plan is'} not available from your current plan.` })

    /* ── Duplicate pending prevention (§16) ─────────────────── */
    const existingPending = await PlanRequest.findOne({ user_id: req.user.id, status: 'pending' })
    if (existingPending) {
      return res.status(409).json({
        error: `You already have a pending ${plans.PLAN_IDS.includes(existingPending.requested_plan) ? existingPending.requested_plan.charAt(0).toUpperCase() + existingPending.requested_plan.slice(1) : ''} upgrade request.`,
        code: 'DUPLICATE_REQUEST',
        request: fmtRequest(existingPending),
      })
    }

    // Previously rejected: submitting a new request is allowed (§16) —
    // the daily rate limit above prevents spam.

    const plan = await plans.getPlan(target)
    const request = await PlanRequest.create({
      user_id: req.user.id,
      full_name: name,
      email: emailStr,
      country: countryStr,
      country_code: String(countryCode || '').trim().toUpperCase().slice(0, 8) || null,
      phone: phoneStr,
      current_plan: currentPlan,
      requested_plan: target,
      message: msgStr,
      current_daily_limit: plan?.dailyChatLimit || null,
      status: 'pending',
    })

    // §21 — immutable audit trail for the user action
    logActivity('PLAN_UPGRADE_REQUESTED', {
      username: req.user.username, user_id: req.user.id,
      meta: { request_id: request._id.toString(), from: currentPlan, to: target },
    })

    notifyUser(req.user.id, {
      type: 'info',
      title: 'Upgrade request submitted',
      message: `Your ${target.charAt(0).toUpperCase() + target.slice(1)} upgrade request was received. We will review it shortly.`,
      kind: 'plan_request_submitted',
      meta: { requestId: request._id.toString(), plan: target },
    })

    res.status(201).json({ request: fmtRequest(request) })
  } catch (err) {
    console.error('[PlanRequest]', err)
    res.status(500).json({ error: 'Could not submit your request. Please try again.' })
  }
})

/* The user's own request history (paginated). */
router.get('/subscription/requests', userOnly, async (req, res) => {
  const page = Math.max(1, parseInt(req.query.page) || 1)
  const limit = Math.min(50, Math.max(1, parseInt(req.query.limit) || 10))
  try {
    const filter = { user_id: req.user.id }
    if (req.query.status && ['pending', 'approved', 'rejected'].includes(req.query.status))
      filter.status = req.query.status
    const [items, total] = await Promise.all([
      PlanRequest.find(filter).sort({ created_at: -1 }).skip((page - 1) * limit).limit(limit),
      PlanRequest.countDocuments(filter),
    ])
    res.json({ requests: items.map(fmtRequest), total, page, pages: Math.ceil(total / limit) || 1 })
  } catch (err) {
    console.error('[PlanRequestsList]', err)
    res.status(500).json({ error: 'Could not load your requests' })
  }
})

/* Acknowledge the "upgrade approved" celebration (§40). */
router.post('/subscription/ack-plan', userOnly, async (req, res) => {
  try {
    await UserPlan.updateOne({ user_id: req.user.id, 'last_change.ack': false }, { $set: { 'last_change.ack': true } })
    res.json({ success: true })
  } catch { res.status(500).json({ error: 'Could not update state' }) }
})

module.exports = router
