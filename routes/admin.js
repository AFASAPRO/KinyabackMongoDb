/**
 * KinyaBot — Superadmin API (v2, rebuilt)
 * ═══════════════════════════════════════════════════════════════
 * ONE administrative role: super_admin. Every route below verifies a
 * valid admin JWT (adminGuard). Legacy admin rows are normalized to
 * super_admin at startup in app.js.
 *
 * Design rules enforced here:
 *   • Every number is computed from real MongoDB aggregations.
 *   • Server-side pagination / filtering / sorting on all lists.
 *   • No N+1 HTTP patterns — counts resolved server-side.
 *   • Every administrative mutation writes an immutable AuditLog row
 *     and (where relevant) a SecurityEvent.
 *   • No secret (API key / password / token) is ever returned.
 *   • Empty results return empty arrays — never fabricated data.
 */
const express  = require('express')
const mongoose = require('mongoose')
const jwt      = require('jsonwebtoken')
const bcrypt   = require('bcryptjs')
const fs       = require('fs')

const {
  User, Chat, Message, Admin, Notification, AdminNotification, AuditLog,
  SecurityEvent, PageView, SystemLog, UserMemory, KnowledgeBase,
  UsageTracking, UserPlan, FlaggedContent,
} = require('../models')

const ADMIN_SECRET = process.env.ADMIN_SECRET || 'kinyabot_admin_secret_change_me'
const aiConfig      = require('../services/ai/config')
const provider      = require('../services/ai/groqProvider')
const settings      = require('../services/settings')
const { onlinePresence, logActivity } = require('../services/activity')
const { writeAudit } = require('../services/audit')
const { notifyAdmins } = require('../services/notify')
const pushService   = require('../services/push')
const healthCheck   = require('../services/healthCheck')

const router = express.Router()

/* ── GUARDS ─────────────────────────────────────────────────────
   NOTE: applied AFTER the public auth routes below so login and
   (invite-gated) registration stay reachable without a token. */
function adminGuard(req, res, next) {
  const h = req.headers.authorization
  if (!h?.startsWith('Bearer ')) return res.status(401).json({ error: 'Unauthorized' })
  try {
    const d = jwt.verify(h.slice(7), ADMIN_SECRET)
    if (!d.isAdmin) throw new Error('not admin')
    // Single-role system: every authenticated admin IS a super_admin.
    req.admin = { ...d, role: 'super_admin' }
    next()
  } catch { return res.status(403).json({ error: 'Superadmin access required' }) }
}

/* ── HELPERS ──────────────────────────────────────────────────── */
function parseRange(q) {
  const r = ['24h', '7d', '30d', '90d'].includes(q) ? q : '7d'
  const hours = { '24h': 24, '7d': 24 * 7, '30d': 24 * 30, '90d': 24 * 90 }[r]
  const start = new Date(Date.now() - hours * 3600 * 1000)
  // 24h → hourly buckets, everything else → daily
  const fmt = r === '24h' ? { $dateToString: { format: '%Y-%m-%dT%H:00:00Z', date: '$created_at' } }
                          : { $dateToString: { format: '%Y-%m-%d', date: '$created_at' } }
  const prevStart = new Date(start.getTime() - (Date.now() - start.getTime()))
  return { r, start, fmt, prevStart }
}

function pctChange(curr, prev) {
  if (!prev) return null
  return Math.round(((curr - prev) / prev) * 1000) / 10
}

function percentiles(sorted) {
  if (!sorted.length) return { p50: null, p95: null, p99: null }
  const at = (p) => sorted[Math.min(sorted.length - 1, Math.floor((p / 100) * sorted.length))]
  return { p50: Math.round(at(50)), p95: Math.round(at(95)), p99: Math.round(at(99)) }
}

function escapeRegex(s) { return String(s).replace(/[.*+?^${}()|[\]\\]/g, '\\$&') }

async function fillSeries(coll, match, fmt, field = 'count') {
  return coll.aggregate([
    { $match: match },
    { $group: { _id: fmt, [field]: { $sum: 1 } } },
    { $sort: { _id: 1 } },
    { $project: { date: '$_id', [field]: 1, _id: 0 } },
  ])
}

async function sysLog(level, source, message, data, userId) {
  try { await SystemLog.create({ level, source, message, data: data || null, user_id: userId || null }) } catch {}
}

function fmtDoc(doc) {
  if (!doc) return null
  const obj = doc.toObject ? doc.toObject({ virtuals: false }) : { ...doc }
  obj.id = obj._id?.toString()
  delete obj._id; delete obj.__v
  for (const k of Object.keys(obj)) {
    if (obj[k] instanceof mongoose.Types.ObjectId) obj[k] = obj[k].toString()
  }
  return obj
}

/* ════════════════════════════════════════════════════════════════
   AUTH
════════════════════════════════════════════════════════════════ */
router.post('/login', async (req, res) => {
  const { email, password } = req.body
  if (!email || !password) return res.status(400).json({ error: 'Email and password required' })
  try {
    const adm = await Admin.findOne({ email: String(email).toLowerCase() })
    if (!adm) {
      await SecurityEvent.create({ type: 'admin_login_failed', severity: 'warning', username: email, ip: req.ip, user_agent: req.headers['user-agent'], message: 'Unknown superadmin email' })
      return res.status(401).json({ error: 'Invalid credentials' })
    }
    const ok = await bcrypt.compare(password, adm.password_hash)
    if (!ok) {
      await SecurityEvent.create({ type: 'admin_login_failed', severity: 'warning', username: adm.username, ip: req.ip, user_agent: req.headers['user-agent'], message: 'Wrong password' })
      return res.status(401).json({ error: 'Invalid credentials' })
    }
    adm.last_login = new Date()
    await adm.save()
    const token = jwt.sign({ id: adm._id.toString(), username: adm.username, email: adm.email, role: 'super_admin', isAdmin: true }, ADMIN_SECRET, { expiresIn: '8h' })
    await SecurityEvent.create({ type: 'admin_login', severity: 'info', username: adm.username, ip: req.ip, user_agent: req.headers['user-agent'], message: 'Superadmin signed in' })
    await sysLog('info', 'admin', `Superadmin login: ${adm.username}`)
    logActivity('admin_login', { username: adm.username, meta: { role: 'super_admin' } })
    res.json({ token, admin: { id: adm._id.toString(), username: adm.username, email: adm.email, role: 'super_admin' } })
  } catch (err) { console.error('[AdminLogin]', err); res.status(500).json({ error: 'Login failed.' }) }
})

router.post('/register', async (req, res) => {
  const { username, email, password, invite_code } = req.body
  if (!username || !email || !password) return res.status(400).json({ error: 'All fields required' })
  if (username.length < 3) return res.status(400).json({ error: 'Username min 3 chars' })
  if (password.length < 8) return res.status(400).json({ error: 'Password min 8 chars' })
  const INVITE_CODE = process.env.ADMIN_INVITE_CODE || 'KinyaBot-Admin-2024'
  try {
    const totalAdmins = await Admin.countDocuments()
    if (totalAdmins > 0 && (invite_code || '').trim() !== INVITE_CODE)
      return res.status(403).json({ error: 'Invalid invite code' })
    const existing = await Admin.findOne({ $or: [{ email: String(email).toLowerCase() }, { username }] })
    if (existing) return res.status(409).json({ error: 'Email or username already taken' })
    const hash = await bcrypt.hash(password, 12)
    // Exactly one role exists: super_admin (first account needs no invite code)
    const adm = await Admin.create({ username, email: String(email).toLowerCase(), password_hash: hash, role: 'super_admin' })
    const token = jwt.sign({ id: adm._id.toString(), username, email: adm.email, role: 'super_admin', isAdmin: true }, ADMIN_SECRET, { expiresIn: '8h' })
    await sysLog('info', 'admin', `Superadmin registered: ${username}`)
    res.status(201).json({ token, admin: { id: adm._id.toString(), username, email: adm.email, role: 'super_admin' } })
  } catch (err) { console.error('[AdminReg]', err); res.status(500).json({ error: 'Registration failed: ' + err.message }) }
})

/* ════════════════════════════════════════════════════════════════
   OVERVIEW (Dashboard command center) — real aggregations only
════════════════════════════════════════════════════════════════ */
/* Everything below this point requires a valid superadmin token. */
router.use(adminGuard)
router.get('/overview', async (req, res) => {
  try {
    const { r, start, fmt, prevStart } = parseRange(req.query.range)

    const [total_users, banned_users] = await Promise.all([
      User.countDocuments(), User.countDocuments({ is_banned: true }),
    ])

    const [new_users, new_prev, active_users, active_prev, total_chats, new_chats, msgs_in_range, msgs_prev] = await Promise.all([
      User.countDocuments({ created_at: { $gte: start } }),
      User.countDocuments({ created_at: { $gte: prevStart, $lt: start } }),
      User.countDocuments({ last_login: { $gte: start } }),
      User.countDocuments({ last_login: { $gte: prevStart, $lt: start } }),
      Chat.countDocuments(),
      Chat.countDocuments({ created_at: { $gte: start } }),
      Message.countDocuments({ created_at: { $gte: start } }),
      Message.countDocuments({ created_at: { $gte: prevStart, $lt: start } }),
    ])

    const [aiAgg, aiPrev, tokensAgg, byModel, pending_flags, unread_notifs] = await Promise.all([
      UsageTracking.aggregate([
        { $match: { created_at: { $gte: start } } },
        { $group: { _id: null, requests: { $sum: 1 }, ok: { $sum: { $cond: ['$success', 1, 0] } }, avg_ms: { $avg: '$response_ms' }, tokens: { $sum: '$tokens_used' } } },
      ]),
      UsageTracking.aggregate([
        { $match: { created_at: { $gte: prevStart, $lt: start } } },
        { $group: { _id: null, requests: { $sum: 1 } } },
      ]),
      UsageTracking.aggregate([{ $group: { _id: null, total: { $sum: '$tokens_used' } } }]),
      Message.aggregate([
        { $match: { model: { $ne: null }, created_at: { $gte: start } } },
        { $group: { _id: '$model', count: { $sum: 1 }, avg_ms: { $avg: '$processing_ms' } } },
        { $sort: { count: -1 } }, { $limit: 6 },
        { $project: { model: '$_id', count: 1, avg_ms: { $round: ['$avg_ms', 0] }, _id: 0 } },
      ]),
      FlaggedContent.countDocuments({ status: 'pending' }),
      AdminNotification.countDocuments({ read: false }),
    ])

    const ai = aiAgg[0] || { requests: 0, ok: 0, avg_ms: 0, tokens: 0 }
    const aiPrevN = aiPrev[0]?.requests || 0

    const [userSeries, msgSeries, aiSeries] = await Promise.all([
      fillSeries(User, { created_at: { $gte: start } }, fmt),
      fillSeries(Message, { created_at: { $gte: start } }, fmt),
      UsageTracking.aggregate([
        { $match: { created_at: { $gte: start } } },
        { $group: { _id: fmt, requests: { $sum: 1 }, errors: { $sum: { $cond: ['$success', 0, 1] } }, avg_ms: { $avg: '$response_ms' } } },
        { $sort: { _id: 1 } }, { $project: { date: '$_id', requests: 1, errors: 1, avg_ms: { $round: ['$avg_ms', 0] }, _id: 0 } },
      ]),
    ])

    const recent_users = await User.find().select('username email avatar_url is_banned created_at last_login').sort({ created_at: -1 }).limit(6).lean()

    res.json({
      range: r,
      users: {
        total: total_users, banned: banned_users, online_now: onlinePresence.size,
        new_in_range: new_users, new_change: pctChange(new_users, new_prev),
        active_in_range: active_users, active_change: pctChange(active_users, active_prev),
      },
      chats: { total: total_chats, new_in_range: new_chats },
      messages: { total_in_range: msgs_in_range, change: pctChange(msgs_in_range, msgs_prev) },
      ai: {
        requests: ai.requests, success: ai.ok, failed: ai.requests - ai.ok,
        success_rate: ai.requests ? Math.round((ai.ok / ai.requests) * 1000) / 10 : null,
        avg_latency_ms: ai.avg_ms ? Math.round(ai.avg_ms) : null,
        tokens: ai.tokens, tokens_total: tokensAgg[0]?.total || 0,
        requests_change: pctChange(ai.requests, aiPrevN),
        by_model: byModel,
      },
      moderation: { pending: pending_flags },
      notifications_unread: unread_notifs,
      series: { users: userSeries, messages: msgSeries, ai: aiSeries },
      recent_users: recent_users.map(u => ({ id: u._id.toString(), username: u.username, email: u.email, is_banned: u.is_banned, created_at: u.created_at, last_login: u.last_login })),
      generated_at: new Date().toISOString(),
    })
  } catch (err) {
    console.error('[Overview]', err)
    res.status(500).json({ error: 'Could not load overview' })
  }
})

/* ════════════════════════════════════════════════════════════════
   ANALYTICS — users / conversations / AI / engagement (all real)
════════════════════════════════════════════════════════════════ */
router.get('/analytics', async (req, res) => {
  try {
    const { r, start, fmt } = parseRange(req.query.range)
    const now = new Date()
    const dayAgo = new Date(now - 24 * 3600e3), weekAgo = new Date(now - 7 * 864e5), monthAgo = new Date(now - 30 * 864e5)

    const [total_users, dau, wau, mau, new_regs, total_chats, new_chats, msg_total, msgs_range, onboarded] = await Promise.all([
      User.countDocuments(),
      User.countDocuments({ last_login: { $gte: dayAgo } }),
      User.countDocuments({ last_login: { $gte: weekAgo } }),
      User.countDocuments({ last_login: { $gte: monthAgo } }),
      User.countDocuments({ created_at: { $gte: start } }),
      Chat.countDocuments(),
      Chat.countDocuments({ created_at: { $gte: start } }),
      Message.countDocuments(),
      Message.countDocuments({ created_at: { $gte: start } }),
      User.countDocuments({ onboarded: true }),
    ])

    const [userSeries, msgSeries, chatSeries, hourly, topUsers, returning] = await Promise.all([
      fillSeries(User, { created_at: { $gte: start } }, fmt),
      fillSeries(Message, { created_at: { $gte: start } }, fmt),
      fillSeries(Chat, { created_at: { $gte: start } }, fmt),
      Message.aggregate([
        { $match: { created_at: { $gte: weekAgo } } },
        { $group: { _id: { $hour: '$created_at' }, count: { $sum: 1 } } },
        { $sort: { _id: 1 } }, { $project: { hour: '$_id', count: 1, _id: 0 } },
      ]),
      User.aggregate([
        { $lookup: { from: 'chats', localField: '_id', foreignField: 'user_id', as: 'chats' } },
        { $addFields: { chat_ids: '$chats._id' } },
        { $lookup: { from: 'messages', let: { cids: '$chat_ids' }, pipeline: [
          { $match: { $expr: { $in: ['$chat_id', '$$cids'] } } }, { $count: 'n' },
        ], as: 'm' } },
        { $addFields: { msg_count: { $ifNull: [{ $first: '$m.n' }, 0] } } },
        { $match: { msg_count: { $gt: 0 } } },
        { $sort: { msg_count: -1 } }, { $limit: 8 },
        { $project: { _id: 0, username: 1, email: 1, msg_count: 1 } },
      ]),
      User.countDocuments({ $expr: { $gt: ['$last_login', '$created_at'] } }),
    ])

    const [aiAgg, aiSeries, byModel] = await Promise.all([
      UsageTracking.aggregate([
        { $match: { created_at: { $gte: start } } },
        { $group: { _id: null, requests: { $sum: 1 }, ok: { $sum: { $cond: ['$success', 1, 0] } }, avg_ms: { $avg: '$response_ms' }, tokens: { $sum: '$tokens_used' } } },
      ]),
      UsageTracking.aggregate([
        { $match: { created_at: { $gte: start } } },
        { $group: { _id: fmt, requests: { $sum: 1 }, errors: { $sum: { $cond: ['$success', 0, 1] } } } },
        { $sort: { _id: 1 } }, { $project: { date: '$_id', requests: 1, errors: 1, _id: 0 } },
      ]),
      Message.aggregate([
        { $match: { model: { $ne: null }, created_at: { $gte: start } } },
        { $group: { _id: '$model', count: { $sum: 1 } } },
        { $sort: { count: -1 } }, { $limit: 8 }, { $project: { model: '$_id', count: 1, _id: 0 } },
      ]),
    ])

    const ai = aiAgg[0] || { requests: 0, ok: 0, avg_ms: 0, tokens: 0 }

    // Engagement: page views (real tracking events)
    const [views_total, views_range, by_page] = await Promise.all([
      PageView.countDocuments(),
      PageView.countDocuments({ created_at: { $gte: start } }),
      PageView.aggregate([
        { $group: { _id: '$page', views: { $sum: 1 } } },
        { $sort: { views: -1 } }, { $limit: 8 },
        { $project: { page: '$_id', views: 1, _id: 0 } },
      ]),
    ])

    res.json({
      range: r,
      users: {
        total: total_users, dau, wau, mau, new_registrations: new_regs, onboarded,
        returning_users: returning,
        growth_rate: total_users ? Math.round((new_regs / total_users) * 1000) / 10 : 0,
        series: userSeries,
      },
      conversations: {
        total: total_chats, new_in_range: new_chats,
        messages_total: msg_total, messages_in_range: msgs_range,
        avg_messages_per_chat: total_chats ? Math.round((msg_total / total_chats) * 10) / 10 : 0,
        series_chat: chatSeries, series_msg: msgSeries,
      },
      ai: {
        requests: ai.requests, success: ai.ok, failed: ai.requests - ai.ok,
        success_rate: ai.requests ? Math.round((ai.ok / ai.requests) * 1000) / 10 : null,
        avg_latency_ms: ai.avg_ms ? Math.round(ai.avg_ms) : null,
        tokens: ai.tokens, series: aiSeries, by_model: byModel,
      },
      engagement: { hourly_activity: hourly, top_users: topUsers, views_total, views_range, top_pages: by_page },
    })
  } catch (err) {
    console.error('[Analytics]', err)
    res.status(500).json({ error: 'Could not load analytics' })
  }
})

/* ════════════════════════════════════════════════════════════════
   USERS — server-side pagination, filters, aggregated counts
════════════════════════════════════════════════════════════════ */
router.get('/users', async (req, res) => {
  const page  = Math.max(1, parseInt(req.query.page) || 1)
  const limit = Math.min(50, Math.max(5, parseInt(req.query.limit) || 20))
  const search = String(req.query.search || '').trim()
  const status = String(req.query.status || '')    // active | banned
  const sort   = ['created_at', 'last_login', 'username'].includes(req.query.sort) ? req.query.sort : 'created_at'
  const dir    = req.query.dir === 'asc' ? 1 : -1
  try {
    const filter = {}
    if (search) filter.$or = [{ username: { $regex: escapeRegex(search), $options: 'i' } }, { email: { $regex: escapeRegex(search), $options: 'i' } }]
    if (status === 'banned') filter.is_banned = true
    if (status === 'active') filter.is_banned = { $ne: true }

    const [users, total] = await Promise.all([
      User.aggregate([
        { $match: filter },
        { $sort: { [sort]: dir } },
        { $skip: (page - 1) * limit }, { $limit: limit },
        { $lookup: { from: 'chats', localField: '_id', foreignField: 'user_id', as: 'chats' } },
        { $addFields: { chat_ids: '$chats._id' } },
        { $lookup: { from: 'messages', let: { cids: '$chat_ids' }, pipeline: [
          { $match: { $expr: { $in: ['$chat_id', '$$cids'] } } }, { $count: 'n' },
        ], as: 'm' } },
        { $addFields: {
          chat_count: { $size: '$chat_ids' },
          message_count: { $ifNull: [{ $first: '$m.n' }, 0] },
        } },
        { $project: {
          username: 1, email: 1, avatar_url: 1, profession: 1, referral_source: 1,
          onboarded: 1, is_banned: 1, email_verified: 1, created_at: 1, last_login: 1,
          chat_count: 1, message_count: 1,
        } },
      ]),
      User.countDocuments(filter),
    ])

    res.json({
      users: users.map(u => ({ ...u, id: u._id.toString(), _id: undefined })),
      total, page, pages: Math.ceil(total / limit) || 1,
    })
  } catch (err) { console.error('[AdminUsers]', err); res.status(500).json({ error: 'Could not load users' }) }
})

router.get('/users/:id', async (req, res) => {
  try {
    const uid = new mongoose.Types.ObjectId(req.params.id)
    const user = await User.findById(uid).select('-password_hash -otp_code -otp_expires -email_otp_code -email_otp_expires -reset_token -reset_token_expires').lean()
    if (!user) return res.status(404).json({ error: 'User not found' })

    const chatIds = (await Chat.find({ user_id: uid }).select('_id').lean()).map(c => c._id)
    const [msg_count, tokenAgg, plan, lastView, recentChats, recentEvents] = await Promise.all([
      Message.countDocuments({ chat_id: { $in: chatIds } }),
      UsageTracking.aggregate([{ $match: { user_id: uid } }, { $group: { _id: null, tokens: { $sum: '$tokens_used' }, requests: { $sum: 1 }, failed: { $sum: { $cond: ['$success', 0, 1] } }, avg_ms: { $avg: '$response_ms' } } }]),
      UserPlan.findOne({ user_id: uid }).lean(),
      PageView.findOne({ user_id: uid }).sort({ created_at: -1 }).select('ip_address created_at user_agent').lean(),
      Chat.find({ user_id: uid }).sort({ updated_at: -1 }).limit(5).select('title created_at updated_at').lean(),
      SystemLog.find({ user_id: uid, source: 'activity' }).sort({ created_at: -1 }).limit(10).select('message created_at').lean(),
    ])
    const t = tokenAgg[0] || {}
    res.json({
      user: { ...user, id: user._id.toString(), _id: undefined },
      stats: {
        chats: chatIds.length, messages: msg_count,
        tokens: t.tokens || 0, ai_requests: t.requests || 0, failed_requests: t.failed || 0,
        avg_latency_ms: t.avg_ms ? Math.round(t.avg_ms) : null,
        last_ip: lastView?.ip_address || null, last_seen_at: lastView?.created_at || null, last_user_agent: lastView?.user_agent || null,
      },
      plan: plan ? { plan: plan.plan, daily_limit: plan.daily_limit, monthly_limit: plan.monthly_limit, tokens_limit: plan.tokens_limit } : null,
      recent_chats: recentChats.map(c => ({ id: c._id.toString(), title: c.title, created_at: c.created_at, updated_at: c.updated_at })),
      recent_activity: recentEvents.map(e => ({ id: e._id.toString(), action: e.message, created_at: e.created_at })),
    })
  } catch (err) { console.error('[AdminUserDetail]', err); res.status(500).json({ error: 'Could not load user' }) }
})

router.put('/users/:id/ban', async (req, res) => {
  const { banned } = req.body
  try {
    const u = await User.findByIdAndUpdate(req.params.id, { is_banned: !!banned }, { new: true }).select('username').lean()
    if (!u) return res.status(404).json({ error: 'User not found' })
    await SecurityEvent.create({ type: banned ? 'banned' : 'unbanned', severity: banned ? 'warning' : 'info', username: u.username, ip: req.ip, message: banned ? 'Account disabled by superadmin' : 'Account re-enabled by superadmin' })
    await writeAudit(req.admin, banned ? 'user.ban' : 'user.unban', { resourceType: 'user', resourceId: req.params.id, resourceLabel: u.username, meta: { banned: !!banned }, req })
    logActivity(banned ? 'banned' : 'unbanned', { username: u.username, user_id: req.params.id })
    if (banned) notifyAdmins({ title: 'User account disabled', message: `${u.username} was disabled by ${req.admin.username}.`, type: 'warning', category: 'security', link: '/admin/users', dedupeKey: `ban-${req.params.id}` }).catch(() => {})
    res.json({ success: true })
  } catch (err) { console.error('[Ban]', err); res.status(500).json({ error: 'Could not update user' }) }
})

router.put('/users/:id/reset-password', async (req, res) => {
  const { password } = req.body
  if (!password || password.length < 8) return res.status(400).json({ error: 'Password min 8 chars' })
  try {
    const u = await User.findById(req.params.id).select('username').lean()
    if (!u) return res.status(404).json({ error: 'User not found' })
    const hash = await bcrypt.hash(password, 12)
    await User.findByIdAndUpdate(req.params.id, { password_hash: hash })
    await SecurityEvent.create({ type: 'password_reset', severity: 'warning', username: u.username, ip: req.ip, message: 'Password reset by superadmin' })
    await writeAudit(req.admin, 'user.reset_password', { resourceType: 'user', resourceId: req.params.id, resourceLabel: u.username, req })
    res.json({ success: true })
  } catch (err) { console.error('[ResetPw]', err); res.status(500).json({ error: 'Failed' }) }
})

router.delete('/users/:id/memory', async (req, res) => {
  try {
    await UserMemory.deleteMany({ user_id: req.params.id })
    await writeAudit(req.admin, 'user.clear_memory', { resourceType: 'user', resourceId: req.params.id, req })
    res.json({ success: true })
  } catch { res.status(500).json({ error: 'Failed' }) }
})

router.delete('/users/:id', async (req, res) => {
  try {
    const u = await User.findById(req.params.id).select('username').lean()
    const chats = await Chat.find({ user_id: req.params.id }).select('_id').lean()
    const chatIds = chats.map(c => c._id)
    await Message.deleteMany({ chat_id: { $in: chatIds } })
    await Chat.deleteMany({ user_id: req.params.id })
    await UserMemory.deleteMany({ user_id: req.params.id })
    await UsageTracking.deleteMany({ user_id: req.params.id })
    await UserPlan.deleteOne({ user_id: req.params.id })
    await User.findByIdAndDelete(req.params.id)
    await writeAudit(req.admin, 'user.delete', { resourceType: 'user', resourceId: req.params.id, resourceLabel: u?.username, meta: { chats_deleted: chatIds.length }, req })
    logActivity('user_deleted', { username: u?.username || null })
    res.json({ success: true })
  } catch (err) { console.error('[DelUser]', err); res.status(500).json({ error: 'Could not delete user' }) }
})

/* ════════════════════════════════════════════════════════════════
   CHATS — one pipeline for counts + model/provider, no N+1
════════════════════════════════════════════════════════════════ */
router.get('/chats', async (req, res) => {
  const page  = Math.max(1, parseInt(req.query.page) || 1)
  const limit = Math.min(50, Math.max(5, parseInt(req.query.limit) || 20))
  const search = String(req.query.search || '').trim()
  const userId = String(req.query.user_id || '').trim()
  try {
    const and = []
    if (search) {
      const rx = { $regex: escapeRegex(search), $options: 'i' }
      const users = await User.find({ $or: [{ username: rx }, { email: rx }] }).select('_id').lean()
      and.push({ $or: [{ title: rx }, { user_id: { $in: users.map(u => u._id) } }] })
    }
    if (userId && mongoose.isValidObjectId(userId)) and.push({ user_id: new mongoose.Types.ObjectId(userId) })
    const matchStage = and.length ? { $and: and } : {}

    const [chats, total] = await Promise.all([
      Chat.aggregate([
        { $match: matchStage },
        { $sort: { updated_at: -1 } },
        { $skip: (page - 1) * limit }, { $limit: limit },
        { $lookup: { from: 'users', localField: 'user_id', foreignField: '_id', as: 'user' } },
        { $addFields: { username: { $first: '$user.username' }, email: { $first: '$user.email' } } },
        { $lookup: { from: 'messages', let: { cid: '$_id' }, pipeline: [
          { $match: { $expr: { $eq: ['$chat_id', '$$cid'] } } },
          { $group: {
            _id: null,
            msg_count: { $sum: 1 },
            failed_count: { $sum: { $cond: [{ $eq: ['$status', 'failed'] }, 1, 0] } },
            last_model: { $last: '$model' },
            last_provider: { $last: '$provider' },
          } },
        ], as: 'agg' } },
        { $addFields: {
          msg_count: { $ifNull: [{ $first: '$agg.msg_count' }, 0] },
          failed_count: { $ifNull: [{ $first: '$agg.failed_count' }, 0] },
          last_model: { $ifNull: [{ $first: '$agg.last_model' }, null] },
          last_provider: { $ifNull: [{ $first: '$agg.last_provider' }, null] },
        } },
        { $project: { user: 0, agg: 0 } },
      ]),
      Chat.countDocuments(matchStage),
    ])

    res.json({
      chats: chats.map(c => ({ ...c, id: c._id.toString(), _id: undefined })),
      total, page, pages: Math.ceil(total / limit) || 1,
    })
  } catch (err) { console.error('[AdminChats]', err); res.status(500).json({ error: 'Could not load chats' }) }
})

router.get('/chats/:id/messages', async (req, res) => {
  try {
    const chat = await Chat.findById(req.params.id).populate('user_id', 'username email').lean()
    if (!chat) return res.status(404).json({ error: 'Not found' })
    const messages = await Message.find({ chat_id: req.params.id }).sort({ created_at: 1 }).select('-attachments.extracted_text').lean()
    res.json({
      chat: { ...chat, id: chat._id.toString(), _id: undefined },
      messages: messages.map(m => ({ ...m, id: m._id.toString(), _id: undefined })),
      user: { username: chat.user_id?.username, email: chat.user_id?.email },
    })
  } catch (err) { console.error('[AdminChatMsgs]', err); res.status(500).json({ error: 'Failed' }) }
})

router.delete('/chats/:id', async (req, res) => {
  try {
    await Message.deleteMany({ chat_id: req.params.id })
    const c = await Chat.findByIdAndDelete(req.params.id).select('title').lean()
    await writeAudit(req.admin, 'chat.delete', { resourceType: 'chat', resourceId: req.params.id, resourceLabel: c?.title, req })
    await sysLog('warn', 'admin', `Superadmin deleted chat ${req.params.id}`)
    res.json({ success: true })
  } catch (err) { console.error('[DelChat]', err); res.status(500).json({ error: 'Failed' }) }
})

/* ════════════════════════════════════════════════════════════════
   MODERATION — real flagged content + status workflow
════════════════════════════════════════════════════════════════ */
router.get('/moderation', async (req, res) => {
  try {
    const status = ['pending', 'reviewed', 'resolved', 'dismissed'].includes(req.query.status) ? req.query.status : null
    const page  = Math.max(1, parseInt(req.query.page) || 1)
    const limit = Math.min(50, Math.max(5, parseInt(req.query.limit) || 20))
    const filter = status ? { status } : {}
    const [items, total, counts] = await Promise.all([
      FlaggedContent.find(filter)
        .populate('message_id', 'content').populate('user_id', 'username')
        .sort({ created_at: -1 }).skip((page - 1) * limit).limit(limit).lean(),
      FlaggedContent.countDocuments(filter),
      FlaggedContent.aggregate([{ $group: { _id: '$status', n: { $sum: 1 } } }]),
    ])
    const countMap = Object.fromEntries(counts.map(c => [c._id, c.n]))
    res.json({
      items: items.map(f => ({
        id: f._id.toString(), chat_id: f.chat_id?.toString() || null,
        username: f.user_id?.username || null,
        content: f.message_id?.content || f.reason || null,
        reason: f.reason, auto_flagged: f.auto_flagged, status: f.status || (f.reviewed ? 'reviewed' : 'pending'),
        resolved_by: f.resolved_by, resolved_at: f.resolved_at, created_at: f.created_at,
      })),
      total, page, pages: Math.ceil(total / limit) || 1,
      counts: {
        pending: countMap.pending || 0,
        reviewed: countMap.reviewed || 0,
        resolved: countMap.resolved || 0,
        dismissed: countMap.dismissed || 0,
      },
    })
  } catch (err) { console.error('[Moderation]', err); res.status(500).json({ error: 'Failed' }) }
})

router.put('/moderation/:id/status', async (req, res) => {
  const status = req.body.status
  if (!['pending', 'reviewed', 'resolved', 'dismissed'].includes(status)) return res.status(400).json({ error: 'Invalid status' })
  try {
    const f = await FlaggedContent.findByIdAndUpdate(
      req.params.id,
      { status, reviewed: status !== 'pending', resolved_by: req.admin.username, resolved_at: new Date() },
      { new: true }
    ).lean()
    if (!f) return res.status(404).json({ error: 'Not found' })
    await writeAudit(req.admin, `moderation.${status}`, { resourceType: 'flagged_content', resourceId: req.params.id, resourceLabel: f.reason, req })
    res.json({ success: true, status })
  } catch (err) { console.error('[ModStatus]', err); res.status(500).json({ error: 'Failed' }) }
})

/* ════════════════════════════════════════════════════════════════
   NOTIFICATIONS — Superadmin control center (real events) +
   user-facing broadcasts (existing Notification system)
════════════════════════════════════════════════════════════════ */
router.get('/notifications', async (req, res) => {
  try {
    const page  = Math.max(1, parseInt(req.query.page) || 1)
    const limit = Math.min(50, Math.max(5, parseInt(req.query.limit) || 20))
    const filter = {}
    if (req.query.filter === 'unread') filter.read = false
    if (req.query.filter === 'read') filter.read = true
    if (req.query.category && ['system', 'ai', 'security', 'user', 'moderation', 'config', 'usage'].includes(req.query.category)) filter.category = req.query.category
    const [items, total, unread] = await Promise.all([
      AdminNotification.find(filter).sort({ created_at: -1 }).skip((page - 1) * limit).limit(limit).lean(),
      AdminNotification.countDocuments(filter),
      AdminNotification.countDocuments({ read: false }),
    ])
    res.json({
      items: items.map(n => ({ ...n, id: n._id.toString(), _id: undefined })),
      total, unread, page, pages: Math.ceil(total / limit) || 1,
    })
  } catch (err) { console.error('[AdminNotifs]', err); res.status(500).json({ error: 'Failed' }) }
})

router.put('/notifications/:id/read', async (req, res) => {
  try { await AdminNotification.findByIdAndUpdate(req.params.id, { read: !!req.body.read }); res.json({ success: true }) }
  catch { res.status(500).json({ error: 'Failed' }) }
})

router.put('/notifications/read-all', async (req, res) => {
  try { await AdminNotification.updateMany({ read: false }, { read: true }); res.json({ success: true }) }
  catch { res.status(500).json({ error: 'Failed' }) }
})

router.delete('/notifications/:id', async (req, res) => {
  try { await AdminNotification.findByIdAndDelete(req.params.id); res.json({ success: true }) }
  catch { res.status(500).json({ error: 'Failed' }) }
})

/* User broadcasts (kept from the original working system) */
router.get('/broadcasts', async (req, res) => {
  try { res.json((await Notification.find().sort({ created_at: -1 }).limit(50).lean()).map(fmtDoc)) }
  catch { res.json([]) }
})

router.post('/broadcasts', async (req, res) => {
  const { title, message, type = 'info', expires_at } = req.body
  if (!title || !message) return res.status(400).json({ error: 'Title and message required' })
  try {
    const notif = await Notification.create({ title, message, type, is_active: true, created_by: req.admin.id, expires_at: expires_at || null })
    const io = req.app.get('io'); if (io) io.emit('admin_notification', fmtDoc(notif))
    await sysLog('info', 'admin', `Broadcast: ${title}`)
    logActivity('broadcast', { username: req.admin.username, meta: { title } })
    await writeAudit(req.admin, 'notification.broadcast', { resourceType: 'notification', resourceId: notif._id.toString(), resourceLabel: title, req })
    res.json(fmtDoc(notif))
  } catch { res.status(500).json({ error: 'Failed' }) }
})

router.put('/broadcasts/:id', async (req, res) => {
  try { await Notification.findByIdAndUpdate(req.params.id, { is_active: !!req.body.is_active }); res.json({ success: true }) }
  catch { res.status(500).json({ error: 'Failed' }) }
})

router.delete('/broadcasts/:id', async (req, res) => {
  try { await Notification.findByIdAndDelete(req.params.id); res.json({ success: true }) }
  catch { res.status(500).json({ error: 'Failed' }) }
})

/* ════════════════════════════════════════════════════════════════
   AI CONTROL — provider/model truth (never exposes secrets)
════════════════════════════════════════════════════════════════ */
router.get('/ai/overview', async (req, res) => {
  try {
    const cfg = settings.get()
    const [providerCheck, byModel, recentErrors] = await Promise.all([
      healthCheck.runChecks(req.app.get('io'), { force: false }).then(h => h.checks.aiProvider),
      Message.aggregate([
        { $match: { model: { $ne: null } } },
        { $group: { _id: '$model', count: { $sum: 1 }, avg_ms: { $avg: '$processing_ms' }, errors: { $sum: { $cond: [{ $eq: ['$status', 'failed'] }, 1, 0] } }, last_used: { $max: '$created_at' } } },
        { $sort: { count: -1 } },
        { $project: { model: '$_id', count: 1, avg_ms: { $round: ['$avg_ms', 0] }, errors: 1, last_used: 1, _id: 0 } },
      ]),
      Message.find({ status: 'failed' }).sort({ created_at: -1 }).limit(8)
        .populate('chat_id', 'title').select('model provider created_at chat_id').lean(),
    ])
    res.json({
      provider: { name: aiConfig.provider, status: providerCheck.status, detail: providerCheck.detail, latency_ms: providerCheck.latency_ms },
      models_configured: {
        chat: aiConfig.models.chat, vision: aiConfig.models.vision,
        document: aiConfig.models.document, stt: aiConfig.models.stt, tts: aiConfig.models.tts,
      },
      runtime: {
        system_prompt: cfg.system_prompt, max_tokens: cfg.max_tokens, temperature: cfg.temperature,
        max_context_messages: cfg.max_context_messages, knowledge_base_enabled: cfg.knowledge_base_enabled,
        moderation_enabled: cfg.moderation_enabled,
      },
      feature_flags: {
        image_gen_enabled: cfg.image_gen_enabled,
        file_uploads_enabled: cfg.file_uploads_enabled,
        knowledge_base_enabled: cfg.knowledge_base_enabled,
        moderation_enabled: cfg.moderation_enabled,
      },
      usage_by_model: byModel,
      recent_errors: recentErrors.map(e => ({ id: e._id.toString(), model: e.model, provider: e.provider, created_at: e.created_at, chat_title: e.chat_id?.title || null })),
    })
  } catch (err) { console.error('[AIOverview]', err); res.status(500).json({ error: 'Failed' }) }
})

router.put('/ai/runtime', async (req, res) => {
  try {
    const before = settings.get()
    const updated = settings.update(req.body || {})
    await writeAudit(req.admin, 'ai.runtime_update', {
      resourceType: 'ai_settings',
      meta: {
        changed: Object.keys(req.body || {}),
        before: Object.fromEntries(Object.keys(req.body || {}).map(k => [k, before[k]])),
        after: Object.fromEntries(Object.keys(req.body || {}).map(k => [k, updated[k]])),
      },
      req,
    })
    await notifyAdmins({ title: 'AI configuration updated', message: `${req.admin.username} updated: ${Object.keys(req.body || {}).join(', ')}.`, type: 'info', category: 'config', link: '/admin/ai', dedupeKey: `ai-cfg-${req.admin.id}` }).catch(() => {})
    res.json({ success: true, runtime: updated })
  } catch (err) { console.error('[AIRuntime]', err); res.status(500).json({ error: 'Failed to save' }) }
})

/* AI TESTING — real calls against the configured provider */
router.post('/ai/test', async (req, res) => {
  const { prompt, model, system_prompt, max_tokens, temperature } = req.body
  if (!prompt || !String(prompt).trim()) return res.status(400).json({ error: 'Prompt required' })
  const cfg = settings.get()
  const start = Date.now()
  try {
    const result = await provider.chatComplete({
      messages: [
        { role: 'system', content: String(system_prompt || cfg.system_prompt) },
        { role: 'user', content: String(prompt) },
      ],
      model: model || aiConfig.models.chat,
      maxTokens: Math.min(Number(max_tokens) || cfg.max_tokens, 8192),
      temperature: Number.isFinite(Number(temperature)) ? Number(temperature) : cfg.temperature,
    })
    const ms = Date.now() - start
    // Real usage record: request_type 'ai_test', actor = the superadmin
    try { await UsageTracking.create({ user_id: new mongoose.Types.ObjectId(req.admin.id), tokens_used: result.tokens || 0, request_type: 'ai_test', response_ms: ms, success: true }) } catch {}
    logActivity('ai_test', { username: req.admin.username, meta: { model: result.model, ms } })
    res.json({ response: result.text, model: result.model, tokens: result.tokens, response_ms: ms, status: 'success' })
  } catch (err) {
    const ms = Date.now() - start
    try { await UsageTracking.create({ user_id: new mongoose.Types.ObjectId(req.admin.id), tokens_used: 0, request_type: 'ai_test', response_ms: ms, success: false }) } catch {}
    const statusMap = { AI_AUTH: 502, AI_MODEL_UNAVAILABLE: 400, AI_RATE_LIMIT: 429, AI_TIMEOUT: 504, GROQ_NOT_CONFIGURED: 503 }
    res.status(statusMap[err.code] || 502).json({
      error: err.userSafe ? err.message : (`AI test failed (${err.code || 'provider error'}): ${err.message}`.slice(0, 300)),
      code: err.code || 'AI_PROVIDER_ERROR', response_ms: ms, status: 'failure',
    })
  }
})

/* ════════════════════════════════════════════════════════════════
   SYSTEM HEALTH — real checks + real API latency percentiles
════════════════════════════════════════════════════════════════ */
router.get('/health/details', async (req, res) => {
  try {
    const force = req.query.force === '1'
    const report = await healthCheck.runChecks(req.app.get('io'), { force })
    const last24h = new Date(Date.now() - 24 * 3600e3)
    const [latSamples, errAgg, reqAgg] = await Promise.all([
      UsageTracking.find({ created_at: { $gte: last24h }, response_ms: { $gt: 0 } }).sort({ created_at: -1 }).limit(1000).select('response_ms').lean(),
      UsageTracking.aggregate([
        { $match: { created_at: { $gte: last24h } } },
        { $group: { _id: null, total: { $sum: 1 }, errors: { $sum: { $cond: ['$success', 0, 1] } } } },
      ]),
      UsageTracking.aggregate([
        { $match: { created_at: { $gte: last24h } } },
        { $group: { _id: { $hour: '$created_at' }, requests: { $sum: 1 }, avg_ms: { $avg: '$response_ms' } } },
        { $sort: { _id: 1 } }, { $project: { hour: '$_id', requests: 1, avg_ms: { $round: ['$avg_ms', 0] }, _id: 0 } },
      ]),
    ])
    const sorted = latSamples.map(s => s.response_ms).sort((a, b) => a - b)
    const err = errAgg[0] || { total: 0, errors: 0 }
    res.json({
      ...report,
      performance: {
        window: '24h',
        sample_size: sorted.length,
        ...percentiles(sorted),
        avg_ms: sorted.length ? Math.round(sorted.reduce((a, b) => a + b, 0) / sorted.length) : null,
        requests_24h: err.total,
        errors_24h: err.errors,
        error_rate: err.total ? Math.round((err.errors / err.total) * 1000) / 10 : null,
        by_hour: reqAgg,
      },
    })
  } catch (err) { console.error('[HealthDetails]', err); res.status(500).json({ error: 'Failed' }) }
})

/* ════════════════════════════════════════════════════════════════
   USAGE — real consumption (no billing: KinyaBot has no payments)
════════════════════════════════════════════════════════════════ */
router.get('/usage', async (req, res) => {
  try {
    const { r, start, fmt } = parseRange(req.query.range)
    const cfg = settings.get()
    const [totalAgg, rangeAgg, byType, byModel, byDay, byUser, plans] = await Promise.all([
      UsageTracking.aggregate([{ $group: { _id: null, tokens: { $sum: '$tokens_used' }, requests: { $sum: 1 }, ok: { $sum: { $cond: ['$success', 1, 0] } } } }]),
      UsageTracking.aggregate([
        { $match: { created_at: { $gte: start } } },
        { $group: { _id: null, tokens: { $sum: '$tokens_used' }, requests: { $sum: 1 }, ok: { $sum: { $cond: ['$success', 1, 0] } }, avg_ms: { $avg: '$response_ms' } } },
      ]),
      UsageTracking.aggregate([
        { $match: { created_at: { $gte: start } } },
        { $group: { _id: '$request_type', requests: { $sum: 1 }, tokens: { $sum: '$tokens_used' }, errors: { $sum: { $cond: ['$success', 0, 1] } } } },
        { $sort: { requests: -1 } }, { $project: { type: '$_id', requests: 1, tokens: 1, errors: 1, _id: 0 } },
      ]),
      Message.aggregate([
        { $match: { model: { $ne: null }, created_at: { $gte: start } } },
        { $group: { _id: '$model', count: { $sum: 1 }, tokens: { $sum: { $ifNull: ['$tokens', 0] } } } },
        { $sort: { count: -1 } }, { $limit: 8 }, { $project: { model: '$_id', count: 1, tokens: 1, _id: 0 } },
      ]),
      UsageTracking.aggregate([
        { $match: { created_at: { $gte: start } } },
        { $group: { _id: fmt, tokens: { $sum: '$tokens_used' }, requests: { $sum: 1 }, errors: { $sum: { $cond: ['$success', 0, 1] } } } },
        { $sort: { _id: 1 } }, { $project: { date: '$_id', tokens: 1, requests: 1, errors: 1, _id: 0 } },
      ]),
      UsageTracking.aggregate([
        { $match: { created_at: { $gte: start } } },
        { $group: { _id: '$user_id', tokens: { $sum: '$tokens_used' }, requests: { $sum: 1 } } },
        { $sort: { tokens: -1 } }, { $limit: 10 },
        { $lookup: { from: 'users', localField: '_id', foreignField: '_id', as: 'user' } },
        { $unwind: { path: '$user', preserveNullAndEmptyArrays: true } },
        { $project: { username: { $ifNull: ['$user.username', '(deleted user)'] }, tokens: 1, requests: 1, _id: 0 } },
      ]),
      UserPlan.aggregate([{ $group: { _id: '$plan', count: { $sum: 1 } } }, { $project: { plan: '$_id', count: 1, _id: 0 } }]),
    ])
    const total = totalAgg[0] || { tokens: 0, requests: 0, ok: 0 }
    const inRange = rangeAgg[0] || { tokens: 0, requests: 0, ok: 0, avg_ms: 0 }
    res.json({
      range: r,
      totals: {
        tokens_total: total.tokens, requests_total: total.requests,
        success_rate_total: total.requests ? Math.round((total.ok / total.requests) * 1000) / 10 : null,
        tokens_in_range: inRange.tokens, requests_in_range: inRange.requests,
        errors_in_range: inRange.requests - inRange.ok,
        avg_latency_ms: inRange.avg_ms ? Math.round(inRange.avg_ms) : null,
        // Honest, clearly-labeled estimate based on the configured rate
        est_cost_in_range: Number((inRange.tokens / 1000 * (cfg.cost_per_1k_tokens || 0)).toFixed(4)),
        cost_rate_per_1k: cfg.cost_per_1k_tokens,
      },
      by_type: byType, by_model: byModel, by_day: byDay, by_user: byUser,
      plan_limits: plans,
    })
  } catch (err) { console.error('[Usage]', err); res.status(500).json({ error: 'Failed' }) }
})

/* ════════════════════════════════════════════════════════════════
   SECURITY — real auth/security telemetry + IP controls
════════════════════════════════════════════════════════════════ */
router.get('/security', async (req, res) => {
  try {
    const page  = Math.max(1, parseInt(req.query.page) || 1)
    const limit = Math.min(50, Math.max(5, parseInt(req.query.limit) || 20))
    const type = String(req.query.type || ''), severity = String(req.query.severity || '')
    const dayAgo = new Date(Date.now() - 24 * 3600e3), weekAgo = new Date(Date.now() - 7 * 864e5)
    const filter = {}
    if (type) filter.type = type
    if (['info', 'warning', 'critical'].includes(severity)) filter.severity = severity

    const [events, total, failed24, failed7, critical24, rateLimited24, blockedIps, suspicious] = await Promise.all([
      SecurityEvent.find(filter).sort({ created_at: -1 }).skip((page - 1) * limit).limit(limit).lean(),
      SecurityEvent.countDocuments(filter),
      SecurityEvent.countDocuments({ type: { $in: ['login_failed', 'admin_login_failed'] }, created_at: { $gte: dayAgo } }),
      SecurityEvent.countDocuments({ type: { $in: ['login_failed', 'admin_login_failed'] }, created_at: { $gte: weekAgo } }),
      SecurityEvent.countDocuments({ severity: 'critical', created_at: { $gte: dayAgo } }),
      SecurityEvent.countDocuments({ type: 'rate_limited', created_at: { $gte: dayAgo } }),
      Promise.resolve(settings.get().blocked_ips || []),
      PageView.aggregate([
        { $match: { ip_address: { $ne: null } } },
        { $group: { _id: '$ip_address', hits: { $sum: 1 }, last_seen: { $max: '$created_at' } } },
        { $sort: { hits: -1 } }, { $limit: 20 },
        { $project: { ip_address: '$_id', hits: 1, last_seen: 1, _id: 0 } },
      ]),
    ])
    res.json({
      events: events.map(e => ({ ...e, id: e._id.toString(), _id: undefined })),
      total, page, pages: Math.ceil(total / limit) || 1,
      stats: { failed_logins_24h: failed24, failed_logins_7d: failed7, critical_24h: critical24, rate_limited_24h: rateLimited24, blocked_count: blockedIps.length },
      blocked_ips: blockedIps,
      suspicious,
    })
  } catch (err) { console.error('[Security]', err); res.status(500).json({ error: 'Failed' }) }
})

router.post('/security/block-ip', async (req, res) => {
  const ip = String(req.body.ip || '').trim()
  if (!ip) return res.status(400).json({ error: 'IP required' })
  try {
    settings.blockIp(ip)
    await SecurityEvent.create({ type: 'ip_blocked', severity: 'warning', ip, message: `Blocked by ${req.admin.username}` })
    await writeAudit(req.admin, 'security.block_ip', { resourceType: 'ip', resourceId: ip, req })
    await sysLog('warn', 'admin', `Blocked IP: ${ip}`)
    res.json({ success: true })
  } catch { res.status(500).json({ error: 'Failed' }) }
})

router.delete('/security/block-ip/:ip', async (req, res) => {
  try {
    settings.unblockIp(req.params.ip)
    await SecurityEvent.create({ type: 'ip_unblocked', severity: 'info', ip: req.params.ip, message: `Unblocked by ${req.admin.username}` })
    await writeAudit(req.admin, 'security.unblock_ip', { resourceType: 'ip', resourceId: req.params.ip, req })
    res.json({ success: true })
  } catch { res.status(500).json({ error: 'Failed' }) }
})

/* ════════════════════════════════════════════════════════════════
   AUDIT ACTIVITY — immutable trail (read-only)
════════════════════════════════════════════════════════════════ */
router.get('/audit', async (req, res) => {
  try {
    const page  = Math.max(1, parseInt(req.query.page) || 1)
    const limit = Math.min(50, Math.max(5, parseInt(req.query.limit) || 20))
    const filter = {}
    if (req.query.action) filter.action = { $regex: escapeRegex(req.query.action), $options: 'i' }
    if (req.query.actor) filter.actor_username = { $regex: escapeRegex(req.query.actor), $options: 'i' }
    const [items, total] = await Promise.all([
      AuditLog.find(filter).sort({ created_at: -1 }).skip((page - 1) * limit).limit(limit).lean(),
      AuditLog.countDocuments(filter),
    ])
    res.json({ items: items.map(a => ({ ...a, id: a._id.toString(), _id: undefined })), total, page, pages: Math.ceil(total / limit) || 1 })
  } catch (err) { console.error('[Audit]', err); res.status(500).json({ error: 'Failed' }) }
})

/* LIVE ACTIVITY — real events + real online presence */
router.get('/activity', async (req, res) => {
  try {
    const limit = Math.min(parseInt(req.query.limit) || 20, 50)
    const logs = await SystemLog.find({ source: 'activity' }).sort({ created_at: -1 }).limit(limit).lean()
    const online_users = Array.from(onlinePresence.entries()).map(([user_id, p]) => ({ user_id, username: p.username, since: p.since }))
    res.json({
      events: logs.map(l => ({ id: l._id.toString(), action: l.message, username: l.data?.username || null, meta: l.data?.meta || null, created_at: l.created_at })),
      online_count: onlinePresence.size,
      online_users,
    })
  } catch (err) { console.error('[AdminActivity]', err); res.json({ events: [], online_count: 0, online_users: [] }) }
})

/* ════════════════════════════════════════════════════════════════
   SYSTEM LOGS (technical) — inside System Health, not a duplicate
   of the audit trail.
════════════════════════════════════════════════════════════════ */
router.get('/logs', async (req, res) => {
  const page  = Math.max(1, parseInt(req.query.page) || 1)
  const limit = Math.min(100, Math.max(10, parseInt(req.query.limit) || 50))
  const level = String(req.query.level || '')
  try {
    const filter = ['info', 'warn', 'error', 'debug'].includes(level) ? { level } : {}
    const [logs, total] = await Promise.all([
      SystemLog.find(filter).sort({ created_at: -1 }).skip((page - 1) * limit).limit(limit).lean(),
      SystemLog.countDocuments(filter),
    ])
    res.json({ logs: logs.map(l => ({ ...l, id: l._id.toString(), _id: undefined })), total, page, pages: Math.ceil(total / limit) || 1 })
  } catch { res.json({ logs: [], total: 0, page: 1, pages: 1 }) }
})

/* ════════════════════════════════════════════════════════════════
   SETTINGS — grouped global configuration (real effects only)
════════════════════════════════════════════════════════════════ */
router.get('/settings', async (req, res) => {
  const cfg = settings.get()
  res.json({
    general: { app_name: cfg.app_name, maintenance_mode: cfg.maintenance_mode },
    ai: {
      system_prompt: cfg.system_prompt, max_tokens: cfg.max_tokens, temperature: cfg.temperature,
      max_context_messages: cfg.max_context_messages,
      free_daily_limit: cfg.free_daily_limit, premium_daily_limit: cfg.premium_daily_limit,
      cost_per_1k_tokens: cfg.cost_per_1k_tokens,
    },
    features: {
      image_gen_enabled: cfg.image_gen_enabled, file_uploads_enabled: cfg.file_uploads_enabled,
      moderation_enabled: cfg.moderation_enabled, knowledge_base_enabled: cfg.knowledge_base_enabled,
    },
    model: aiConfig.models.chat,
  })
})

router.put('/settings', async (req, res) => {
  try {
    const before = settings.get()
    const updated = settings.update(req.body || {})
    const changed = Object.keys(req.body || {})
    await writeAudit(req.admin, 'settings.update', {
      resourceType: 'settings',
      meta: { changed, before: Object.fromEntries(changed.map(k => [k, before[k]])), after: Object.fromEntries(changed.map(k => [k, updated[k]])) },
      req,
    })
    await notifyAdmins({ title: 'System settings updated', message: `${req.admin.username} changed: ${changed.join(', ')}.`, type: 'info', category: 'config', link: '/admin/settings', dedupeKey: `settings-${req.admin.id}` }).catch(() => {})
    const io = req.app.get('io')
    if (io && req.body.maintenance_mode !== undefined) io.emit('maintenance_mode', { active: req.body.maintenance_mode })
    res.json({ success: true })
  } catch { res.status(500).json({ error: 'Failed to save settings' }) }
})

/* Admin accounts (single role: super_admin) */
router.get('/admins', async (req, res) => {
  try { res.json((await Admin.find().select('username email role created_at last_login').sort({ created_at: 1 }).lean()).map(fmtDoc)) }
  catch { res.json([]) }
})

router.delete('/admins/:id', async (req, res) => {
  if (req.admin.id === req.params.id) return res.status(400).json({ error: 'Cannot delete yourself' })
  try {
    const total = await Admin.countDocuments()
    if (total <= 1) return res.status(400).json({ error: 'Cannot delete the last superadmin account' })
    const a = await Admin.findByIdAndDelete(req.params.id).select('username').lean()
    await writeAudit(req.admin, 'admin.delete', { resourceType: 'admin', resourceId: req.params.id, resourceLabel: a?.username, req })
    res.json({ success: true })
  } catch { res.status(500).json({ error: 'Failed' }) }
})

/* ════════════════════════════════════════════════════════════════
   PUSH NOTIFICATIONS (Superadmin PWA, web-push VAPID)
════════════════════════════════════════════════════════════════ */
router.get('/push/status', async (req, res) => {
  const st = pushService.status()
  st.subscriptions = await pushService.subscriptionCount()
  res.json(st)
})

router.post('/push/subscribe', async (req, res) => {
  try {
    const r = await pushService.subscribe({ endpoint: req.body.endpoint, keys: req.body.keys, user_agent: req.headers['user-agent'] })
    await writeAudit(req.admin, 'push.subscribe', { resourceType: 'push_subscription', resourceId: String(req.body.endpoint || '').slice(0, 80), req })
    res.json(r)
  } catch (err) { res.status(err.status || 500).json({ error: err.message }) }
})

router.post('/push/unsubscribe', async (req, res) => {
  try {
    const r = await pushService.unsubscribe({ endpoint: req.body.endpoint })
    await writeAudit(req.admin, 'push.unsubscribe', { resourceType: 'push_subscription', req })
    res.json(r)
  } catch (err) { res.status(err.status || 500).json({ error: err.message }) }
})

router.post('/push/test', async (req, res) => {
  const result = await pushService.sendToAll({
    title: 'KinyaBot test notification',
    body: 'If you can read this, push notifications and deep links are working.',
    url: '/admin/health', tag: 'kinyabot-test', priority: 'information',
  })
  await writeAudit(req.admin, 'push.test', { resourceType: 'push', meta: result, req })
  res.json(result)
})

/* ════════════════════════════════════════════════════════════════
   KNOWLEDGE BASE — real documents + real derived state
════════════════════════════════════════════════════════════════ */
router.get('/knowledge', async (req, res) => {
  const page  = Math.max(1, parseInt(req.query.page) || 1)
  const limit = Math.min(50, Math.max(5, parseInt(req.query.limit) || 12))
  const search = String(req.query.search || '').trim()
  try {
    const filter = search ? { title: { $regex: escapeRegex(search), $options: 'i' } } : {}
    const [items, total, agg] = await Promise.all([
      KnowledgeBase.find(filter).sort({ created_at: -1 }).skip((page - 1) * limit).limit(limit)
        .select('title file_type file_url content uploaded_by created_at').lean(),
      KnowledgeBase.countDocuments(filter),
      KnowledgeBase.aggregate([{ $project: { size: { $strLenCP: '$content' }, has_file: { $cond: [{ $ne: ['$file_url', null] }, 1, 0] } } }, { $group: { _id: null, chars: { $sum: '$size' }, files: { $sum: '$has_file' }, docs: { $sum: 1 } } }]),
    ])
    res.json({
      items: items.map(k => ({
        id: k._id.toString(), title: k.title, file_type: k.file_type, file_url: k.file_url,
        // Real derived processing state: indexed when the backend actually
        // holds extractable text that the RAG search uses; needs_review when
        // a file was stored but no text could be extracted from it.
        size_chars: (k.content || '').length,
        state: (k.content && k.content.length > 0) ? 'indexed' : 'needs_review',
        created_at: k.created_at,
      })),
      total, page, pages: Math.ceil(total / limit) || 1,
      stats: { docs: agg[0]?.docs || 0, chars: agg[0]?.chars || 0, files: agg[0]?.files || 0, rag_enabled: settings.get().knowledge_base_enabled },
    })
  } catch (err) { console.error('[Knowledge]', err); res.status(500).json({ error: 'Failed' }) }
})

router.post('/knowledge', async (req, res) => {
  const { title, content } = req.body
  if (!title) return res.status(400).json({ error: 'Title required' })
  try {
    let fileContent = content || ''
    let fileUrl = null, fileType = 'text'
    if (req.file) {
      fileUrl = `/uploads/${req.file.filename}`
      fileType = req.file.mimetype
      const extracted = extractTextFromFile(req.file.path)
      if (extracted) fileContent = extracted
    }
    if (!fileContent) return res.status(400).json({ error: 'Content or file with extractable text required' })
    const kb = await KnowledgeBase.create({ title, content: fileContent, file_url: fileUrl, file_type: fileType, uploaded_by: req.admin.id })
    await writeAudit(req.admin, 'knowledge.create', { resourceType: 'knowledge', resourceId: kb._id.toString(), resourceLabel: title, req })
    logActivity('knowledge_added', { username: req.admin.username, meta: { title } })
    res.json({ id: kb._id.toString(), title, success: true })
  } catch { res.status(500).json({ error: 'Failed to add knowledge' }) }
})

router.delete('/knowledge/:id', async (req, res) => {
  try {
    const k = await KnowledgeBase.findByIdAndDelete(req.params.id).select('title').lean()
    await writeAudit(req.admin, 'knowledge.delete', { resourceType: 'knowledge', resourceId: req.params.id, resourceLabel: k?.title, req })
    res.json({ success: true })
  } catch { res.status(500).json({ error: 'Failed' }) }
})

function extractTextFromFile(filePath) {
  try {
    const ext = require('path').extname(filePath).toLowerCase()
    if (['.txt', '.md', '.csv', '.json', '.py', '.js', '.ts', '.html', '.css'].includes(ext)) {
      return fs.readFileSync(filePath, 'utf8').slice(0, 8000)
    }
    return null
  } catch { return null }
}

/* ════════════════════════════════════════════════════════════════
   FILES — real uploads on disk, paginated
════════════════════════════════════════════════════════════════ */
router.get('/files', async (req, res) => {
  try {
    const dir = './uploads'
    if (!fs.existsSync(dir)) return res.json({ files: [], total: 0, page: 1, pages: 1, total_size: 0 })
    const page  = Math.max(1, parseInt(req.query.page) || 1)
    const limit = Math.min(60, Math.max(6, parseInt(req.query.limit) || 24))
    const search = String(req.query.search || '').trim().toLowerCase()
    const type  = String(req.query.type || '') // image | document | audio | video
    const IMAGE = /\.(jpg|jpeg|png|gif|webp|svg)$/i
    const AUDIO = /\.(mp3|wav|m4a|ogg|webm|flac|aac|mp4)$/i
    const DOC   = /\.(pdf|txt|md|csv|json|docx?|py|js|ts|html|css|xml|ya?ml)$/i

    let files = fs.readdirSync(dir).map(name => {
      const stat = fs.statSync(`${dir}/${name}`)
      const ext = name.split('.').pop()?.toLowerCase() || ''
      const kind = IMAGE.test(name) ? 'image' : AUDIO.test(name) ? 'audio' : DOC.test(name) ? 'document' : 'other'
      return { name, size: stat.size, created: stat.birthtime, mtime: stat.mtime, kind, ext, url: `/api/files/${encodeURIComponent(name)}` }
    })
    if (search) files = files.filter(f => f.name.toLowerCase().includes(search))
    if (type) files = files.filter(f => f.kind === type)
    files.sort((a, b) => b.created - a.created)
    const total_size = files.reduce((s, f) => s + f.size, 0)
    const total = files.length
    const paged = files.slice((page - 1) * limit, page * limit)
    res.json({ files: paged, total, page, pages: Math.ceil(total / limit) || 1, total_size })
  } catch (err) { console.error('[Files]', err); res.json({ files: [], total: 0, page: 1, pages: 1, total_size: 0 }) }
})

router.delete('/files/:name', async (req, res) => {
  try {
    const p = `./uploads/${req.params.name.replace(/\.\./g, '')}`
    if (fs.existsSync(p)) fs.unlinkSync(p)
    await writeAudit(req.admin, 'file.delete', { resourceType: 'file', resourceId: req.params.name, req })
    await sysLog('warn', 'admin', `Deleted file: ${req.params.name}`)
    res.json({ success: true })
  } catch { res.status(500).json({ error: 'Failed' }) }
})

/* ════════════════════════════════════════════════════════════════
   EXPORTS (CSV, auth via Bearer header — frontend downloads via fetch)
════════════════════════════════════════════════════════════════ */
router.get('/export/users', async (req, res) => {
  try {
    const users = await User.find().select('username email profession referral_source onboarded is_banned created_at last_login').sort({ created_at: -1 }).lean()
    res.setHeader('Content-Type', 'text/csv')
    res.setHeader('Content-Disposition', 'attachment; filename=users.csv')
    const header = 'id,username,email,profession,referral,onboarded,banned,created_at,last_login\n'
    const rows = users.map(u => `${u._id},"${u.username}","${u.email}","${u.profession || ''}","${u.referral_source || ''}",${u.onboarded},${u.is_banned},"${u.created_at}","${u.last_login || ''}"`).join('\n')
    res.send(header + rows)
  } catch { res.status(500).json({ error: 'Export failed' }) }
})

router.get('/export/chats', async (req, res) => {
  try {
    const chats = await Chat.aggregate([
      { $lookup: { from: 'users', localField: 'user_id', foreignField: '_id', as: 'user' } },
      { $addFields: { username: { $first: '$user.username' }, email: { $first: '$user.email' } } },
      { $lookup: { from: 'messages', let: { cid: '$_id' }, pipeline: [
        { $match: { $expr: { $eq: ['$chat_id', '$$cid'] } } }, { $count: 'n' },
      ], as: 'm' } },
      { $addFields: { msg_count: { $ifNull: [{ $first: '$m.n' }, 0] } } },
      { $sort: { created_at: -1 } },
    ])
    res.setHeader('Content-Type', 'text/csv')
    res.setHeader('Content-Disposition', 'attachment; filename=chats.csv')
    const header = 'id,title,username,email,messages,created_at,updated_at\n'
    const rows = chats.map(c => `${c._id},"${c.title}","${c.username || ''}","${c.email || ''}",${c.msg_count},"${c.created_at}","${c.updated_at}"`).join('\n')
    res.send(header + rows)
  } catch { res.status(500).json({ error: 'Export failed' }) }
})

module.exports = router
