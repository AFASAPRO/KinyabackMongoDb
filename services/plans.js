/**
 * KinyaBot — Centralized Plan Service (§2, §27)
 * ═══════════════════════════════════════════════════════════════
 * Single source of truth for plan definitions (FREE / PLUS / PRO).
 *
 *  • Plan limits + feature flags live in the `planconfig` MongoDB
 *    collection so the SuperAdmin can change them WITHOUT code
 *    changes (PUT /api/admin/plans/:planId).
 *  • Defaults are seeded automatically at startup.
 *  • A short in-process cache keeps the hot chat path fast — the
 *    per-request quota check never hits a cold aggregate.
 *  • `canUseFeature(plan, feature)` is the ONLY sanctioned way to
 *    gate a capability — never `if (plan === 'pro')`.
 *
 * NOTE: a user without a UserPlan document is implicitly FREE.
 * That keeps every existing account working after migration (§43).
 */
const { PlanConfig, UserPlan } = require('../models')

const PLAN_IDS = ['free', 'plus', 'pro']

/* Feature flags known to the system. New capabilities ship by
   adding a flag here + a default below — no schema redesign. */
const FEATURE_FLAGS = [
  'chatAccess', 'voiceAccess', 'imageGeneration', 'documentAnalysis',
  'advancedContext', 'agentAccess', 'priorityProcessing', 'advancedTools',
]

/* Human-readable upgrade paths: which plans a plan can request. */
const UPGRADE_PATHS = { free: ['plus', 'pro'], plus: ['pro'], pro: [] }

const DEFAULTS = [
  {
    plan_id: 'free',
    name: 'Free',
    tagline: 'Get started with KinyaBot.',
    daily_chat_limit: 50,
    context_messages: 10,
    doc_size_multiplier: 1,
    burst_multiplier: 1,
    features: {
      chatAccess: true, voiceAccess: true, imageGeneration: true,
      documentAnalysis: true, advancedContext: false, agentAccess: false,
      priorityProcessing: false, advancedTools: true,
    },
    sort_order: 1,
  },
  {
    plan_id: 'plus',
    name: 'Plus',
    tagline: 'More capacity for everyday AI work.',
    daily_chat_limit: 200,
    context_messages: 20,
    doc_size_multiplier: 2,
    burst_multiplier: 2,
    features: {
      chatAccess: true, voiceAccess: true, imageGeneration: true,
      documentAnalysis: true, advancedContext: true, agentAccess: false,
      priorityProcessing: true, advancedTools: true,
    },
    sort_order: 2,
  },
  {
    plan_id: 'pro',
    name: 'Pro',
    tagline: 'Maximum KinyaBot capacity and priority processing.',
    daily_chat_limit: 500,
    context_messages: 40,
    doc_size_multiplier: 4,
    burst_multiplier: 4,
    features: {
      chatAccess: true, voiceAccess: true, imageGeneration: true,
      documentAnalysis: true, advancedContext: true, agentAccess: false,
      priorityProcessing: true, advancedTools: true,
    },
    sort_order: 3,
  },
]

/* ── Cache (15s TTL; invalidated on admin writes) ─────────────── */
const CACHE_TTL_MS = 15 * 1000
let cache = { plans: null, at: 0 }

function normalizeFeatures(features = {}) {
  const out = {}
  for (const f of FEATURE_FLAGS) out[f] = features?.[f] === true
  return out
}

function normalizePlan(doc) {
  return {
    plan_id: doc.plan_id,
    name: doc.name,
    tagline: doc.tagline || '',
    dailyChatLimit: doc.daily_chat_limit,
    contextMessages: doc.context_messages,
    docSizeMultiplier: doc.doc_size_multiplier,
    burstMultiplier: doc.burst_multiplier,
    features: normalizeFeatures(doc.features),
    isActive: doc.is_active !== false,
    sortOrder: doc.sort_order,
  }
}

/** Seed / repair plan configuration documents (idempotent). */
async function ensureSeed() {
  for (const def of DEFAULTS) {
    try {
      await PlanConfig.updateOne(
        { plan_id: def.plan_id },
        {
          $setOnInsert: {
            name: def.name, tagline: def.tagline,
            daily_chat_limit: def.daily_chat_limit,
            context_messages: def.context_messages,
            doc_size_multiplier: def.doc_size_multiplier,
            burst_multiplier: def.burst_multiplier,
            features: def.features, sort_order: def.sort_order,
            is_active: true,
          },
        },
        { upsert: true }
      )
    } catch (err) { console.error('[Plans] seed failed:', err.message) }
  }
}

/** All active plans (cached). Falls back to DEFAULTS when the DB is
 *  unreachable — quota enforcement must never crash the chat path. */
async function getPlans() {
  const fresh = cache.plans && (Date.now() - cache.at < CACHE_TTL_MS)
  if (fresh) return cache.plans
  try {
    const docs = await PlanConfig.find({}).lean()
    if (!docs.length) throw new Error('no planconfig rows')
    const plans = docs
      .map(normalizePlan)
      .filter(p => p.isActive)
      .sort((a, b) => a.sortOrder - b.sortOrder)
    cache = { plans, at: Date.now() }
    return plans
  } catch {
    return DEFAULTS.map(d => normalizePlan(d))
  }
}

function invalidateCache() { cache = { plans: null, at: 0 } }

async function getPlan(planId) {
  const plans = await getPlans()
  return plans.find(p => p.plan_id === String(planId)) ||
         plans.find(p => p.plan_id === 'free') || null
}

/** The plan record for a user — undefined UserPlan ⇒ FREE (§43). */
async function getPlanForUser(userPlanDoc) {
  return getPlan(userPlanDoc?.plan || 'free')
}

/** Resolve the user's UserPlan document, creating the FREE default
 *  when missing (safe: only called on writes / explicit reads). */
async function getUserPlanDoc(userId) {
  let doc = await UserPlan.findOne({ user_id: userId })
  if (!doc) {
    try {
      doc = await UserPlan.create({ user_id: userId, plan: 'free', daily_limit: 50, status: 'active' })
    } catch (err) {
      if (err?.code === 11000) doc = await UserPlan.findOne({ user_id: userId })
      else throw err
    }
  }
  return doc
}

/** §27 — capability check. NEVER compare plan strings in feature code. */
async function canUseFeature(planId, feature) {
  const plan = await getPlan(planId)
  return !!(plan && plan.features[feature] === true)
}

/** Validate admin-supplied plan configuration (whitelist + bounds). */
function validatePlanPatch(body = {}) {
  const patch = {}
  if (body.dailyChatLimit !== undefined) {
    const n = Number(body.dailyChatLimit)
    if (!Number.isInteger(n) || n < 1 || n > 100000) return { error: 'dailyChatLimit must be an integer between 1 and 100000' }
    patch.daily_chat_limit = n
  }
  if (body.contextMessages !== undefined) {
    const n = Number(body.contextMessages)
    if (!Number.isInteger(n) || n < 1 || n > 200) return { error: 'contextMessages must be an integer between 1 and 200' }
    patch.context_messages = n
  }
  if (body.docSizeMultiplier !== undefined) {
    const n = Number(body.docSizeMultiplier)
    if (!Number.isFinite(n) || n < 1 || n > 10) return { error: 'docSizeMultiplier must be between 1 and 10' }
    patch.doc_size_multiplier = n
  }
  if (body.burstMultiplier !== undefined) {
    const n = Number(body.burstMultiplier)
    if (!Number.isFinite(n) || n < 1 || n > 10) return { error: 'burstMultiplier must be between 1 and 10' }
    patch.burst_multiplier = n
  }
  if (body.name !== undefined) {
    const s = String(body.name).trim()
    if (!s || s.length > 40) return { error: 'name must be 1-40 characters' }
    patch.name = s
  }
  if (body.tagline !== undefined) {
    const s = String(body.tagline).trim()
    if (s.length > 140) return { error: 'tagline must be at most 140 characters' }
    patch.tagline = s
  }
  if (body.features !== undefined) {
    if (typeof body.features !== 'object' || Array.isArray(body.features)) return { error: 'features must be an object' }
    const features = {}
    for (const f of FEATURE_FLAGS) {
      if (body.features[f] !== undefined) features[f] = body.features[f] === true
    }
    patch.features = features
  }
  if (!Object.keys(patch).length) return { error: 'Nothing to update' }
  return { patch }
}

module.exports = {
  PLAN_IDS, FEATURE_FLAGS, UPGRADE_PATHS, DEFAULTS,
  ensureSeed, getPlans, getPlan, getPlanForUser, getUserPlanDoc,
  canUseFeature, invalidateCache, validatePlanPatch, normalizePlan,
}
