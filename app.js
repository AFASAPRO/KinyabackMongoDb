/**
 * KinyaBot AI Assistant — Backend v7.0 (MongoDB / Mongoose)
 * Features: SSE Streaming, File AI Analysis, Memory System, RAG, Usage Tracking,
 *           Full admin panel support, MongoDB Atlas ready, Render-deployable
 */
require('dotenv').config();
const express    = require('express');
const cors       = require('cors');
const mongoose   = require('mongoose');
const bcrypt     = require('bcryptjs');
const jwt        = require('jsonwebtoken');
const multer     = require('multer');
const fs         = require('fs');
const path       = require('path');
const crypto     = require('crypto');
const nodemailer = require('nodemailer');
const admin      = require('firebase-admin');
const { complete: completeWithGroq, DEFAULT_MODEL } = require('./ai-service');
const aiConfig        = require('./services/ai/config');
const provider        = require('./services/ai/groqProvider');
const chatService     = require('./services/ai/chatService');
const documentService = require('./services/ai/documentService');
const speechService   = require('./services/ai/speechService');
const rateLimiter     = require('./services/rateLimiter');
const settings        = require('./services/settings');
const plansService    = require('./services/plans');
const usageService    = require('./services/usage');
const authGuard       = require('./services/authGuard');
const webSearchService = require('./services/search');
const { attachIo, onlinePresence, logActivity } = require('./services/activity');
const { notifyAdmins, notifyUser } = require('./services/notify');
const pushService     = require('./services/push');

const {
  User, Chat, Message, Admin, Notification, PageView,
  SystemLog, UserMemory, KnowledgeBase, UsageTracking,
  UserPlan, FlaggedContent, SecurityEvent, SearchLog
} = require('./models');

// Firebase Admin init
if (!admin.apps.length) {
  admin.initializeApp({ projectId: process.env.FIREBASE_PROJECT_ID || 'kinyabot-92ad1' });
}

const app  = express();
const PORT = process.env.PORT || 5000;
const JWT_SECRET   = process.env.JWT_SECRET   || 'kinyabot_jwt_secret_change_me';
const ADMIN_SECRET = process.env.ADMIN_SECRET || 'kinyabot_admin_secret_change_me';

/* ── MONGODB CONNECTION ──────────────────────────────────────── */
async function connectDB() {
  const uri = process.env.MONGODB_URI;
  if (!uri) { console.error('❌ MONGODB_URI not set in .env'); process.exit(1); }
  try {
    await mongoose.connect(uri, { serverSelectionTimeoutMS: 10000 });
    console.log('✅ MongoDB connected');
  } catch (err) {
    console.error('❌ MongoDB connection failed:', err.message);
    process.exit(1);
  }
}

/* ── CORS ──────────────────────────────────────────────────────── */
const allowedOrigins = [
  "https://kinyabotai.vercel.app",
  "http://localhost:5173",
  "http://localhost:3000",
  "http://localhost:4173"
];

app.use(cors({
  origin: function (origin, callback) {
    if (!origin) return callback(null, true);

    if (allowedOrigins.includes(origin)) {
      return callback(null, true);
    } else {
      return callback(new Error("Not allowed by CORS"));
    }
  },
  credentials: true
}));

// ✅ THIS LINE FIXES YOUR ERROR
app.options("*", cors());
app.use(express.json({ limit: '100mb' }));
app.use(express.urlencoded({ extended: true, limit: '100mb' }));

/* ── FILE UPLOAD ─────────────────────────────────────────────── */
const upload = multer({
  storage: multer.diskStorage({
    destination(_, __, cb) {
      const d = './uploads';
      if (!fs.existsSync(d)) fs.mkdirSync(d, { recursive: true });
      cb(null, d);
    },
    filename(_, file, cb) {
      cb(null, `${Date.now()}-${file.originalname.replace(/[^a-zA-Z0-9._-]/g, '_')}`);
    }
  }),
  limits: { fileSize: 50 * 1024 * 1024 },
  fileFilter(_, file, cb) {
    const allowed = /\.(jpg|jpeg|png|gif|webp|pdf|txt|md|csv|json|py|js|ts|html|css)$/i;
    cb(null, allowed.test(file.originalname));
  }
});
// NOTE: public static serving of ./uploads was REMOVED for privacy (§19).
// Attachments are now served exclusively through the authenticated,
// ownership-checked GET /api/files/:name endpoint (see CHAT ROUTES).
// Upload TYPE validation happens in buildMessageAttachments() (with
// magic-byte checks) — NOT in the multer filter — so unsupported files
// get a friendly 400 naming the file instead of being silently dropped.
// Hard cap covers the largest plan document allowance (Pro = 4× base);
// per-plan limits are enforced inside the route handlers (§27).
const CHAT_UPLOAD_MAX_BYTES = Math.max(
  aiConfig.limits.imageSizeBytes,
  aiConfig.limits.documentSizeBytes * 4
);
// Max attachments per message — reliable multi-upload without
// destabilizing request sizes (§13).
const CHAT_MAX_FILES = 4;
const uploadChat = multer({
  storage: multer.diskStorage({
    destination(_, __, cb) {
      const d = './uploads';
      if (!fs.existsSync(d)) fs.mkdirSync(d, { recursive: true });
      cb(null, d);
    },
    filename(_, file, cb) {
      cb(null, `c_${Date.now()}-${file.originalname.replace(/[^a-zA-Z0-9._-]/g, '_')}`);
    }
  }),
  limits: { fileSize: CHAT_UPLOAD_MAX_BYTES, files: CHAT_MAX_FILES },
  /* Broad accept at the multer layer: a rejected file must reach the
     app's validator so the caller gets a FRIENDLY 400 naming the file
     — a silent multer skip would turn "bad file" into a plain text
     message and the user would never know the attachment was lost.
     Size and count are still capped here; classification, magic-byte
     checks and per-plan limits run in buildMessageAttachments.     */
  fileFilter(_, file, cb) { cb(null, true); }
});
/* Accept BOTH attachment conventions: `files[]` / `files` (new,
   multiple) and `file` (legacy single). Normalized downstream by
   normalizeUploadedFiles() so handlers only ever see one array. */
const uploadChatFields = uploadChat.fields([
  { name: 'files', maxCount: CHAT_MAX_FILES },
  { name: 'files[]', maxCount: CHAT_MAX_FILES },
  { name: 'file', maxCount: 1 },
]);
const uploadAudio = multer({
  storage: multer.diskStorage({
    destination(_, __, cb) {
      const d = './uploads';
      if (!fs.existsSync(d)) fs.mkdirSync(d, { recursive: true });
      cb(null, d);
    },
    filename(_, file, cb) {
      cb(null, `a_${Date.now()}-${file.originalname.replace(/[^a-zA-Z0-9._-]/g, '_')}`);
    }
  }),
  limits: { fileSize: aiConfig.limits.audioSizeBytes },
  fileFilter(_, file, cb) { cb(null, /\.(mp3|wav|m4a|ogg|webm|flac|aac|mp4)$/i.test(file.originalname)); }
});

/* ── SETTINGS ──────────────────────────────────────────────────
   Owned by services/settings.js (single source of truth shared with
   the Superadmin Settings / AI Control pages).                     */
const cfg = settings.get();

/* ── EMAIL ───────────────────────────────────────────────────── */
const mailer = nodemailer.createTransport({
  host: process.env.SMTP_HOST || 'smtp.gmail.com',
  port: parseInt(process.env.SMTP_PORT || '587'),
  secure: process.env.SMTP_SECURE === 'true',
  auth: { user: process.env.SMTP_USER || '', pass: process.env.SMTP_PASS || '' }
});
async function sendOtpEmail(to, username, otp) {
  try {
    await mailer.sendMail({
      from: process.env.SMTP_FROM || 'KinyaBot AI <noreply@kinyabot.ai>', to,
      subject: 'Your KinyaBot Password Reset Code',
      html: `<div style="font-family:Arial;max-width:520px;margin:40px auto;background:#111;border-radius:16px;overflow:hidden">
        <div style="background:linear-gradient(135deg,#4f46e5,#7c3aed);padding:28px;text-align:center">
          <h1 style="color:#fff;margin:0">KinyaBot AI</h1></div>
        <div style="padding:28px">
          <p style="color:#e3e3e3">Hi <strong>${username}</strong>, your reset code:</p>
          <div style="text-align:center;margin:24px 0">
            <div style="display:inline-block;background:rgba(109,40,217,.2);border:2px solid rgba(109,40,217,.5);border-radius:12px;padding:14px 36px">
              <span style="font-size:34px;font-weight:700;color:#c4b5fd;letter-spacing:8px">${otp}</span></div></div>
          <p style="color:#9aa0a6;font-size:13px;text-align:center">Expires in 15 minutes</p></div></div>`
    });
    return true;
  } catch (e) { console.error('[Email]', e.message); return false; }
}
async function sendVerifyEmail(to, username, otp) {
  try {
    await mailer.sendMail({
      from: process.env.SMTP_FROM || 'KinyaBot AI <noreply@kinyabot.ai>', to,
      subject: 'Verify your KinyaBot account',
      html: `<div style="font-family:Arial;max-width:520px;margin:40px auto;background:#111;border-radius:16px;overflow:hidden">
        <div style="background:linear-gradient(135deg,#4f46e5,#7c3aed);padding:28px;text-align:center">
          <h1 style="color:#fff;margin:0">KinyaBot AI</h1></div>
        <div style="padding:28px">
          <p style="color:#e3e3e3">Hi <strong>${username}</strong>, welcome! Confirm it's you with this code:</p>
          <div style="text-align:center;margin:24px 0">
            <div style="display:inline-block;background:rgba(109,40,217,.2);border:2px solid rgba(109,40,217,.5);border-radius:12px;padding:14px 36px">
              <span style="font-size:34px;font-weight:700;color:#c4b5fd;letter-spacing:8px">${otp}</span></div></div>
          <p style="color:#9aa0a6;font-size:13px;text-align:center">Expires in 15 minutes</p></div></div>`
    });
    return true;
  } catch (e) { console.error('[Email]', e.message); return false; }
}
async function sendInviteEmail(to, inviterName, workspaceName) {
  const link = `${process.env.FRONTEND_URL || 'http://localhost:5173'}/register?invited_by=${encodeURIComponent(inviterName)}`;
  try {
    await mailer.sendMail({
      from: process.env.SMTP_FROM || 'KinyaBot AI <noreply@kinyabot.ai>', to,
      subject: `${inviterName} invited you to KinyaBot AI`,
      html: `<div style="font-family:Arial;max-width:520px;margin:40px auto;background:#111;border-radius:16px;overflow:hidden">
        <div style="background:linear-gradient(135deg,#4f46e5,#7c3aed);padding:28px;text-align:center">
          <h1 style="color:#fff;margin:0">KinyaBot AI</h1></div>
        <div style="padding:28px">
          <p style="color:#e3e3e3"><strong>${inviterName}</strong> invited you to join${workspaceName ? ` the <strong>${workspaceName}</strong> workspace on` : ''} KinyaBot AI.</p>
          <div style="text-align:center;margin:26px 0">
            <a href="${link}" style="display:inline-block;background:#6d28d9;color:#fff;text-decoration:none;font-weight:700;padding:14px 32px;border-radius:99px">Accept invite</a></div>
          <p style="color:#9aa0a6;font-size:13px;text-align:center">${link}</p></div></div>`
    });
    return true;
  } catch (e) { console.error('[Email]', e.message); return false; }
}

/* ── MIDDLEWARES ─────────────────────────────────────────────── */
/* authGuard now lives in services/authGuard.js (shared with the
   modular routers) — imported above. */
function adminGuard(req, res, next) {
  const h = req.headers.authorization;
  if (!h?.startsWith('Bearer ')) return res.status(401).json({ error: 'Unauthorized' });
  try {
    const d = jwt.verify(h.slice(7), ADMIN_SECRET);
    if (!d.isAdmin) throw new Error();
    req.admin = d; next();
  } catch { res.status(403).json({ error: 'Admin access required' }); }
}
app.use((req, res, next) => {
  if (cfg.blocked_ips?.includes(req.ip)) return res.status(403).json({ error: 'Access denied' });
  next();
});

/* ── HELPERS ─────────────────────────────────────────────────── */
function friendlyError(err) {
  const msg = String(err?.message || err || '');
  // Honest, user-safe errors thrown by the AI services pass through as-is
  if (err?.userSafe) return err.message;
  if (err?.code === 'GROQ_NOT_CONFIGURED')
    return 'KinyaBot AI is not configured yet. Please contact the administrator.';
  if (err?.code === 'AI_AUTH')
    return 'KinyaBot AI rejected its configured credentials. Please contact the administrator.';
  if (err?.code === 'AI_MODEL_UNAVAILABLE')
    return 'The configured AI model is currently unavailable. Please try again later or contact the administrator.';
  if (err?.code === 'AI_RATE_LIMIT')
    return 'KinyaBot is very busy right now. Please wait a moment and try again.';
  if (err?.status === 401 || msg.includes('401'))
    return 'KinyaBot AI is temporarily unavailable. Please contact the administrator.';
  if (err?.status === 429 || msg.includes('429') || msg.toLowerCase().includes('rate limit'))
    return 'KinyaBot is busy right now. Please wait a moment and try again.';
  if (err?.code === 'INVALID_CONVERSATION' || err?.code === 'EMPTY_AI_RESPONSE')
    return 'KinyaBot could not process that conversation. Please try again.';
  if (err?.code === 'CONVERSATION_NOT_FOUND')
    return 'This conversation could not be loaded. It may have been deleted or you may not have permission to access it.';
  if (msg.includes('ENOTFOUND') || msg.includes('getaddrinfo') || msg.includes('ECONNREFUSED'))
    return "Couldn't reach the AI service. Please check your internet connection and try again.";
  if (msg.includes('timeout') || msg.includes('ETIMEDOUT'))
    return "The AI service took too long to respond. Please try again in a moment.";
  if (msg.includes('API') || msg.includes('status'))
    return "The AI service is temporarily unavailable. Please try again shortly.";
  return "Something went wrong. Please try again.";
}

function estimateTokens(text) { return Math.ceil((text || '').length / 4); }

async function sysLog(level, source, message, data, userId) {
  try { await SystemLog.create({ level, source, message, data: data || null, user_id: userId || null }); } catch {}
}

/* ══════════════════════════════════════════════════════════════
   PLAN SYSTEM — plan-aware request plumbing (§1-§4, §27, §36)
   The plan configuration is DB-backed (services/plans.js) so the
   SuperAdmin can change limits/flags without touching code.
══════════════════════════════════════════════════════════════ */

/** Resolve the caller's plan + configuration (one indexed read;
 *  plan config itself is cached in-process for 15s). */
async function getPlanContext(userId) {
  const planDoc = await plansService.getUserPlanDoc(userId).catch(() => null);
  const planCfg = await plansService.getPlan(planDoc?.plan || 'free');
  return { plan: planDoc?.plan || 'free', planStatus: planDoc?.status || 'active', planCfg };
}

/** Structured 429 for a reached daily limit (§3, §7).
 *  The AI provider is NEVER called in this path. */
function limitReachedResponse(res, usage) {
  return res.status(429).json({
    error: `You have used all ${usage.limit} chats available on your ${usage.planName} plan today. Your limit resets tomorrow.`,
    code: 'DAILY_LIMIT_REACHED',
    usage: {
      used: usage.used, limit: usage.limit, remaining: 0,
      percent: 100, state: 'limit', plan: usage.plan, planName: usage.planName, date: usage.date,
    },
  });
}

/** Atomic daily-chat reservation (§36). Returns the reservation or
 *  null after answering with a structured limit-reached response. */
async function reserveChatUsage(req, res, { count = 1 } = {}) {
  const reservation = await usageService.consume(req.user.id, { count });
  if (reservation.ok) return reservation;
  limitReachedResponse(res, reservation.usage);
  return null;
}

/** Give a reserved chat back exactly once — failed AI turns must not
 *  count as successful chats (§36). Idempotent per reservation. */
async function refundReservation(req, reservation) {
  if (!reservation || reservation.refunded || reservation.completed) return;
  reservation.refunded = true;
  try { await usageService.refund(req.user.id, { count: reservation.count || 1 }); } catch {}
}

/** Per-plan request-capability guard (§27) — used by feature routes. */
async function featureGuard(req, res, feature, message) {
  const { plan, planStatus } = await getPlanContext(req.user.id);
  if (!['active', 'pending'].includes(planStatus)) {
    res.status(403).json({ error: 'Your subscription is not active. Please contact support.', code: 'SUBSCRIPTION_INACTIVE' });
    return null;
  }
  if (!(await plansService.canUseFeature(plan, feature))) {
    res.status(403).json({ error: message, code: 'FEATURE_LOCKED', feature });
    return null;
  }
  return { plan };
}

/* ══════════════════════════════════════════════════════════════
   WEB SEARCH — Pro-only web intelligence layer (§2, §26, §30)
   ONE reusable backend service shared by Chat (auto + manual)
   and the Agent's web_search tool. Free users NEVER reach
   LangSearch: the entitlement is resolved server-side from the
   UserPlan/PlanConfig collections, never from the request body.
══════════════════════════════════════════════════════════════ */

/** Conversation modes accepted on message turns. 'web_search' is the
 *  explicit manual research mode; 'agent' stays reserved (Agent rules
 *  govern it); anything else is plain chat with possible AUTO search. */
const CHAT_MODES = ['chat', 'web_search', 'agent'];

/** Server-side entitlement for web search (§2/§47): plan feature flag
 *  AND global operational switches (AI Control §38). */
async function webSearchEntitled(plan) {
  if (!cfg.web_search_enabled) return false;
  return plansService.canUseFeature(plan, 'webSearch');
}

/**
 * Decide whether this turn performs a web search and with what trigger.
 * Returns { trigger } — null = no search; 'manual' | 'auto' | 'agent'.
 * `res` is answered (403) directly when a manual Web Search request
 * comes from an unentitled account — LangSearch is NEVER called (§2).
 */
async function resolveSearchTrigger(req, res, { mode, plan }) {
  if (mode === 'web_search') {
    if (!(await webSearchEntitled(plan))) {
      res.status(403).json({
        error: 'Web Search is available with KinyaBot Pro.',
        code: 'FEATURE_LOCKED',
        feature: 'webSearch',
        upgradeHint: true,
      });
      return { trigger: null };
    }
    return { trigger: 'manual' };
  }
  if (mode === 'agent') {
    // Agent may use web_search as one of its tools (§31) — gated by the
    // SAME entitlement (§30: no duplicated search system).
    if (await webSearchEntitled(plan)) return { trigger: 'agent' };
    return { trigger: null };
  }
  // Chat mode: AUTO search only when globally enabled AND the account
  // is entitled. Free users simply never search — no error, no lock-in
  // of normal chat (§28).
  if (cfg.web_search_enabled && cfg.web_search_auto_enabled && (await webSearchEntitled(plan))) {
    return { trigger: 'auto' };
  }
  return { trigger: null };
}

/** Serialize a search outcome for the client (safe subset — no internal
 *  prompts, no decision reasoning, no URLs other than real sources §15). */
function serializeSearchOutcome(outcome) {
  if (!outcome) return null;
  return {
    performed: !!outcome.performed,
    status: outcome.status,             // success | empty | unavailable | skipped | rate_limited
    trigger: outcome.mode,              // auto | manual | agent
    queries: (outcome.queries || []).slice(0, 5),
    sources: (outcome.sources || []).slice(0, 12).map(s => ({
      title: s.title, url: s.url, domain: s.domain,
      snippet: String(s.snippet || '').slice(0, 300),
      published_date: s.published_date || null,
    })),
    resultCount: outcome.resultCount || 0,
    domains: (outcome.domains || []).slice(0, 12),
    durationMs: outcome.durationMs || 0,
    cached: !!outcome.cached,
  };
}

/** Persist one REAL search attempt for analytics/observability (§21/§36).
 *  Metadata only — never the retrieved page contents (§21). */
async function logSearchAttempt({ req, chat, userText, outcome, plan }) {
  try {
    await SearchLog.create({
      user_id: req.user.id,
      chat_id: chat ? chat._id : null,
      conversation_id: chat?.conversation_id || null,
      query: String(userText || '').slice(0, 1000),
      queries: (outcome.queries || []).slice(0, 5),
      trigger: outcome.mode || 'auto',
      plan: plan || 'free',
      result_count: outcome.resultCount || 0,
      source_domains: (outcome.domains || []).slice(0, 12),
      duration_ms: outcome.durationMs || 0,
      status: outcome.status === 'success' ? 'success'
        : outcome.status === 'empty' ? 'empty'
        : outcome.status === 'rate_limited' ? 'rate_limited' : 'error',
      error_code: outcome.error || null,
      cached: !!outcome.cached,
      usage: outcome.usage ? { input_tokens: outcome.usage.input_tokens, output_tokens: outcome.usage.output_tokens } : null,
    });
  } catch { /* logging must never break the chat */ }
}

/**
 * Run the web-search pipeline for one turn with live SSE activity
 * (§13/§14). Per-user rate limiting lives INSIDE the orchestrator so
 * a skipped auto-decision never consumes rate-limit budget (§26);
 * every failure degrades to a normal knowledge answer, honestly
 * labeled (§25) — a search outage can never fail the chat turn.
 */
async function runTurnSearch(req, res, { send, chat, userText, history, trigger, plan }) {
  const outcome = await webSearchService.runWebSearch({
    userText, userId: req.user.id, history, trigger,
    callbacks: {
      onStage: (stage, data) => {
        send('search_status', { stage, ...data });
        if (stage === 'unavailable') {
          send('search_notice', {
            message: data?.reason === 'rate_limited'
              ? 'Web Search is cooling down for a moment — answering from existing knowledge.'
              : 'Web Search is temporarily unavailable. I can still answer using my existing knowledge.',
          });
        }
      },
      onQuery: (query) => send('search_status', { stage: 'searching', query }),
      onSources: (sourcesFound, domains) => send('search_status', { stage: 'reading', sourcesFound, domains }),
    },
  });

  // Skipped decisions (auto mode, nothing worth searching) are NOT
  // attempts — no log row, no client event; the turn is a normal chat.
  if (outcome.status !== 'skipped') {
    send('search_results', serializeSearchOutcome(outcome));
    await logSearchAttempt({ req, chat, userText, outcome, plan });
  }
  return outcome;
}

/** Small recent-history slice for the decision/optimizer layers.
 *  Cheap projection — full bounded context is rebuilt later by
 *  runAssistantTurn for the actual model call. */
async function recentTurnHistory(chatId, beforeMessageId = null) {
  if (!chatId) return [];
  try {
    const q = { chat_id: chatId, superseded: { $ne: true } };
    if (beforeMessageId) q._id = { $lt: beforeMessageId };
    const rows = await Message.find(q).sort({ created_at: -1, _id: -1 }).limit(4)
      .select('role content -_id').lean();
    return rows.reverse().map(r => ({ role: r.role, content: r.content }));
  } catch { return []; }
}

/* ══════════════════════════════════════════════════════════════
   LIVE ACTIVITY (real, event-sourced — no randomized/fabricated
   entries). Implemented in services/activity.js: logActivity(),
   onlinePresence, attachIo(). Every call is made at the exact
   moment a real thing happens and is both persisted and pushed
   over Socket.IO to the Superadmin dashboards in `admin_room`.
   Online/offline state derives from real Socket.IO connections —
   see the io.on('connection', …) handler below.
══════════════════════════════════════════════════════════════ */

/* Real AI request telemetry for the Superadmin dashboards. */
async function trackUsage(userId, chatId, tokens, type, responseMs, success) {
  try {
    await UsageTracking.create({ user_id: userId, chat_id: chatId, tokens_used: tokens, request_type: type, response_ms: responseMs, success });
  } catch {}
  if (success) {
    const io = app.get('io');
    if (io) io.to('admin_room').emit('admin_ai_request', { ok: true, ms: responseMs, type });
  } else {
    logActivity('ai_request_failed', { meta: { type, ms: responseMs } });
    const io = app.get('io');
    if (io) io.to('admin_room').emit('admin_ai_request', { ok: false, ms: responseMs, type });
    notifyAdmins({
      title: 'AI request failed',
      message: `A ${type || 'chat'} request failed after ${responseMs || 0}ms.`,
      type: 'warning', category: 'ai', link: '/admin/ai',
      dedupeKey: `ai-fail-${type}`, push: false,
    }).catch(() => {});
  }
}

async function getUserMemory(userId) {
  try {
    const rows = await UserMemory.find({ user_id: userId }).lean();
    const mem = {};
    rows.forEach(r => { mem[r.memory_key] = r.memory_value; });
    return mem;
  } catch { return {}; }
}

async function setUserMemory(userId, key, value) {
  try {
    await UserMemory.findOneAndUpdate(
      { user_id: userId, memory_key: key },
      { memory_value: value },
      { upsert: true, new: true }
    );
  } catch {}
}

async function extractMemoryFromConversation(userId, userMsg, aiReply) {
  const text = userMsg.toLowerCase();
  if (text.includes('my name is ') || text.includes("i'm ") || text.includes('i am ')) {
    const nameMatch = userMsg.match(/(?:my name is|i'm|i am)\s+([A-Za-z]+)/i);
    if (nameMatch) await setUserMemory(userId, 'name', nameMatch[1]);
  }
  if (text.includes('i work as') || text.includes('i am a ') || text.includes("i'm a ")) {
    const jobMatch = userMsg.match(/(?:i work as|i am a|i'm a)\s+([^,.!?]+)/i);
    if (jobMatch) await setUserMemory(userId, 'profession', jobMatch[1].trim());
  }
  if (text.includes('i prefer') || text.includes('i like')) {
    const prefMatch = userMsg.match(/(?:i prefer|i like)\s+([^,.!?]+)/i);
    if (prefMatch) await setUserMemory(userId, 'preference_' + Date.now(), prefMatch[1].trim().slice(0, 100));
  }
}

async function searchKnowledgeBase(query) {
  try {
    const rows = await KnowledgeBase.find(
      { $text: { $search: query } },
      { score: { $meta: 'textScore' }, title: 1, content: 1 }
    ).sort({ score: { $meta: 'textScore' } }).limit(3).lean();
    if (!rows.length) return '';
    return '\n\n[Knowledge Base Context]\n' + rows.map(r => `${r.title}:\n${r.content.slice(0, 500)}`).join('\n\n');
  } catch { return ''; }
}

async function moderateContent(text) {
  if (!cfg.moderation_enabled) return { flagged: false, reason: null };
  const patterns = [
    { re: /\b(bomb|explosive|weapon|kill|murder|suicide|hack|illegal)\b/i, reason: 'Potentially harmful content' },
    { re: /\b(spam|advertisement|buy now|click here|free money)\b/i, reason: 'Spam detected' },
  ];
  for (const p of patterns) {
    if (p.re.test(text)) return { flagged: true, reason: p.reason };
  }
  return { flagged: false, reason: null };
}

/* A real moderation flag was just created — surface it to the
   Superadmin (notification center + security log + live feed). */
async function onContentFlagged(chatId, userId, reason, auto) {
  try {
    await SecurityEvent.create({ type: 'moderation_flag', severity: 'warning', message: reason, meta: { chat_id: chatId ? String(chatId) : null, auto_flagged: !!auto } });
  } catch {}
  let username = null;
  if (userId) { try { const u = await User.findById(userId).select('username').lean(); username = u?.username || null; } catch {} }
  logActivity('content_flagged', { username, user_id: userId || null, meta: { reason } });
  notifyAdmins({
    title: 'Content flagged by moderation',
    message: `${username || 'A user'}: ${reason}`,
    type: 'warning', category: 'moderation', link: '/admin/moderation',
    resource: { kind: 'chat', id: chatId ? String(chatId) : null },
    dedupeKey: 'moderation-flag', push: false,
  }).catch(() => {});
}

/* Real rate-limit / quota trip → security telemetry. */
async function onRateLimited(userId, kind) {
  try {
    let username = null;
    if (userId) { try { const u = await User.findById(userId).select('username').lean(); username = u?.username || null; } catch {} }
    await SecurityEvent.create({ type: 'rate_limited', severity: 'info', username, message: `${kind} rate limit reached` });
    notifyAdmins({
      title: 'Rate limit reached',
      message: `${username || 'A user'} hit the ${kind} rate limit.`,
      type: 'info', category: 'security', link: '/admin/security',
      dedupeKey: `rate-${kind}`, push: false,
    }).catch(() => {});
  } catch {}
}

/* Real rate-limit / quota trip → security telemetry. */
function extractTextFromFile(filePath) {
  try {
    const ext = path.extname(filePath).toLowerCase();
    if (['.txt', '.md', '.csv', '.json', '.py', '.js', '.ts', '.html', '.css'].includes(ext)) {
      return fs.readFileSync(filePath, 'utf8').slice(0, 8000);
    }
    return null;
  } catch { return null; }
}

// Helper: format a MongoDB doc to look like MySQL row (convert _id to id)
function fmt(doc) {
  if (!doc) return null;
  const obj = doc.toObject ? doc.toObject({ virtuals: false }) : { ...doc };
  obj.id = obj._id?.toString();
  delete obj._id;
  delete obj.__v;
  // Convert ObjectId references to strings
  for (const key of Object.keys(obj)) {
    if (obj[key] instanceof mongoose.Types.ObjectId) obj[key] = obj[key].toString();
  }
  return obj;
}
function fmtArr(docs) { return docs.map(fmt); }
/* Message formatter — keeps API payloads light by never shipping the
   stored document text used for context building (it can be large). */
function fmtMessage(doc) {
  const obj = fmt(doc);
  if (Array.isArray(obj.attachments)) {
    obj.attachments = obj.attachments.map(a => {
      const { extracted_text, ...rest } = a || {};
      void extracted_text;
      return rest;
    });
  }
  return obj;
}
function fmtMessageArr(docs) { return docs.map(fmtMessage); }

/* ── CONVERSATION ID (public URL identifier) ───────────────────
   UUID v4 via crypto.randomUUID (crypto is required at the top) —
   collision-resistant, not sequential, never exposes Mongo
   ObjectIds in URLs (§1/§2).                                     */
function newConversationId() { return crypto.randomUUID(); }

/* Resolve `:id` as EITHER a public conversation_id (UUID) or a Mongo
   ObjectId, ALWAYS scoped to the authenticated owner (§5). Attaches
   the verified chat document to req.chatDoc. */
async function resolveChatParam(req, res) {
  const raw = String(req.params.id || '').trim();
  if (!raw) {
    res.status(404).json({ error: 'Conversation not found', code: 'CONVERSATION_NOT_FOUND' });
    return null;
  }
  const isObjectId = /^[a-f\d]{24}$/i.test(raw);
  const query = isObjectId
    ? { _id: raw, user_id: req.user.id }
    : { conversation_id: raw, user_id: req.user.id };
  const chat = await Chat.findOne(query);
  if (!chat) {
    res.status(404).json({
      error: 'This conversation could not be loaded. It may have been deleted or you may not have permission to access it.',
      code: 'CONVERSATION_NOT_FOUND',
    });
    return null;
  }
  return chat;
}

/* Normalize multer output (fields map from .fields()) into ONE flat
   array of uploaded files, preserving submission order. Accepts the
   legacy single `file` field too. */
function normalizeUploadedFiles(req) {
  if (!req.files) {
    // Legacy .single('file') uploads expose req.file
    return req.file ? [req.file] : [];
  }
  if (Array.isArray(req.files)) return req.files; // .array('files')
  const groups = ['files[]', 'files', 'file'];
  const out = [];
  for (const g of groups) {
    if (Array.isArray(req.files[g])) out.push(...req.files[g]);
  }
  return out;
}

/* HTTP status for a failed request: coded userSafe errors carry a
   friendly message and deserve 4xx — never a scary 500 (§24).     */
function httpErrorStatus(err) {
  return err?.status || (err?.userSafe ? 400 : 500);
}

/* ══════════════════════════════════════════════════════════════
   USER AUTH
══════════════════════════════════════════════════════════════ */
app.post('/api/auth/register', async (req, res) => {
  const { username, email, password } = req.body;
  if (!username || !email || !password) return res.status(400).json({ error: 'All fields required' });
  if (username.length < 3) return res.status(400).json({ error: 'Username must be at least 3 characters' });
  if (password.length < 8) return res.status(400).json({ error: 'Password must be at least 8 characters' });
  try {
    const existing = await User.findOne({ $or: [{ email: email.toLowerCase() }, { username }] });
    if (existing) return res.status(409).json({ error: 'Email or username already in use' });
    const hash = await bcrypt.hash(password, 12);
    const user = await User.create({ username, email: email.toLowerCase(), password_hash: hash, email_verified: true });
    const token = jwt.sign({ id: user._id.toString(), username, email: user.email }, JWT_SECRET, { expiresIn: '30d' });
    await sysLog('info', 'auth', `Registered: ${username}`, null, user._id);
    logActivity('register', { username, user_id: user._id.toString() });
    res.status(201).json({ token, user: { id: user._id.toString(), username, email: user.email, onboarded: false, email_verified: true } });
  } catch (err) { console.error('[Register]', err); res.status(500).json({ error: 'Registration failed. Please try again.' }); }
});

/* Post-signup email verification — separate OTP from the password-reset one */
app.post('/api/auth/send-verification', authGuard, async (req, res) => {
  try {
    const user = await User.findById(req.user.id);
    if (!user) return res.status(404).json({ error: 'User not found' });
    if (user.email_verified) return res.json({ message: 'Already verified.' });
    const otp = String(Math.floor(100000 + Math.random() * 900000));
    user.email_otp_code = otp;
    user.email_otp_expires = new Date(Date.now() + 15 * 60 * 1000);
    await user.save();
    const sent = await sendVerifyEmail(user.email, user.username, otp);
    if (sent) res.json({ message: 'Verification code sent to your email.' });
    else res.json({ message: 'Email service not configured. Use code below for testing.', demo_otp: otp });
  } catch (err) { console.error('[SendVerify]', err); res.status(500).json({ error: 'Failed to send code.' }); }
});

app.post('/api/auth/verify-email', authGuard, async (req, res) => {
  const { otp } = req.body;
  if (!otp) return res.status(400).json({ error: 'Code required' });
  try {
    const user = await User.findOne({ _id: req.user.id, email_otp_code: String(otp).trim(), email_otp_expires: { $gt: new Date() } });
    if (!user) return res.status(400).json({ error: 'Invalid or expired code.' });
    user.email_verified = true;
    user.email_otp_code = null;
    user.email_otp_expires = null;
    await user.save();
    res.json({ success: true });
  } catch (err) { console.error('[VerifyEmail]', err); res.status(500).json({ error: 'Verification failed.' }); }
});

/* Invite a teammate by email — used on the onboarding "invite" step */
app.post('/api/onboarding/invite', authGuard, async (req, res) => {
  const { email } = req.body;
  if (!email || !/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(email)) return res.status(400).json({ error: 'Valid email required' });
  try {
    const user = await User.findById(req.user.id);
    const sent = await sendInviteEmail(email.toLowerCase(), user?.username || 'A teammate', user?.workspace_name || null);
    if (sent) res.json({ success: true, message: `Invitation sent to ${email}` });
    else res.json({ success: false, message: 'Email service not configured — invitation was not delivered.' });
  } catch (err) { console.error('[Invite]', err); res.status(500).json({ error: 'Could not send invitation.' }); }
});

app.post('/api/auth/login', async (req, res) => {
  const { email, password } = req.body;
  if (!email || !password) return res.status(400).json({ error: 'Email and password required' });
  try {
    const user = await User.findOne({ email: email.toLowerCase() });
    if (!user) {
      SecurityEvent.create({ type: 'login_failed', severity: 'info', username: email, ip: req.ip, user_agent: req.headers['user-agent'], message: 'Unknown email' }).catch(() => {});
      return res.status(401).json({ error: 'Invalid email or password' });
    }
    if (user.is_banned) return res.status(403).json({ error: 'Account suspended. Please contact support.' });
    if (cfg.maintenance_mode) return res.status(503).json({ error: 'KinyaBot is in maintenance mode. Please check back soon.' });
    const ok = await bcrypt.compare(password, user.password_hash);
    if (!ok) {
      SecurityEvent.create({ type: 'login_failed', severity: 'info', username: user.username, ip: req.ip, user_agent: req.headers['user-agent'], message: 'Wrong password' }).catch(() => {});
      return res.status(401).json({ error: 'Invalid email or password' });
    }
    user.last_login = new Date();
    await user.save();
    const planDoc = await UserPlan.findOne({ user_id: user._id }).select('plan status').lean();
    const token = jwt.sign({ id: user._id.toString(), username: user.username, email: user.email }, JWT_SECRET, { expiresIn: '30d' });
    logActivity('login', { username: user.username, user_id: user._id.toString() });
    res.json({ token, user: { id: user._id.toString(), username: user.username, email: user.email, avatar_url: user.avatar_url, onboarded: user.onboarded, profession: user.profession, email_verified: user.email_verified, plan: planDoc?.plan || 'free' } });
  } catch (err) { console.error('[Login]', err); res.status(500).json({ error: 'Login failed. Please try again.' }); }
});

app.post('/api/auth/google', async (req, res) => {
  const { idToken } = req.body;
  if (!idToken) return res.status(400).json({ error: 'ID Token required' });
  try {
    const decodedToken = await admin.auth().verifyIdToken(idToken);
    const { email, name, picture, uid, email_verified } = decodedToken;
    let user = await User.findOne({ email: email.toLowerCase() });
    if (!user) {
      const randomPass = crypto.randomBytes(16).toString('hex');
      const hash = await bcrypt.hash(randomPass, 12);
      let username = name || email.split('@')[0];
      const existingUser = await User.findOne({ username });
      if (existingUser) username = `${username}_${uid.slice(0, 5)}`;
      user = await User.create({ username, email: email.toLowerCase(), password_hash: hash, avatar_url: picture || null, email_verified: email_verified === true });
      await sysLog('info', 'auth', `Registered via Google: ${username}`, null, user._id);
      logActivity('register', { username, user_id: user._id.toString() });
    } else {
      if (user.is_banned) return res.status(403).json({ error: 'Account suspended.' });
      user.last_login = new Date();
      if (picture) user.avatar_url = picture;
      if (email_verified === true) user.email_verified = true;
      await user.save();
      logActivity('login', { username: user.username, user_id: user._id.toString() });
    }
    const token = jwt.sign({ id: user._id.toString(), username: user.username, email: user.email }, JWT_SECRET, { expiresIn: '30d' });
    res.json({ token, user: { id: user._id.toString(), username: user.username, email: user.email, avatar_url: user.avatar_url, onboarded: user.onboarded, profession: user.profession, email_verified: user.email_verified } });
  } catch (err) {
    console.error('[Google Auth]', err);
    res.status(401).json({ error: 'Google authentication failed. Please try again.' });
  }
});

app.get('/api/auth/me', authGuard, async (req, res) => {
  try {
    const user = await User.findById(req.user.id).select('username email avatar_url profession onboarded email_verified usage_type workspace_name use_cases created_at last_login').lean();
    if (!user) return res.status(404).json({ error: 'User not found' });
    // Plan comes from the authoritative UserPlan document (backend is
    // the single source of truth — §19). Missing doc ⇒ FREE (§43).
    const planDoc = await UserPlan.findOne({ user_id: req.user.id }).select('plan status').lean();
    res.json({ ...user, id: user._id.toString(), _id: undefined, plan: planDoc?.plan || 'free', plan_status: planDoc?.status || 'active' });
  } catch { res.status(500).json({ error: 'Could not fetch profile' }); }
});

app.put('/api/auth/profile', authGuard, async (req, res) => {
  const { username, avatar_url, profession } = req.body;
  try {
    await User.findByIdAndUpdate(req.user.id, { username, avatar_url, profession });
    res.json({ success: true });
  } catch { res.status(500).json({ error: 'Could not update profile' }); }
});

app.post('/api/auth/onboarding', authGuard, async (req, res) => {
  const { username, referral_source, profession, usage_type, workspace_name, use_cases } = req.body;
  try {
    const user = await User.findById(req.user.id).select('_id');
    if (!user) return res.status(404).json({ error: 'User not found' });
    const update = { onboarded: true, referral_source: referral_source || null, profession: profession || null };
    if (username) update.username = username;
    if (usage_type) update.usage_type = usage_type;
    if (workspace_name) update.workspace_name = workspace_name;
    if (Array.isArray(use_cases)) update.use_cases = use_cases;
    await User.findByIdAndUpdate(req.user.id, update);
    if (username) await setUserMemory(req.user.id, 'name', username);
    if (profession) await setUserMemory(req.user.id, 'profession', profession);
    logActivity('onboarded', { username: username || req.user.username, user_id: req.user.id });
    res.json({ success: true });
  } catch (err) {
    console.error('[Onboarding]', err);
    if (err.code === 11000) return res.status(409).json({ error: 'This name is already taken. Please try another.' });
    res.status(500).json({ error: 'Could not complete onboarding' });
  }
});

app.post('/api/auth/forgot-password', async (req, res) => {
  const { email } = req.body;
  if (!email) return res.status(400).json({ error: 'Email required' });
  try {
    const user = await User.findOne({ email: email.toLowerCase() });
    if (!user) return res.json({ message: 'If that email exists, a reset code has been sent.' });
    const otp = String(Math.floor(100000 + Math.random() * 900000));
    user.otp_code = otp;
    user.otp_expires = new Date(Date.now() + 15 * 60 * 1000);
    await user.save();
    const sent = await sendOtpEmail(email, user.username, otp);
    if (sent) res.json({ message: 'Reset code sent to your email.' });
    else res.json({ message: 'Email service not configured. Use code below for testing.', demo_otp: otp });
  } catch (err) { console.error('[ForgotPW]', err); res.status(500).json({ error: 'Failed to process request.' }); }
});

app.post('/api/auth/verify-otp', async (req, res) => {
  const { email, otp } = req.body;
  if (!email || !otp) return res.status(400).json({ error: 'Email and code required' });
  try {
    const user = await User.findOne({ email: email.toLowerCase(), otp_code: otp.trim(), otp_expires: { $gt: new Date() } });
    if (!user) return res.status(400).json({ error: 'Invalid or expired code.' });
    const resetToken = crypto.randomBytes(32).toString('hex');
    user.otp_code = null;
    user.otp_expires = null;
    user.reset_token = resetToken;
    user.reset_token_expires = new Date(Date.now() + 10 * 60 * 1000);
    await user.save();
    res.json({ reset_token: resetToken });
  } catch { res.status(500).json({ error: 'Verification failed.' }); }
});

app.post('/api/auth/reset-password', async (req, res) => {
  const { token, password } = req.body;
  if (!token || !password) return res.status(400).json({ error: 'Token and password required' });
  if (password.length < 8) return res.status(400).json({ error: 'Password must be at least 8 characters' });
  try {
    const user = await User.findOne({ reset_token: token, reset_token_expires: { $gt: new Date() } });
    if (!user) return res.status(400).json({ error: 'Invalid or expired reset link. Please request a new one.' });
    user.password_hash = await bcrypt.hash(password, 12);
    user.reset_token = null;
    user.reset_token_expires = null;
    await user.save();
    res.json({ success: true });
  } catch { res.status(500).json({ error: 'Reset failed.' }); }
});

/* ── MEMORY API ──────────────────────────────────────────────── */
app.get('/api/memory', authGuard, async (req, res) => {
  try { res.json(await getUserMemory(req.user.id)); }
  catch { res.json({}); }
});

app.delete('/api/memory/:key', authGuard, async (req, res) => {
  try {
    await UserMemory.deleteOne({ user_id: req.user.id, memory_key: req.params.key });
    res.json({ success: true });
  } catch { res.status(500).json({ error: 'Failed' }); }
});

app.delete('/api/memory', authGuard, async (req, res) => {
  try { await UserMemory.deleteMany({ user_id: req.user.id }); res.json({ success: true }); }
  catch { res.status(500).json({ error: 'Failed' }); }
});

/* ── NOTIFICATIONS (public) ──────────────────────────────────── */
app.get('/api/notifications', async (req, res) => {
  try {
    const notifs = await Notification.find({
      is_active: true,
      $or: [{ expires_at: null }, { expires_at: { $gt: new Date() } }]
    }).sort({ created_at: -1 }).limit(5).lean();
    res.json(fmtArr(notifs));
  } catch { res.json([]); }
});

/* ── PAGE TRACKING ────────────────────────────────────────────── */
app.post('/api/track', async (req, res) => {
  try {
    const { session_id, page } = req.body;
    let userId = null;
    const h = req.headers.authorization;
    if (h?.startsWith('Bearer ')) try { userId = jwt.verify(h.slice(7), JWT_SECRET).id; } catch {}
    await PageView.create({ session_id, page, user_id: userId, ip_address: req.ip, user_agent: (req.headers['user-agent'] || '').slice(0, 255) });
    res.json({ ok: true });
  } catch { res.json({ ok: false }); }
});

/* ══════════════════════════════════════════════════════════════
   CHAT ROUTES
══════════════════════════════════════════════════════════════ */
app.get('/api/chats', authGuard, async (req, res) => {
  try {
    // Two indexed queries total (sidebar perf, §33) — no per-chat N+1.
    const chats = await Chat.find({ user_id: req.user.id }).sort({ updated_at: -1 }).lean();
    const ids = chats.map(c => c._id);
    const stats = ids.length ? await Message.aggregate([
      { $match: { chat_id: { $in: ids }, superseded: { $ne: true } } },
      { $sort: { created_at: -1, _id: -1 } },
      { $group: { _id: '$chat_id', last: { $first: '$content' }, count: { $sum: 1 } } },
    ]) : [];
    const byChat = new Map(stats.map(s => [String(s._id), s]));
    res.json(chats.map(c => ({
      id: c._id.toString(),
      conversation_id: c.conversation_id || null,
      title: c.title,
      is_pinned: !!c.is_pinned,
      mode: c.mode || 'chat',
      model: c.model || null,
      created_at: c.created_at,
      updated_at: c.updated_at,
      last_message: byChat.get(String(c._id))?.last || null,
      message_count: byChat.get(String(c._id))?.count || 0,
    })));
  } catch { res.status(500).json({ error: 'Could not load chats' }); }
});

/* Explicit empty-conversation creation — kept for API compatibility.
   The main UI never calls this: conversations are created lazily with
   the first message (POST /api/chats/messages/stream, §3).           */
app.post('/api/chats', authGuard, async (req, res) => {
  try {
    const chat = await Chat.create({
      user_id: req.user.id,
      title: (req.body.title || 'New Chat').slice(0, 255),
      conversation_id: newConversationId(),
      mode: ['chat', 'agent'].includes(req.body.mode) ? req.body.mode : 'chat',
    });
    logActivity('new_chat', { username: req.user.username, user_id: req.user.id, meta: { chatId: chat._id.toString() } });
    res.status(201).json(fmt(chat));
  } catch { res.status(500).json({ error: 'Could not create chat' }); }
});

app.get('/api/chats/:id', authGuard, async (req, res) => {
  try {
    const chat = await resolveChatParam(req, res);
    if (!chat) return;
    // Superseded messages stay in the database but never load into the
    // active conversation view (§18 branching).
    const messages = await Message.find({ chat_id: chat._id, superseded: { $ne: true } }).sort({ created_at: 1, _id: 1 }).lean();
    const obj = fmt(chat);
    obj.messages = fmtMessageArr(messages);
    res.json(obj);
  } catch { res.status(500).json({ error: 'Could not load chat' }); }
});

app.put('/api/chats/:id', authGuard, async (req, res) => {
  const { title, is_pinned, mode } = req.body;
  const update = {};
  if (title !== undefined)     update.title = title;
  if (is_pinned !== undefined) update.is_pinned = is_pinned;
  if (['chat', 'agent'].includes(mode)) update.mode = mode;
  if (!Object.keys(update).length) return res.status(400).json({ error: 'Nothing to update' });
  try {
    const chat = await resolveChatParam(req, res);
    if (!chat) return;
    await Chat.updateOne({ _id: chat._id }, update);
    res.json({ success: true });
  } catch { res.status(500).json({ error: 'Could not update chat' }); }
});

app.delete('/api/chats/:id', authGuard, async (req, res) => {
  try {
    const chat = await resolveChatParam(req, res);
    if (!chat) return;
    await Message.deleteMany({ chat_id: chat._id });
    await Chat.deleteOne({ _id: chat._id });
    res.json({ success: true });
  } catch { res.status(500).json({ error: 'Could not delete chat' }); }
});

app.delete('/api/chats', authGuard, async (req, res) => {
  try {
    const chats = await Chat.find({ user_id: req.user.id }).select('_id').lean();
    const ids = chats.map(c => c._id);
    if (ids.length) await Message.deleteMany({ chat_id: { $in: ids } });
    await Chat.deleteMany({ user_id: req.user.id });
    res.json({ success: true });
  } catch { res.status(500).json({ error: 'Could not delete chats' }); }
});

/* ── AUTHENTICATED FILE SERVING (ownership-checked, §19) ─────── */
app.get('/api/files/:name', async (req, res) => {
  const name = path.basename(req.params.name); // prevents path traversal
  const filePath = path.join('./uploads', name);
  if (!name || !fs.existsSync(filePath) || !fs.statSync(filePath).isFile())
    return res.status(404).json({ error: 'File not found' });

  const h = req.headers.authorization;
  let adminOk = false, user = null;
  if (h?.startsWith('Bearer ')) {
    const token = h.slice(7);
    try { const d = jwt.verify(token, ADMIN_SECRET); if (d.isAdmin) adminOk = true; } catch {}
    if (!adminOk) { try { user = jwt.verify(token, JWT_SECRET); } catch {} }
  }
  if (!adminOk && !user) return res.status(401).json({ error: 'Unauthorized' });

  if (!adminOk) {
    // Owners only: the file must belong to one of the requester's messages
    const msg = await Message.findOne({
      $or: [{ file_url: `/uploads/${name}` }, { 'attachments.url': `/uploads/${name}` }]
    }).populate('chat_id', 'user_id').lean();
    const ownerId = msg?.chat_id?.user_id?.toString ? msg.chat_id.user_id.toString() : null;
    if (!msg || ownerId !== user.id) return res.status(403).json({ error: 'Forbidden' });
  }

  res.setHeader('Cache-Control', 'private, max-age=86400');
  if (req.query.download === '1') res.setHeader('Content-Disposition', `attachment; filename="${name.split('-').slice(1).join('-') || name}"`);
  res.sendFile(path.resolve(filePath));
});

/* ── Per-chat reply preferences (language / style) ───────────────
   Whitelisted values only — the client never sends free text into the
   system prompt. Returns '' when no valid preference was supplied. */
const REPLY_LANGS = { en:'English', fr:'French', rw:'Kinyarwanda', sw:'Swahili', es:'Spanish', de:'German', ar:'Arabic', zh:'Chinese' };
const REPLY_STYLES = {
  concise:  'Keep answers short and to the point.',
  balanced: '',
  detailed: 'Give thorough, step-by-step answers with examples where useful.',
  code:     'Prioritise working code first, then a brief explanation.',
};
function replyPrefsPrompt(body = {}, headers = {}) {
  const parts = [];
  const lang = REPLY_LANGS[String(body.reply_language || headers['x-reply-language'] || '')];
  const style = REPLY_STYLES[String(body.reply_style || headers['x-reply-style'] || '')];
  if (lang) parts.push(`Always reply in ${lang} unless the user explicitly asks for another language.`);
  if (style) parts.push(style);
  return parts.join(' ');
}

function codeDeliveryPrompt(userText = '') {
  const request = String(userText)
  const asksToBuild = /\b(create|build|make|write|generate|develop|implement|code)\b/i.test(request)
  const namesSoftware = /\b(code|coding|program|programming|html|css|javascript|typescript|react|vue|website|web app|frontend|front-end|backend|component|script|software|app|application|page|landing page)\b/i.test(request)
  if (!asksToBuild || !namesSoftware) return ''

  const singleFile = /\b(single[- ]file|one[- ]file|single html file|one html file|single file)\b/i.test(request)
  return [
    'Code delivery requirements: The user asked you to create or implement software. Deliver the actual complete working source code; do not answer with instructions to copy code, a description without code, or claims that files were created.',
    singleFile
      ? 'The user requested one file. Return exactly one complete file in one fenced code block. Include all required HTML, CSS and JavaScript in that file when applicable.'
      : 'Return every required source file in its own fenced code block. Put its relative filename immediately after the language on the opening fence, for example ```html filename=index.html or ```jsx filename=src/App.jsx. Include all code needed for the requested deliverable.',
    'Use valid Markdown code fences and always close every fence. Keep any explanation brief and outside the code blocks. Never claim that code was executed, tested, or written to disk.'
  ].join(' ')
}

/* ── Shared assistant turn (real Groq streaming, SSE) ──────────
   opts:
     chat         — owning Chat document (freshened + saved)
     send         — SSE writer
     startedAt    — perf clock
     trackType    — UsageTracking request_type
     reservation  — daily-usage reservation (refunded on failure)
     planCfg      — plan configuration (context budget)
     carrier      — EXISTING assistant message being regenerated.
                    When set, the new answer is appended to the
                    carrier's `versions` history instead of creating
                    a new document (§19/§20).
     excludeMessageId — message to leave out of the context window
                    (the carrier itself while it is being replaced).
     searchOutcome — web-search pipeline result for this turn (or
                    null). When it carries real sources, the model
                    receives structured SOURCE blocks + grounding
                    instructions, and the saved answer records the
                    actual queries/URLs (§11/§12/§42). */
async function runAssistantTurn(req, res, { chat, send, startedAt, trackType = 'chat', reservation = null, planCfg = null, carrier = null, excludeMessageId = null, searchOutcome = null }) {
  const abortController = new AbortController();
  let clientClosed = false;
  req.on('close', () => { clientClosed = true; try { abortController.abort(new Error('client closed')); } catch {} });

  const chatId = String(chat._id);
  const memory = await getUserMemory(req.user.id);

  // Context: plan-aware bounded window + budget trim + rolling summary (§5)
  // Higher plans keep more recent messages in context (advancedContext).
  const planContextMult = planCfg?.contextMessages ? Math.min(8, Math.max(1, planCfg.contextMessages / 10)) : 1;
  const planBudgetTokens = Math.round(aiConfig.context.tokenBudget * planContextMult);
  const fullHistory = await chatService.loadHistory(chatId, { maxRows: planCfg?.contextMessages || null, excludeMessageId });
  const { kept, droppedCount } = chatService.trimToBudget(fullHistory, planBudgetTokens);
  const summary = await chatService.ensureSummary(chat, kept, droppedCount);
  const ragContext = cfg.knowledge_base_enabled ? await searchKnowledgeBase(kept[kept.length - 1]?.content || '') : '';
  const documentContext = chatService.findRecentDocumentContext(kept);

  // Multimodal: ALL images attached to the most recent user turn (§8),
  // re-attached from earlier in the conversation for follow-ups (§18)
  const lastUser = [...kept].reverse().find(m => m.role === 'user');
  const imageAtts = (lastUser?.attachments || []).filter(a => a.kind === 'image');
  const imageDataUrls = [];
  if (imageAtts.length) {
    for (const att of imageAtts) {
      try {
        const imgPath = att.url.replace('/uploads', './uploads');
        const b64 = fs.readFileSync(imgPath).toString('base64');
        imageDataUrls.push(`data:${att.mime || 'image/jpeg'};base64,${b64}`);
      } catch (e) {
        console.error('[Stream] image load failed:', e.message);
        send('error', { message: 'KinyaBot could not open the attached image. Please re-attach it and try again.' });
        return res.end();
      }
    }
  }

  // Follow-up about an earlier image: re-attach the most recent one so
  // the model can see it instead of inventing an answer (§18).
  let priorImage = null;
  if (!imageDataUrls.length) {
    const priorAtt = chatService.findRecentImageContext(kept);
    if (priorAtt) {
      try {
        const priorPath = priorAtt.url.replace('/uploads', './uploads');
        const b64 = fs.readFileSync(priorPath).toString('base64');
        priorImage = { name: priorAtt.name, dataUrl: `data:${priorAtt.mime || 'image/jpeg'};base64,${b64}` };
      } catch (e) {
        // File gone (ephemeral disk) — no re-attach; the honesty guard in
        // the system prompt makes the model say it cannot see the image.
        console.warn('[Stream] prior image unavailable:', e.message);
      }
    }
  }

  // Attachment-only turns must still carry a user request, otherwise the
  // model receives a transcript with no trailing user message.
  let userText = lastUser?.content || '';
  if (!userText.trim() && !imageDataUrls.length && !priorImage) {
    const att = lastUser?.attachments?.[0];
    if (att?.kind === 'document') userText = 'Please read the attached document and tell me what it contains.';
    else if (att) userText = 'Please tell me about the file I attached.';
  }

  const prefs = replyPrefsPrompt(req.body, req.headers);
  const codeDelivery = codeDeliveryPrompt(userText);
  // Web-grounded turn (§11): real retrieved sources become structured
  // context + grounding/citation instructions. Performed ONLY when the
  // backend actually searched — never faked (§42).
  const hasWebSources = !!(searchOutcome && searchOutcome.status === 'success' && searchOutcome.sources?.length);
  const searchContext = hasWebSources ? webSearchService.buildSearchContextBlock(searchOutcome) : '';
  const messages = chatService.buildMessages({
    systemPrompt: [
      cfg.system_prompt, prefs, codeDelivery,
      hasWebSources ? webSearchService.GROUNDED_ANSWER_INSTRUCTIONS : '',
    ].filter(Boolean).join('\n\n'), memory, ragContext, searchContext,
    history: kept, summary, documentContext,
    userText,
    imageDataUrls,
    priorImage,
  });
  const hasImages = imageDataUrls.length > 0 || !!priorImage;
  const primaryModel = chatService.pickModel({ imageDataUrl: imageDataUrls[0], priorImage });

  send('start', { streaming: true });

  let aiText = '';
  let usageTokens = null;
  let usedModel = primaryModel;

  /* Run one streaming attempt against a specific model. */
  async function streamOnce(model) {
    const stream = await provider.chatCompleteStream({
      messages, model,
      maxTokens: codeDelivery ? Math.max(Number(cfg.max_tokens) || 2048, 8192) : cfg.max_tokens,
      temperature: cfg.temperature,
      signal: abortController.signal,
    });
    let text = '';
    let tokens = null;
    for await (const chunk of stream) {
      const delta = chunk.choices?.[0]?.delta?.content || '';
      if (chunk.usage?.total_tokens) tokens = chunk.usage.total_tokens;
      if (delta) { text += delta; send('chunk', { text: delta }); }
      if (clientClosed) break;
    }
    return { text, tokens };
  }

  try {
    try {
      const r = await streamOnce(primaryModel);
      aiText = r.text; usageTokens = r.tokens;
    } catch (err) {
      /* Vision robustness (§6/§7): when an image WAS attached and the
         configured model rejects the request (text-only model, retired
         model id, unsupported media part), retry once with the known
         vision-capable fallback before surfacing an error. The user
         must never be told the image "was not attached" because of a
         model configuration problem.                                  */
      const retryable = hasImages && !clientClosed && !aiText &&
        (err?.status === 400 || err?.status === 404 || err?.code === 'AI_MODEL_UNAVAILABLE' ||
         err?.code === 'AI_PROVIDER_ERROR');
      const fallbackModel = chatService.visionFallbackModel(primaryModel);
      if (retryable && fallbackModel) {
        console.warn(`[Stream] vision retry: "${primaryModel}" rejected the image request (${err?.code || err?.status}), retrying with "${fallbackModel}"`);
        const r = await streamOnce(fallbackModel);
        aiText = r.text; usageTokens = r.tokens; usedModel = fallbackModel;
      } else {
        throw err;
      }
    }
  } catch (err) {
    if (!clientClosed) {
      // The AI request failed — give the reserved chat back (§36:
      // failed requests must not count as successful chats).
      await refundReservation(req, reservation);
      throw err;
    }
  }

  // Client cancelled mid-generation → keep the partial answer honestly (§17)
  if (clientClosed) {
    if (aiText.trim()) {
      await saveAssistantResult({ carrier, chatId, content: aiText, model: usedModel, tokens: usageTokens, processingMs: Date.now() - startedAt, status: 'cancelled' });
    }
    return;
  }

  if (!aiText.trim()) {
    await refundReservation(req, reservation);
    const e = new Error('EMPTY_AI_RESPONSE'); e.code = 'EMPTY_AI_RESPONSE'; throw e;
  }

  // Source references ONLY when the backend actually knows them (§7)
  const sources = (!imageDataUrls.length && documentContext)
    ? [`${documentContext.name}${documentContext.pages ? ` (${documentContext.pages} pages)` : ''}`]
    : [];

  // Web-search provenance (§12/§42): attached only when a real search
  // attempt happened this turn (success, empty or unavailable — each
  // is honest information for the UI).
  const webSearchMeta = (searchOutcome && searchOutcome.status !== 'skipped') ? {
    performed: !!searchOutcome.performed,
    mode: searchOutcome.mode === 'manual' ? 'manual' : (searchOutcome.mode === 'agent' ? 'agent' : 'auto'),
    queries: (searchOutcome.queries || []).slice(0, 5),
    sources: (searchOutcome.sources || []).slice(0, 12).map(s => ({
      title: s.title, url: s.url, domain: s.domain,
      snippet: String(s.snippet || '').slice(0, 300),
      published_date: s.published_date || null,
      icon: null,
    })),
    result_count: searchOutcome.resultCount || 0,
    duration_ms: searchOutcome.durationMs || 0,
    status: searchOutcome.status === 'success' ? 'success'
      : searchOutcome.status === 'empty' ? 'empty' : 'unavailable',
    cached: !!searchOutcome.cached,
  } : null;

  const aiMsg = await saveAssistantResult({
    carrier, chatId, content: aiText, model: usedModel, tokens: usageTokens,
    processingMs: Date.now() - startedAt, status: 'completed', sources, provider: aiConfig.provider,
    webSearch: webSearchMeta,
  });
  chat.updated_at = new Date();
  chat.model = usedModel; // conversation remembers the model for restoration (§31)
  await chat.save();
  if (reservation) reservation.completed = true; // AI turn fully served

  const tokens = usageTokens || estimateTokens(messages.map(m => (m.content || (Array.isArray(m.content) ? m.content.map(c => c.text || '').join(' ') : '')).slice(0, 400)).join('\n') + aiText);
  await trackUsage(req.user.id, chatId, tokens, trackType, Date.now() - startedAt, true);
  await extractMemoryFromConversation(req.user.id, lastUser?.content || '', aiText);

  const io = req.app.get('io');
  if (io) {
    io.to(`chat_${chatId}`).emit('new_message', { userMessage: null, aiMessage: fmtMessage(aiMsg), chatId });
    io.to(`user_${req.user.id}`).emit('chat_updated', { chatId });
    // Live usage refresh for the sidebar indicator (§5, §28)
    if (reservation?.usage) {
      io.to(`user_${req.user.id}`).emit('usage_updated', {
        used: reservation.usage.used, limit: reservation.usage.limit,
        remaining: Math.max(0, reservation.usage.limit - reservation.usage.used),
        plan: reservation.usage.plan, state: reservation.usage.state,
      });
    }
  }

  send('done', { aiMessage: fmtMessage(aiMsg), userMessage: null });
  res.end();
}

/* Persist an assistant generation.
   With a carrier (regeneration): append the previous active answer to
   `versions`, then make the new answer active — nothing is destroyed
   and the user can navigate between generations (§20).
   Without one: create a fresh message whose `versions` starts with
   this first generation. `content` ALWAYS mirrors the active version
   so context building keeps working unchanged.                     */
const MAX_RESPONSE_VERSIONS = 10;
async function saveAssistantResult({ carrier, chatId, content, model, tokens, processingMs, status = 'completed', sources = [], provider = null, webSearch = null }) {
  const version = {
    content, model: model || null, tokens: tokens ?? null,
    created_at: new Date(), processing_ms: processingMs, status,
  };
  if (carrier) {
    const versions = Array.isArray(carrier.versions) ? carrier.versions.filter(v => (v.content || '').trim()) : [];
    if (!versions.length) {
      versions.push({
        content: carrier.content || '', model: carrier.model || null, tokens: carrier.tokens ?? null,
        created_at: carrier.created_at || new Date(), processing_ms: carrier.processing_ms ?? null,
        status: carrier.status === 'cancelled' ? 'cancelled' : 'completed',
      });
    }
    versions.push(version);
    carrier.versions = versions.slice(-MAX_RESPONSE_VERSIONS);
    carrier.active_version = carrier.versions.length - 1;
    carrier.content = content;
    carrier.model = version.model;
    carrier.tokens = version.tokens;
    carrier.processing_ms = processingMs;
    carrier.status = status;
    carrier.created_at = new Date();
    // Web-search provenance follows the ACTIVE answer: regenerating
    // replaces it with the newest turn's truth (or clears it when the
    // new answer was not web-grounded) — never stale metadata (§42).
    carrier.web_search = webSearch || null;
    carrier.markModified?.('web_search');
    await carrier.save();
    return carrier;
  }
  return Message.create({
    chat_id: chatId, role: 'assistant', content,
    model: version.model, provider, tokens: version.tokens,
    processing_ms: processingMs, status, sources,
    web_search: webSearch || null,
    versions: [version], active_version: 0,
  });
}

/* Validate + prepare chat attachments (server-side truth, §19).
   Handles MULTIPLE files per message (§13): every file is classified,
   magic-byte validated and turned into a structured attachment meta.
   Images additionally produce base64 data URLs for the vision model.
   Throws user-safe coded errors naming the offending file.        */
function prepareAttachments(req) {
  const files = normalizeUploadedFiles(req);
  if (!files.length) {
    return { metas: [], imageDataUrls: [], messageType: 'text' };
  }

  const metas = [];
  const imageDataUrls = [];
  let hasImage = false, hasDocument = false;

  for (const file of files) {
    const kind = documentService.classify(file.originalname, file.mimetype);
    if (kind === 'unknown')
      throw documentService.coded('UNSUPPORTED_FILE', `"${file.originalname}" is not a supported file type. Attach images, PDF, DOCX, TXT, CSV, JSON or code files.`);
    if (kind === 'audio')
      throw documentService.coded('UNSUPPORTED_FILE', `"${file.originalname}" is an audio file — voice messages are handled by the voice input feature, not chat attachments.`);

    const valid = documentService.validateUpload(file.path, kind, file.originalname);
    const url = `/uploads/${file.filename}`;
    const meta = { kind, url, name: file.originalname, mime: file.mimetype, size: valid.size };

    if (kind === 'image') {
      const b64 = fs.readFileSync(file.path).toString('base64');
      imageDataUrls.push(`data:${file.mimetype};base64,${b64}`);
      hasImage = true;
    } else {
      hasDocument = true;
    }
    metas.push(meta);
  }

  return {
    metas,
    imageDataUrls,
    messageType: hasImage ? 'image' : (hasDocument ? 'document' : 'text'),
  };
}

/* Clean up multer temp files (best-effort) when a request bails out
   before the attachments became part of a saved message. */
function cleanupUploads(req) {
  for (const f of normalizeUploadedFiles(req)) {
    try { if (f?.path && fs.existsSync(f.path)) fs.unlinkSync(f.path); } catch {}
  }
}

/* Validate + prepare ALL uploaded attachments for a turn (§12, §13):
   classification, magic-byte validation, per-plan document size
   limits and text extraction. Throws user-safe coded errors (with
   HTTP status) naming the offending file; temp files are cleaned up
   on every failure.                                                */
async function buildMessageAttachments(req, { planCfg = null, isPro = false } = {}) {
  const files = normalizeUploadedFiles(req);
  if (!files.length) return { metas: [], imageDataUrls: [], messageType: 'text' };

  const docLimit = Math.round(aiConfig.limits.documentSizeBytes * (planCfg?.docSizeMultiplier || 1));
  const metas = [];
  const imageDataUrls = [];
  let hasImage = false, hasDocument = false;

  try {
    for (const file of files) {
      const kind = documentService.classify(file.originalname, file.mimetype);
      if (kind === 'unknown')
        throw documentService.coded('UNSUPPORTED_FILE', `"${file.originalname}" is not a supported file type yet. Attach images, PDF, DOCX, TXT, CSV, JSON or code files.`);
      if (kind === 'audio')
        throw documentService.coded('UNSUPPORTED_FILE', `"${file.originalname}" is an audio file — use the voice input feature instead of chat attachments.`);

      const valid = documentService.validateUpload(file.path, kind, file.originalname);

      if (kind === 'document' && valid.size > docLimit) {
        throw Object.assign(documentService.coded('PLAN_SIZE_LIMIT',
          `"${file.originalname}" is too large for your ${planCfg?.name || 'current'} plan. Maximum document size is ${(docLimit / (1024 * 1024)).toFixed(0)} MB.`), { status: 413, upgradeHint: !isPro });
      }

      const meta = { kind, url: `/uploads/${file.filename}`, name: file.originalname, mime: file.mimetype, size: valid.size };

      if (kind === 'image') {
        const b64 = fs.readFileSync(file.path).toString('base64');
        imageDataUrls.push(`data:${file.mimetype};base64,${b64}`);
        hasImage = true;
      } else {
        // Honest document processing (§14): text is extracted NOW — a
        // failure surfaces before anything is saved or answered.
        const extract = await documentService.extractText(file.path, file.originalname, file.mimetype);
        meta.extracted_text = extract.text;
        meta.pages = extract.pages ?? null;
        hasDocument = true;
      }
      metas.push(meta);
    }
  } catch (err) {
    cleanupUploads(req);
    throw err;
  }

  return { metas, imageDataUrls, messageType: hasImage ? 'image' : (hasDocument ? 'document' : 'text') };
}

/* Shared send-message turn (SSE). Used by BOTH:
   • POST /api/chats/messages/stream          (lazy conversation create, §3)
   • POST /api/chats/:id/messages/stream      (existing conversation)
   Runs every validation BEFORE the daily-usage reservation, which
   itself runs before any SSE output — so rejections are plain JSON
   and over-limit requests never reach the AI provider (§3, §36).  */
async function handleChatMessageTurn(req, res, { chat = null, isNew = false }) {
  const content = typeof req.body?.content === 'string' ? req.body.content.trim() : '';
  let chatId = chat ? String(chat._id) : null;

  const prepared = await buildMessageAttachments(req, {
    planCfg: req._planCfg, isPro: req._plan === 'pro',
  });
  if (!content && !prepared.metas.length) {
    cleanupUploads(req);
    return res.status(400).json({ error: 'Message or attachment required' });
  }

  if (content) {
    const mod = await moderateContent(content);
    if (mod.flagged) {
      cleanupUploads(req);
      await FlaggedContent.create({ chat_id: chatId, user_id: req.user.id, reason: mod.reason, auto_flagged: true });
      return res.status(400).json({ error: 'Your message was flagged. Please keep conversations respectful.' });
    }
  }

  /* Conversation mode (§30): chat | web_search | agent. An EXPLICIT
     'web_search' mode is Pro-only — resolved SERVER-SIDE before any
     conversation/usage side effects so an unentitled request never
     reaches LangSearch nor consumes allowance (§2). Invalid/omitted
     modes never silently flip an existing conversation's mode.     */
  const requestedMode = CHAT_MODES.includes(req.body?.mode) ? req.body.mode : null;
  const effectiveMode = requestedMode || chat?.mode || 'chat';
  const { trigger } = await resolveSearchTrigger(req, res, { mode: effectiveMode, plan: req._plan });
  if (requestedMode === 'web_search' && trigger === null) return; // 403 already sent

  /* Lazy creation (§3) happens ONLY after every pre-AI validation has
     passed — a rejected request (bad file, flagged text) must never
     leave an empty conversation behind. */
  if (isNew && !chat) {
    for (let attempt = 0; attempt < 3 && !chat; attempt++) {
      try {
        chat = await Chat.create({ user_id: req.user.id, title: 'New Chat', conversation_id: newConversationId(), mode: effectiveMode });
      } catch (err) {
        // Duplicate conversation_id — regenerate and retry (astronomically rare)
        if (err?.code !== 11000) throw err;
      }
    }
    if (!chat) return res.status(500).json({ error: 'Could not create the conversation. Please try again.' });
    chatId = String(chat._id);
    logActivity('new_chat', { username: req.user.username, user_id: req.user.id, meta: { chatId } });
  }

  // Atomic daily-chat reservation — AFTER every validation, BEFORE the
  // AI call (§3, §36). Rejected requests never consume allowance.
  const reservation = await reserveChatUsage(req, res);
  if (!reservation) {
    cleanupUploads(req);
    // Roll the freshly-created row back — over-limit requests must not
    // create phantom empty conversations.
    if (isNew && chat) { try { await Chat.deleteOne({ _id: chat._id }); } catch {} }
    return;
  }

  res.setHeader('Content-Type', 'text/event-stream');
  res.setHeader('Cache-Control', 'no-cache');
  res.setHeader('Connection', 'keep-alive');
  res.setHeader('X-Accel-Buffering', 'no');
  res.flushHeaders();

  const send = (event, data) => res.write(`event: ${event}\ndata: ${JSON.stringify(data)}\n\n`);

  // Lazy-create flow: hand the public conversation id to the client
  // FIRST so it can navigate to /chat/c/{conversationId} immediately (§3).
  if (isNew) {
    send('conversation', {
      conversationId: chat.conversation_id,
      chatId,
      title: chat.title,
      mode: chat.mode,
    });
  }

  // Mode persistence (§31/§32): a VALID, explicitly-sent mode updates
  // the conversation ('chat' | 'web_search' | 'agent'); omitted or
  // invalid modes leave the conversation's persisted mode untouched.
  if (requestedMode && requestedMode !== chat.mode) chat.mode = requestedMode;

  const userMsg = await Message.create({
    chat_id: chatId, role: 'user', content,
    file_url: prepared.metas[0]?.url || null,
    message_type: prepared.messageType,
    attachments: prepared.metas,
  });
  send('user_message', fmtMessage(userMsg));
  logActivity('message', { username: req.user.username, user_id: req.user.id, meta: { chatId } });

  // Auto-title from the first message (or first attachment name)
  const msgCount = await Message.countDocuments({ chat_id: chatId });
  if (msgCount <= 1) {
    const title = content ? content.slice(0, 60) : (prepared.metas[0]?.name || 'New Chat').replace(/\.[a-z0-9]+$/i, '').slice(0, 60);
    if (title && title !== chat.title) chat.title = title;
  }
  await chat.save();

  const trackType = prepared.messageType === 'image' ? 'image' : (prepared.messageType === 'document' ? 'document' : 'chat');

  /* Web Search pipeline (§7) — runs AFTER the user message is saved
     (so the decision/optimizer see prior turns) and BEFORE the model
     call. Live progress streams to the client; the outcome grounds
     the answer and is persisted on it (§11/§12). Auto mode may skip
     (no search needed) with zero side effects.                    */
  let searchOutcome = null;
  if (trigger) {
    const history = await recentTurnHistory(chatId, String(userMsg._id));
    searchOutcome = await runTurnSearch(req, res, {
      send, chat, userText: content || userMsg.content || '', history, trigger, plan: req._plan,
    });
  }

  await runAssistantTurn(req, res, { chat, send, startedAt: Date.now(), trackType, reservation, planCfg: req._planCfg, searchOutcome });
}

/* Shared pre-turn checks for message endpoints (plan status + burst
   limits). Attaches req._plan / req._planCfg for downstream helpers. */
async function preflightTurn(req, res, { withUploadLimiter = false } = {}) {
  const { plan, planStatus, planCfg } = await getPlanContext(req.user.id);
  if (!['active', 'pending'].includes(planStatus)) {
    res.status(403).json({ error: 'Your subscription is not active. Please contact support.', code: 'SUBSCRIPTION_INACTIVE' });
    return false;
  }
  const mult = planCfg?.burstMultiplier || 1;
  const rl = rateLimiter.allow(req.user.id, 'chat', {
    limit: Math.round(aiConfig.rateLimits.chat.limit * mult),
    windowMs: aiConfig.rateLimits.chat.windowMs,
  });
  if (!rl.ok) { rateLimiter.tooMany(res, rl.retryAfterSec); return false; }
  if (withUploadLimiter && normalizeUploadedFiles(req).length) {
    const ul = rateLimiter.allow(req.user.id, 'upload', {
      limit: Math.round(aiConfig.rateLimits.upload.limit * mult),
      windowMs: aiConfig.rateLimits.upload.windowMs,
    });
    if (!ul.ok) { rateLimiter.tooMany(res, ul.retryAfterSec); return false; }
  }
  req._plan = plan; req._planCfg = planCfg;
  return true;
}

/* ── SEND MESSAGE — FIRST message CREATES the conversation (§3) ─
   POST /api/chats/messages/stream
   No empty conversations are ever created from the UI: the chat row
   is inserted here, with its UUID conversation_id, then the turn
   proceeds exactly like an existing-conversation send.             */
app.post('/api/chats/messages/stream', authGuard, uploadChatFields, async (req, res) => {
  try {
    if (!(await preflightTurn(req, res, { withUploadLimiter: true }))) { cleanupUploads(req); return; }

    const hasFiles = normalizeUploadedFiles(req).length > 0;
    if (!String(req.body?.content || '').trim() && !hasFiles)
      return res.status(400).json({ error: 'Message or attachment required' });

    await handleChatMessageTurn(req, res, { chat: null, isNew: true });
  } catch (err) {
    cleanupUploads(req);
    console.error('[ConversationCreate]', err);
    if (!res.headersSent) return res.status(httpErrorStatus(err)).json({ error: friendlyError(err) });
    try { res.write(`event: error\ndata: ${JSON.stringify({ message: friendlyError(err) })}\n\n`); res.end(); } catch { res.end(); }
  }
});

/* ── SEND MESSAGE to an EXISTING conversation (SSE Streaming) ──
   :id accepts the public conversation_id (UUID) or a Mongo id —
   both ownership-checked server-side (§5).                        */
app.post('/api/chats/:id/messages/stream', authGuard, uploadChatFields, async (req, res) => {
  try {
    if (!(await preflightTurn(req, res, { withUploadLimiter: true }))) { cleanupUploads(req); return; }

    const chat = await resolveChatParam(req, res);
    if (!chat) { cleanupUploads(req); return; }

    await handleChatMessageTurn(req, res, { chat, isNew: false });
  } catch (err) {
    cleanupUploads(req);
    console.error('[Stream]', err);
    await refundReservation(req, req._reservation || null);
    if (!res.headersSent) {
      if (err?.code === 'CONVERSATION_NOT_FOUND')
        return res.status(404).json({ error: friendlyError(err), code: err.code });
      return res.status(httpErrorStatus(err)).json({ error: friendlyError(err) });
    }
    try {
      res.write(`event: error\ndata: ${JSON.stringify({ message: friendlyError(err) })}\n\n`);
      res.end();
    } catch { res.end(); }
  }
});

/* ── REGENERATE a response (SSE, §19/§20) ──────────────────────
   POST /api/chats/:id/messages/:messageId/regenerate
   messageId = the USER message whose answer is regenerated.
   • Latest answer regenerated → its document becomes the "carrier":
     the previous answer is preserved as a version (‹ n/m › nav),
     the new answer becomes active. Nothing is destroyed on failure.
   • Mid-conversation regenerate → everything after that turn is
     superseded (branch reset), a fresh answer is generated.        */
async function handleRegenerate(req, res, { chat, targetUserMsg }) {
  // Web Search entitlement for the conversation's persisted mode (§30):
  // a 'web_search' conversation re-searches on regenerate ONLY while
  // the account still holds the entitlement — otherwise the turn
  // degrades to a normal chat answer (no mid-stream failure).
  let searchTrigger = null;
  if (chat.mode === 'web_search') {
    if (await webSearchEntitled(req._plan)) searchTrigger = 'manual';
  } else if (chat.mode === 'agent' && (await webSearchEntitled(req._plan))) {
    searchTrigger = 'agent';
  } else if (cfg.web_search_enabled && cfg.web_search_auto_enabled && (await webSearchEntitled(req._plan))) {
    searchTrigger = 'auto';
  }

  // Usage reservation FIRST — a reached daily limit must never mutate
  // the visible conversation (the old answer stays exactly as it was).
  const reservation = await reserveChatUsage(req, res);
  if (!reservation) return;

  res.setHeader('Content-Type', 'text/event-stream');
  res.setHeader('Cache-Control', 'no-cache');
  res.setHeader('Connection', 'keep-alive');
  res.setHeader('X-Accel-Buffering', 'no');
  res.flushHeaders();
  const send = (event, data) => res.write(`event: ${event}\ndata: ${JSON.stringify(data)}\n\n`);
  send('user_message', fmtMessage(targetUserMsg));

  // Active assistant answers after the target user message
  const activeAfter = await Message.find({
    chat_id: chat._id, role: 'assistant', superseded: { $ne: true }, _id: { $gt: targetUserMsg._id },
  }).sort({ created_at: 1, _id: 1 }).select('content model tokens created_at processing_ms status versions').lean();

  // Later USER turns still visible? → regenerating an older branch
  const laterUserCount = await Message.countDocuments({
    chat_id: chat._id, role: 'user', superseded: { $ne: true }, _id: { $gt: targetUserMsg._id },
  });

  let carrier = null;
  if (laterUserCount > 0) {
    // Branch reset: hide everything after the target turn (§18) — the
    // data stays in the database, the conversation view stays clean.
    await Message.updateMany(
      { chat_id: chat._id, _id: { $gt: targetUserMsg._id }, superseded: { $ne: true } },
      { $set: { superseded: true } }
    );
  } else if (activeAfter.length) {
    // Normal regenerate of the newest answer — reuse its document as
    // the version carrier. Legacy duplicate assistants are removed.
    const newest = activeAfter[activeAfter.length - 1];
    carrier = await Message.findById(newest._id);
    const extraIds = activeAfter.slice(0, -1).map(m => m._id);
    if (extraIds.length) await Message.deleteMany({ _id: { $in: extraIds } });
  }

  await runAssistantTurn(req, res, {
    chat, send, startedAt: Date.now(), trackType: 'regenerate',
    reservation, planCfg: req._planCfg, carrier,
    excludeMessageId: carrier?._id || null,
    searchOutcome: await (searchTrigger ? runTurnSearch(req, res, {
      send, chat, userText: targetUserMsg.content || '',
      history: await recentTurnHistory(String(chat._id), String(targetUserMsg._id)),
      trigger: searchTrigger, plan: req._plan,
    }) : Promise.resolve(null)),
  });
}

app.post('/api/chats/:id/messages/:messageId/regenerate', authGuard, async (req, res) => {
  try {
    if (!(await preflightTurn(req, res))) return;
    const chat = await resolveChatParam(req, res);
    if (!chat) return;
    const targetUserMsg = await Message.findOne({ _id: req.params.messageId, chat_id: chat._id, role: 'user', superseded: { $ne: true } });
    if (!targetUserMsg) return res.status(404).json({ error: 'Message not found', code: 'MESSAGE_NOT_FOUND' });
    await handleRegenerate(req, res, { chat, targetUserMsg });
  } catch (err) {
    console.error('[Regenerate:msg]', err);
    if (!res.headersSent) return res.status(httpErrorStatus(err)).json({ error: friendlyError(err) });
    try { res.write(`event: error\ndata: ${JSON.stringify({ message: friendlyError(err) })}\n\n`); res.end(); } catch { res.end(); }
  }
});

/* ── REGENERATE the LAST response (SSE, legacy-compatible path) ── */
app.post('/api/chats/:id/regenerate/stream', authGuard, async (req, res) => {
  try {
    if (!(await preflightTurn(req, res))) return;
    const chat = await resolveChatParam(req, res);
    if (!chat) return;
    const lastUser = await Message.findOne({ chat_id: chat._id, role: 'user', superseded: { $ne: true } })
      .sort({ created_at: -1, _id: -1 });
    if (!lastUser) return res.status(400).json({ error: 'Nothing to regenerate yet.' });
    await handleRegenerate(req, res, { chat, targetUserMsg: lastUser });
  } catch (err) {
    console.error('[Regenerate]', err);
    if (!res.headersSent) return res.status(httpErrorStatus(err)).json({ error: friendlyError(err) });
    try { res.write(`event: error\ndata: ${JSON.stringify({ message: friendlyError(err) })}\n\n`); res.end(); } catch { res.end(); }
  }
});

/* ── SPEECH-TO-TEXT (voice input, §11/§12) ───────────────────── */
app.post('/api/stt', authGuard, uploadAudio.single('audio'), async (req, res) => {
  // Plan feature gate (§27) — voiceAccess is a per-plan capability flag
  if (!(await featureGuard(req, res, 'voiceAccess', 'Voice input is not included in your current plan. Upgrade to enable it.'))) return;
  const rl = rateLimiter.allow(req.user.id, 'stt', aiConfig.rateLimits.stt);
  if (!rl.ok) return rateLimiter.tooMany(res, rl.retryAfterSec);
  if (!req.file) return res.status(400).json({ error: 'No audio received.' });
  const filePath = req.file.path;
  try {
    try { documentService.validateUpload(filePath, 'audio', req.file.originalname); }
    catch (err) { return res.status(400).json({ error: friendlyError(err) }); }
    const result = await speechService.transcribe(filePath);
    await trackUsage(req.user.id, null, estimateTokens(result.text || ''), 'stt', 0, true);
    res.json({ text: result.text, language: result.language, duration: result.duration });
  } catch (err) {
    console.error('[STT]', err.code || '', err.message);
    await trackUsage(req.user.id, null, 0, 'stt', 0, false);
    res.status(502).json({ error: friendlyError(err) });
  } finally {
    try { fs.unlinkSync(filePath); } catch {}
  }
});

/* ── TEXT-TO-SPEECH (voice output, §13) ──────────────────────── */
app.post('/api/tts', authGuard, async (req, res) => {
  if (!(await featureGuard(req, res, 'voiceAccess', 'Voice output is not included in your current plan. Upgrade to enable it.'))) return;
  const rl = rateLimiter.allow(req.user.id, 'tts', aiConfig.rateLimits.tts);
  if (!rl.ok) return rateLimiter.tooMany(res, rl.retryAfterSec);
  const { text } = req.body;
  if (!text || !String(text).trim()) return res.status(400).json({ error: 'Text required.' });
  try {
    const { buffer, model, format } = await speechService.synthesize(String(text));
    await trackUsage(req.user.id, null, estimateTokens(String(text)), 'tts', 0, true);
    res.setHeader('Content-Type', format === 'mp3' ? 'audio/mpeg' : 'audio/wav');
    res.setHeader('X-TTS-Model', model);
    res.send(buffer);
  } catch (err) {
    console.error('[TTS]', err.code || '', err.message);
    await trackUsage(req.user.id, null, 0, 'tts', 0, false);
    res.status(err?.code === 'TTS_TOO_LONG' || err?.code === 'TTS_EMPTY_INPUT' ? 400 : 502).json({ error: friendlyError(err) });
  }
});

/* ── SEND MESSAGE (non-streaming fallback) ───────────────────── */
app.post('/api/chats/:id/messages', authGuard, uploadChatFields, async (req, res) => {
  const content = typeof req.body?.content === 'string' ? req.body.content.trim() : '';
  const startTime = Date.now();

  if (!(await preflightTurn(req, res, { withUploadLimiter: true }))) { cleanupUploads(req); return; }
  const plan = req._plan, planCfg = req._planCfg;

  /* Web Search mode gate (§2) — BEFORE any side effects, same as the
     streaming path: an unentitled manual search never reaches
     LangSearch and never consumes allowance. */
  const requestedMode = CHAT_MODES.includes(req.body?.mode) ? req.body.mode : null;
  const { trigger: searchTrigger } = await resolveSearchTrigger(req, res, { mode: requestedMode || 'chat', plan });
  if (requestedMode === 'web_search' && searchTrigger === null) return; // 403 already sent

  let reservation = null;
  try {
    const chat = await resolveChatParam(req, res);
    if (!chat) { cleanupUploads(req); return; }
    const chatId = String(chat._id);

    const prepared = await buildMessageAttachments(req, { planCfg, isPro: plan === 'pro' });
    if (!content && !prepared.metas.length) {
      cleanupUploads(req);
      return res.status(400).json({ error: 'Message or attachment required' });
    }

    if (content) {
      const mod = await moderateContent(content);
      if (mod.flagged) {
        cleanupUploads(req);
        await FlaggedContent.create({ chat_id: chatId, user_id: req.user.id, reason: mod.reason, auto_flagged: true });
        return res.status(400).json({ error: 'Message flagged. Please keep conversations respectful.' });
      }
    }

    // Atomic daily-chat reservation (§3, §36) — after validations,
    // before any AI provider call.
    reservation = await reserveChatUsage(req, res);
    if (!reservation) { cleanupUploads(req); return; }

    const userMsg = await Message.create({
      chat_id: chatId, role: 'user', content,
      file_url: prepared.metas[0]?.url || null,
      message_type: prepared.messageType,
      attachments: prepared.metas,
    });
    logActivity('message', { username: req.user.username, user_id: req.user.id, meta: { chatId } });

    const msgCount = await Message.countDocuments({ chat_id: chatId });
    if (msgCount <= 1) {
      const title = content ? content.slice(0, 60) : (prepared.metas[0]?.name || 'New Chat');
      if (title && title !== chat.title) { chat.title = title; }
    }
    // Mode persistence (§30) — same rules as the streaming path.
    if (requestedMode && requestedMode !== chat.mode) chat.mode = requestedMode;

    /* Web Search pipeline (§7) — synchronous variant of the SSE flow.
       Skipped decisions produce no events and no log rows.          */
    let searchOutcome = null;
    if (searchTrigger) {
      searchOutcome = await webSearchService.runWebSearch({
        userText: content || userMsg.content || '',
        userId: req.user.id,
        history: await recentTurnHistory(chatId, String(userMsg._id)),
        trigger: searchTrigger,
      });
      if (searchOutcome.status !== 'skipped') {
        await logSearchAttempt({ req, chat, userText: content || userMsg.content || '', outcome: searchOutcome, plan });
      }
    }

    // Context via AI Core (plan-aware bounded window + budget + rolling summary)
    const planContextMult = planCfg?.contextMessages ? Math.min(8, Math.max(1, planCfg.contextMessages / 10)) : 1;
    const fullHistory = await chatService.loadHistory(chatId, { maxRows: planCfg?.contextMessages || null });
    const { kept, droppedCount } = chatService.trimToBudget(fullHistory, Math.round(aiConfig.context.tokenBudget * planContextMult));
    const summary = await chatService.ensureSummary(chat, kept, droppedCount);
    const memory = await getUserMemory(req.user.id);
    const ragCtx = cfg.knowledge_base_enabled && content ? await searchKnowledgeBase(content) : '';
    const documentContext = chatService.findRecentDocumentContext(kept);

    // Vision turn (image understanding — new attachments or re-attached prior image)
    let result;
    let priorImage = null;
    if (!prepared.imageDataUrls.length) {
      const priorAtt = chatService.findRecentImageContext(kept);
      if (priorAtt) {
        try {
          const priorPath = priorAtt.url.replace('/uploads', './uploads');
          const b64 = fs.readFileSync(priorPath).toString('base64');
          priorImage = { name: priorAtt.name, dataUrl: `data:${priorAtt.mime || 'image/jpeg'};base64,${b64}` };
        } catch (e) { console.warn('[Message] prior image unavailable:', e.message); }
      }
    }

    try {
      if (prepared.imageDataUrls.length || priorImage) {
        const historyText = kept.filter(m => !(String(m._id) === String(userMsg._id)) && m.content?.trim())
          .slice(-6).map(m => ({ role: m.role, content: m.content.trim() }));
        result = await provider.visionComplete({
          prompt: content || (prepared.imageDataUrls.length ? 'What is in this image? Describe it in detail.' : `Tell me more about this image (${priorImage.name}).`),
          imageDataUrl: prepared.imageDataUrls[0] || priorImage.dataUrl,
          history: historyText, systemPrompt: cfg.system_prompt,
          maxTokens: cfg.max_tokens, temperature: cfg.temperature,
        });
      } else {
        const hasWebSources = !!(searchOutcome && searchOutcome.status === 'success' && searchOutcome.sources?.length);
        const messages = chatService.buildMessages({
          systemPrompt: [
            cfg.system_prompt,
            hasWebSources ? webSearchService.GROUNDED_ANSWER_INSTRUCTIONS : '',
          ].filter(Boolean).join('\n\n'),
          memory, ragContext: ragCtx,
          searchContext: hasWebSources ? webSearchService.buildSearchContextBlock(searchOutcome) : '',
          history: kept, summary, documentContext,
          userText: content || '',
        });
        result = await provider.chatComplete({
          messages, model: chatService.pickModel({}),
          maxTokens: cfg.max_tokens, temperature: cfg.temperature,
        });
      }
    } catch (err) {
      // AI never produced a usable answer — refund the reservation (§36)
      await refundReservation(req, reservation);
      throw err;
    }
    const aiText = result?.text || '';
    if (!aiText.trim()) {
      await refundReservation(req, reservation);
      return res.status(502).json({ error: friendlyError(new Error('EMPTY_AI_RESPONSE')) });
    }
    if (reservation) reservation.completed = true;

    const sources = (!prepared.imageDataUrls.length && documentContext)
      ? [`${documentContext.name}${documentContext.pages ? ` (${documentContext.pages} pages)` : ''}`]
      : [];

    const webSearchMeta = (searchOutcome && searchOutcome.status !== 'skipped') ? {
      performed: !!searchOutcome.performed,
      mode: searchOutcome.mode === 'manual' ? 'manual' : (searchOutcome.mode === 'agent' ? 'agent' : 'auto'),
      queries: (searchOutcome.queries || []).slice(0, 5),
      sources: (searchOutcome.sources || []).slice(0, 12).map(s => ({
        title: s.title, url: s.url, domain: s.domain,
        snippet: String(s.snippet || '').slice(0, 300),
        published_date: s.published_date || null, icon: null,
      })),
      result_count: searchOutcome.resultCount || 0,
      duration_ms: searchOutcome.durationMs || 0,
      status: searchOutcome.status === 'success' ? 'success'
        : searchOutcome.status === 'empty' ? 'empty' : 'unavailable',
      cached: !!searchOutcome.cached,
    } : null;

    const aiMsg = await saveAssistantResult({
      chatId, content: aiText, model: result.model, tokens: result.tokens,
      processingMs: Date.now() - startTime, status: 'completed', sources, provider: aiConfig.provider,
      webSearch: webSearchMeta,
    });
    chat.updated_at = new Date();
    chat.model = result.model;
    await chat.save();

    const tokens = result.tokens || estimateTokens(kept.map(m => m.content).join('\n') + aiText);
    await trackUsage(req.user.id, chatId, tokens, prepared.messageType === 'image' ? 'image' : 'chat', Date.now() - startTime, true);
    await extractMemoryFromConversation(req.user.id, content || '', aiText);

    const io = req.app.get('io');
    if (io) {
      io.to(`chat_${chatId}`).emit('new_message', { userMessage: fmtMessage(userMsg), aiMessage: fmtMessage(aiMsg), chatId });
      io.to(`user_${req.user.id}`).emit('chat_updated', { chatId });
    }
    res.json({ userMessage: fmtMessage(userMsg), aiMessage: fmtMessage(aiMsg) });
  } catch (err) {
    console.error('[Message]', err);
    if (err?.userSafe) return res.status(err?.status || 400).json({ error: err.message, code: err.code || undefined, upgradeHint: err.upgradeHint });
    res.status(500).json({ error: friendlyError(err) });
  }
});

/* ── EDIT a sent message (§17/§18/§22) ─────────────────────────
   PATCH /api/chats/:id/messages/:messageId
   User messages only. Accepts JSON (text-only edit) or multipart
   (attachment changes: new files[] + keep_attachments url list).
   Everything AFTER the edited turn is superseded (branch reset,
   §18) — preserved in the database, hidden from the conversation.
   The client then triggers regeneration of the response.          */
app.patch('/api/chats/:id/messages/:messageId', authGuard, uploadChatFields, async (req, res) => {
  try {
    const planCtx = await getPlanContext(req.user.id);
    if (!['active', 'pending'].includes(planCtx.planStatus))
      return res.status(403).json({ error: 'Your subscription is not active. Please contact support.', code: 'SUBSCRIPTION_INACTIVE' });

    const chat = await resolveChatParam(req, res);
    if (!chat) { cleanupUploads(req); return; }

    const msg = await Message.findOne({ _id: req.params.messageId, chat_id: chat._id });
    if (!msg || msg.superseded) { cleanupUploads(req); return res.status(404).json({ error: 'Message not found', code: 'MESSAGE_NOT_FOUND' }); }
    if (msg.role !== 'user') { cleanupUploads(req); return res.status(400).json({ error: 'Only your own messages can be edited.' }); }

    // Edited text (optional when attachments are being adjusted)
    const newContent = typeof req.body?.content === 'string' ? req.body.content.trim() : null;

    // Existing attachments: keep list (urls) — default keeps everything
    let keptAttachments = [...(msg.attachments || [])];
    if (typeof req.body?.keep_attachments === 'string') {
      let keepUrls = null;
      try { keepUrls = JSON.parse(req.body.keep_attachments); } catch {}
      if (Array.isArray(keepUrls)) {
        const wanted = new Set(keepUrls.map(u => String(u)));
        keptAttachments = keptAttachments.filter(a => wanted.has(String(a.url)));
      }
    }

    // New attachments (validated + extracted exactly like a fresh send)
    const prepared = await buildMessageAttachments(req, {
      planCfg: planCtx.planCfg, isPro: planCtx.plan === 'pro',
    });

    const finalAttachments = [...keptAttachments, ...prepared.metas];
    const finalContent = newContent !== null ? newContent : msg.content;
    if (!finalContent && !finalAttachments.length) {
      cleanupUploads(req);
      return res.status(400).json({ error: 'An edited message needs text or at least one attachment.' });
    }

    msg.edit_history.push({ content: msg.content, edited_at: new Date() });
    msg.content = finalContent;
    msg.attachments = finalAttachments;
    msg.file_url = finalAttachments[0]?.url || null;
    const hasImage = finalAttachments.some(a => a.kind === 'image');
    const hasDocument = finalAttachments.some(a => a.kind === 'document');
    msg.message_type = hasImage ? 'image' : (hasDocument ? 'document' : 'text');
    await msg.save();

    // Branch reset (§18): hide everything after the edited turn.
    const result = await Message.updateMany(
      { chat_id: chat._id, _id: { $gt: msg._id }, superseded: { $ne: true } },
      { $set: { superseded: true } }
    );

    const io = req.app.get('io');
    if (io) io.to(`chat_${String(chat._id)}`).emit('message_updated', { chatId: String(chat._id), userMessage: fmtMessage(msg) });

    res.json({
      userMessage: fmtMessage(msg),
      removedResponses: result.modifiedCount || 0,
      chat: { id: String(chat._id), conversation_id: chat.conversation_id, title: chat.title, mode: chat.mode },
    });
  } catch (err) {
    cleanupUploads(req);
    console.error('[EditMessage]', err);
    if (err?.userSafe) return res.status(err?.status || 400).json({ error: err.message, code: err.code || undefined, upgradeHint: err.upgradeHint });
    res.status(500).json({ error: friendlyError(err) });
  }
});

/* ── SWITCH the active response version (§20) ──────────────────
   PATCH /api/messages/:id  { version: index }                     */
app.patch('/api/messages/:id', authGuard, async (req, res) => {
  try {
    const msg = await Message.findById(req.params.id);
    if (!msg) return res.status(404).json({ error: 'Message not found' });
    const chat = await Chat.findOne({ _id: msg.chat_id, user_id: req.user.id });
    if (!chat) return res.status(403).json({ error: 'Forbidden' });

    if (msg.role !== 'assistant' || !Array.isArray(msg.versions) || !msg.versions.length)
      return res.status(400).json({ error: 'This message has no alternative responses.' });
    const idx = Number(req.body?.version);
    if (!Number.isInteger(idx) || idx < 0 || idx >= msg.versions.length)
      return res.status(400).json({ error: 'Invalid response version.' });

    const v = msg.versions[idx];
    msg.active_version = idx;
    msg.content = v.content;
    msg.model = v.model;
    msg.tokens = v.tokens;
    msg.status = v.status || 'completed';
    await msg.save();

    const io = req.app.get('io');
    if (io) io.to(`chat_${String(chat._id)}`).emit('message_updated', { chatId: String(chat._id), aiMessage: fmtMessage(msg) });
    res.json({ success: true, message: fmtMessage(msg) });
  } catch { res.status(500).json({ error: 'Could not switch response version' }); }
});

app.delete('/api/messages/:id', authGuard, async (req, res) => {
  try {
    const msg = await Message.findById(req.params.id);
    if (!msg) return res.status(404).json({ error: 'Message not found' });
    const chat = await Chat.findOne({ _id: msg.chat_id, user_id: req.user.id });
    if (!chat) return res.status(403).json({ error: 'Forbidden' });

    if (msg.role === 'user') {
      // Deleting a user message also removes its answer(s) from the
      // visible thread — superseded, not destroyed (§21: never
      // accidentally delete the user's preceding message).
      const later = await Message.find({ chat_id: msg.chat_id, _id: { $gt: msg._id } })
        .sort({ created_at: 1, _id: 1 }).select('role').lean();
      const orphanIds = [];
      for (const m of later) {
        if (m.role === 'user') break; // answers of the NEXT turn stay
        orphanIds.push(m._id);
      }
      if (orphanIds.length)
        await Message.updateMany({ _id: { $in: orphanIds } }, { $set: { superseded: true } });
    }
    await Message.deleteOne({ _id: req.params.id });
    const io = req.app.get('io');
    if (io) io.to(`chat_${String(msg.chat_id)}`).emit('message_deleted', { chatId: String(msg.chat_id), messageId: String(msg._id) });
    res.json({ success: true });
  } catch { res.status(500).json({ error: 'Could not delete message' }); }
});

app.get('/api/search', authGuard, async (req, res) => {
  const { q } = req.query;
  if (!q) return res.json([]);
  try {
    const userChats = await Chat.find({ user_id: req.user.id }).select('_id title conversation_id').lean();
    const chatIds = userChats.map(c => c._id);
    const chatMap = {};
    userChats.forEach(c => { chatMap[c._id.toString()] = { title: c.title, conversation_id: c.conversation_id || null }; });
    const messages = await Message.find({
      chat_id: { $in: chatIds },
      superseded: { $ne: true },
      content: { $regex: q, $options: 'i' }
    }).sort({ created_at: -1 }).limit(20).lean();
    const result = messages.map(m => ({
      ...m, id: m._id.toString(), _id: undefined,
      chat_id: m.chat_id.toString(),
      chat_title: chatMap[m.chat_id.toString()]?.title || 'Unknown',
      chat_conversation_id: chatMap[m.chat_id.toString()]?.conversation_id || null,
    }));
    res.json(result);
  } catch { res.json([]); }
});

app.get('/api/stats', authGuard, async (req, res) => {
  try {
    const userChats = await Chat.find({ user_id: req.user.id }).select('_id').lean();
    const chatIds = userChats.map(c => c._id);
    const total_chats = userChats.length;
    const total_messages = await Message.countDocuments({ chat_id: { $in: chatIds } });
    const tokenAgg = await UsageTracking.aggregate([
      { $match: { user_id: new mongoose.Types.ObjectId(req.user.id) } },
      { $group: { _id: null, total: { $sum: '$tokens_used' } } }
    ]);
    const total_tokens = tokenAgg[0]?.total || 0;
    res.json({ total_chats, total_messages, total_tokens });
  } catch { res.json({ total_chats: 0, total_messages: 0, total_tokens: 0 }); }
});

/* ── WEB SEARCH HISTORY (user-facing, §21) ────────────────────
   The caller's OWN search metadata only — queries, trigger, status
   and source domains. Never includes other users' rows and never
   the retrieved webpage contents.                              */
app.get('/api/web-search/history', authGuard, async (req, res) => {
  try {
    const limit = Math.min(50, Math.max(1, parseInt(req.query.limit, 10) || 20));
    const rows = await SearchLog.find({ user_id: req.user.id })
      .sort({ created_at: -1 }).limit(limit)
      .select('query queries trigger result_count source_domains duration_ms status cached created_at')
      .lean();
    res.json({ searches: rows.map(r => ({ ...r, _id: undefined, id: r._id?.toString() })) });
  } catch { res.json({ searches: [] }); }
});

app.get('/api/usage', authGuard, async (req, res) => {
  try {
    const uid = new mongoose.Types.ObjectId(req.user.id);
    // Authoritative daily usage: UsageDaily counter (services/usage.js)
    const u = await usageService.getUsage(req.user.id);
    const monthStart = new Date(); monthStart.setDate(1); monthStart.setHours(0, 0, 0, 0);
    const month = await UsageTracking.countDocuments({ user_id: uid, created_at: { $gte: monthStart } });
    const tokenAgg = await UsageTracking.aggregate([
      { $match: { user_id: uid } },
      { $group: { _id: null, total: { $sum: '$tokens_used' } } }
    ]);
    const tokens = tokenAgg[0]?.total || 0;
    res.json({
      today: u.used, month, tokens,
      daily_limit: u.limit, remaining: u.remaining,
      plan: u.plan, planName: u.planName, state: u.state, date: u.date,
    });
  } catch { res.json({ today: 0, month: 0, tokens: 0, daily_limit: 50, remaining: 50, plan: 'free' }); }
});

/* ════════════════════════════════════════════════════════════
   PLANS & SUBSCRIPTION (modular router — §33)
   GET /api/plans · GET /api/subscription · GET /api/subscription/usage
   POST /api/subscription/requests · GET /api/subscription/requests
   POST /api/subscription/ack-plan
════════════════════════════════════════════════════════════ */
app.use('/api', require('./routes/subscription'));
/* ══════════════════════════════════════════════════════════════
   SUPERADMIN API (v2) — implemented in routes/admin.js
   One administrative role: super_admin. Every endpoint verifies
   authentication + authorization server-side, records audit events
   for every mutation, and returns only real data.
══════════════════════════════════════════════════════════════ */
/* Record real unauthorized-access attempts against the Superadmin
   API (login endpoint excluded — it has its own telemetry).
   Registered BEFORE the router so the finish hook sees the final
   401/403 status codes emitted by the router's guard.            */
app.use('/api/admin', (req, res, next) => {
  if (req.path !== '/login') {
    res.on('finish', () => {
      if (res.statusCode === 401 || res.statusCode === 403) {
        SecurityEvent.create({
          type: 'unauthorized_access', severity: 'warning',
          ip: req.ip, user_agent: req.headers['user-agent'],
          message: `${req.method} /api/admin${req.path} → ${res.statusCode}`,
        }).catch(() => {});
      }
    });
  }
  next();
});

const adminRouter = require('./routes/admin');
app.use('/api/admin', adminRouter);

/* ── HEALTH ──────────────────────────────────────────────────── */
app.get('/api/health', (_, res) => res.json({ status: 'ok', version: require('./package.json').version, db: mongoose.connection.readyState === 1 ? 'connected' : 'disconnected', uptime: process.uptime(), memory: process.memoryUsage().rss, timestamp: new Date().toISOString() }));

/* ══════════════════════════════════════════════════════════════
   SOCKET.IO
══════════════════════════════════════════════════════════════ */
const http = require('http');
const { Server } = require('socket.io');
const server = http.createServer(app);
const io = new Server(server, { cors: { origin: true, credentials: true } });
app.set('io', io);
attachIo(io); // services/activity.js emits live events through this

io.use((socket, next) => {
  const t = socket.handshake.auth?.token;
  const a = socket.handshake.auth?.adminToken;
  if (t) { try { socket.user = jwt.verify(t, JWT_SECRET); return next(); } catch {} }
  if (a) { try { const d = jwt.verify(a, ADMIN_SECRET); if (d.isAdmin) { socket.admin = d; return next(); } } catch {} }
  return next(new Error('Auth required'));
});

io.on('connection', socket => {
  if (socket.user) {
    const uid = String(socket.user.id);
    socket.join(`user_${uid}`);

    // Real presence: a user is "online" exactly as long as they have at
    // least one live socket connection — no sampling, no guessing.
    let presence = onlinePresence.get(uid);
    if (!presence) {
      presence = { username: socket.user.username, sockets: new Set(), since: new Date() };
      onlinePresence.set(uid, presence);
      logActivity('online', { username: socket.user.username, user_id: uid });
    }
    presence.sockets.add(socket.id);

    socket.on('join_chat', id => socket.join(`chat_${id}`));
    socket.on('leave_chat', id => socket.leave(`chat_${id}`));
    socket.on('typing', ({ chatId, isTyping }) => {
      socket.to(`chat_${chatId}`).emit('user_typing', { userId: socket.user.id, username: socket.user.username, isTyping });
    });

    socket.on('disconnect', () => {
      const p = onlinePresence.get(uid);
      if (!p) return;
      p.sockets.delete(socket.id);
      // Only mark offline once every tab/connection for this user has closed.
      if (p.sockets.size === 0) {
        onlinePresence.delete(uid);
        logActivity('offline', { username: p.username, user_id: uid });
      }
    });
  }
  if (socket.admin) { socket.join('admin_room'); }
});

/* ── UPLOAD ERROR HANDLING (friendly client errors) ─────────── */
app.use((err, req, res, next) => {
  if (err?.code === 'LIMIT_FILE_SIZE')
    return res.status(400).json({ error: 'That file is too large. Images: 4 MB, documents: 15 MB, audio: 15 MB.' });
  if (err?.name === 'MulterError')
    return res.status(400).json({ error: 'The file could not be uploaded. Please try again.' });
  console.error('[Server]', err);
  res.status(500).json({ error: 'Something went wrong. Please try again.' });
});

/* ── START ───────────────────────────────────────────────────── */
/* Idempotent migration (§35): every conversation that predates the
   public conversation_id gets a UUID v4 backfilled in bounded
   batches. Existing chats, messages and attachments are NEVER
   touched beyond adding the identifier — users keep their history.
   Safe to run on every boot: the query only matches what is missing. */
async function migrateConversationIds() {
  const BATCH = 200;
  let migrated = 0;
  for (;;) {
    const missing = await Chat.find(
      { $or: [{ conversation_id: { $exists: false } }, { conversation_id: null }, { conversation_id: '' }] },
      { _id: 1 }
    ).limit(BATCH).lean();
    if (!missing.length) break;
    const ops = missing.map(doc => ({
      updateOne: {
        filter: { _id: doc._id, $or: [{ conversation_id: { $exists: false } }, { conversation_id: null }, { conversation_id: '' }] },
        update: { $set: { conversation_id: newConversationId() } },
      },
    }));
    try {
      const r = await Chat.bulkWrite(ops, { ordered: false });
      migrated += r.modifiedCount || 0;
    } catch (err) {
      // Duplicate key on an (astronomically unlikely) UUID collision —
      // the untouched rows are picked up by the next loop iteration.
      if (err?.code !== 11000 && !err?.writeErrors) throw err;
      migrated += (err?.result?.nModified) || 0;
    }
    if (missing.length < BATCH) break;
  }
  return migrated;
}

connectDB().then(async () => {
  // Normalize legacy admin roles — KinyaBot has exactly ONE role:
  // super_admin. Any legacy 'admin'/'moderator' rows are upgraded.
  try {
    const r = await Admin.updateMany({ role: { $ne: 'super_admin' } }, { $set: { role: 'super_admin' } });
    if (r.modifiedCount) console.log(`✅ Normalized ${r.modifiedCount} admin account(s) to super_admin`);
  } catch {}
  // Plan system (§43 migration safety): seed plan configuration and
  // migrate legacy plan values. Users WITHOUT a UserPlan document are
  // implicitly FREE — no backfill needed, existing accounts keep working.
  try {
    await plansService.ensureSeed();
    const migrated = await UserPlan.updateMany(
      { plan: { $in: ['premium', 'enterprise'] } },
      { $set: { plan: 'pro', daily_limit: 500, status: 'active', activation_source: 'manual_admin_approval' } }
    );
    if (migrated.modifiedCount) console.log(`✅ Migrated ${migrated.modifiedCount} legacy premium/enterprise plan(s) to pro`);
    const statuses = await UserPlan.updateMany(
      { status: { $in: [null, ''] } },
      { $set: { status: 'active' } }
    );
    if (statuses.modifiedCount) console.log(`✅ Normalized ${statuses.modifiedCount} plan status(es) to active`);
  } catch (err) { console.error('[Plans] startup seed/migration failed:', err.message); }
  // Conversation identity migration (§35): backfill UUID conversation_id
  try {
    const n = await migrateConversationIds();
    if (n) console.log(`✅ Backfilled ${n} conversation(s) with public conversation_id`);
  } catch (err) { console.error('[Migration] conversation_id backfill failed:', err.message); }
  server.listen(PORT, () => {
    const pkg = require('./package.json');
    console.log(`\n✅ KinyaBot v${pkg.version} (MongoDB) → http://localhost:${PORT}`);
    console.log(`   Superadmin  → http://localhost:5173/admin\n`);
  });
});
