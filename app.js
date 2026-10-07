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
const { attachIo, onlinePresence, logActivity } = require('./services/activity');
const { notifyAdmins } = require('./services/notify');
const pushService     = require('./services/push');

const {
  User, Chat, Message, Admin, Notification, PageView,
  SystemLog, UserMemory, KnowledgeBase, UsageTracking,
  UserPlan, FlaggedContent, SecurityEvent
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
const CHAT_FILE_FILTER = /\.(jpg|jpeg|png|gif|webp|pdf|txt|md|csv|json|docx|py|js|ts|html|css|xml|yaml|yml|mp3|wav|m4a|ogg|webm|flac|aac|mp4)$/i;
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
  limits: { fileSize: Math.max(aiConfig.limits.imageSizeBytes, aiConfig.limits.documentSizeBytes) },
  fileFilter(_, file, cb) { cb(null, CHAT_FILE_FILTER.test(file.originalname)); }
});
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
function authGuard(req, res, next) {
  const h = req.headers.authorization;
  if (!h?.startsWith('Bearer ')) return res.status(401).json({ error: 'Unauthorized' });
  try { req.user = jwt.verify(h.slice(7), JWT_SECRET); next(); }
  catch { res.status(401).json({ error: 'Session expired. Please log in again.' }); }
}
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
    const token = jwt.sign({ id: user._id.toString(), username: user.username, email: user.email }, JWT_SECRET, { expiresIn: '30d' });
    logActivity('login', { username: user.username, user_id: user._id.toString() });
    res.json({ token, user: { id: user._id.toString(), username: user.username, email: user.email, avatar_url: user.avatar_url, onboarded: user.onboarded, profession: user.profession, email_verified: user.email_verified } });
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
    res.json({ ...user, id: user._id.toString(), _id: undefined });
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
    const chats = await Chat.find({ user_id: req.user.id }).sort({ updated_at: -1 }).lean();
    const enriched = await Promise.all(chats.map(async c => {
      const lastMsg = await Message.findOne({ chat_id: c._id }).sort({ created_at: -1 }).select('content').lean();
      const msgCount = await Message.countDocuments({ chat_id: c._id });
      return { ...c, id: c._id.toString(), _id: undefined, user_id: c.user_id.toString(), last_message: lastMsg?.content || null, message_count: msgCount };
    }));
    res.json(enriched);
  } catch { res.status(500).json({ error: 'Could not load chats' }); }
});

app.post('/api/chats', authGuard, async (req, res) => {
  try {
    const chat = await Chat.create({ user_id: req.user.id, title: (req.body.title || 'New Chat').slice(0, 255) });
    logActivity('new_chat', { username: req.user.username, user_id: req.user.id, meta: { chatId: chat._id.toString() } });
    res.status(201).json(fmt(chat));
  } catch { res.status(500).json({ error: 'Could not create chat' }); }
});

app.get('/api/chats/:id', authGuard, async (req, res) => {
  try {
    const chat = await Chat.findOne({ _id: req.params.id, user_id: req.user.id }).lean();
    if (!chat) return res.status(404).json({ error: 'Chat not found' });
    const messages = await Message.find({ chat_id: req.params.id }).sort({ created_at: 1 }).lean();
    res.json({ ...chat, id: chat._id.toString(), _id: undefined, messages: fmtMessageArr(messages) });
  } catch { res.status(500).json({ error: 'Could not load chat' }); }
});

app.put('/api/chats/:id', authGuard, async (req, res) => {
  const { title, is_pinned } = req.body;
  const update = {};
  if (title !== undefined)     update.title = title;
  if (is_pinned !== undefined) update.is_pinned = is_pinned;
  if (!Object.keys(update).length) return res.status(400).json({ error: 'Nothing to update' });
  try {
    await Chat.findOneAndUpdate({ _id: req.params.id, user_id: req.user.id }, update);
    res.json({ success: true });
  } catch { res.status(500).json({ error: 'Could not update chat' }); }
});

app.delete('/api/chats/:id', authGuard, async (req, res) => {
  try {
    const chat = await Chat.findOne({ _id: req.params.id, user_id: req.user.id });
    if (!chat) return res.status(404).json({ error: 'Chat not found' });
    await Message.deleteMany({ chat_id: req.params.id });
    await Chat.deleteOne({ _id: req.params.id });
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
      ? 'The user requested one file. Return exactly one complete file in one fenced code block with a descriptive filename immediately after the language, for example ```html filename=hotel-booking.html. Include all required HTML, CSS and JavaScript in that file when applicable.'
      : 'Return every required source file in its own fenced code block. Put its relative filename immediately after the language on the opening fence, for example ```html filename=index.html or ```jsx filename=src/App.jsx. Include all code needed for the requested deliverable.',
    'Use valid Markdown code fences and always close every fence. Keep any explanation brief and outside the code blocks. Never claim that code was executed, tested, or written to disk.'
  ].join(' ')
}

/* ── Shared assistant turn (real Groq streaming, SSE) ────────── */
async function runAssistantTurn(req, res, { chat, send, startedAt, trackType = 'chat' }) {
  const abortController = new AbortController();
  let clientClosed = false;
  req.on('close', () => { clientClosed = true; try { abortController.abort(new Error('client closed')); } catch {} });

  const chatId = String(chat._id);
  const memory = await getUserMemory(req.user.id);

  // Context: bounded window + budget trim + rolling summary (§5)
  const fullHistory = await chatService.loadHistory(chatId);
  const { kept, droppedCount } = chatService.trimToBudget(fullHistory);
  const summary = await chatService.ensureSummary(chat, kept, droppedCount);
  const ragContext = cfg.knowledge_base_enabled ? await searchKnowledgeBase(kept[kept.length - 1]?.content || '') : '';
  const documentContext = chatService.findRecentDocumentContext(kept);

  // Multimodal: image attached to the most recent user turn (§8),
  // or re-attached from earlier in the conversation for follow-ups (§18)
  const lastUser = [...kept].reverse().find(m => m.role === 'user');
  const imgAtt = lastUser?.attachments?.find(a => a.kind === 'image');
  let imageDataUrl = null;
  if (imgAtt) {
    try {
      const imgPath = imgAtt.url.replace('/uploads', './uploads');
      const b64 = fs.readFileSync(imgPath).toString('base64');
      imageDataUrl = `data:${imgAtt.mime || 'image/jpeg'};base64,${b64}`;
    } catch (e) {
      console.error('[Stream] image load failed:', e.message);
      send('error', { message: 'KinyaBot could not open the attached image. Please re-attach it and try again.' });
      return res.end();
    }
  }

  // Follow-up about an earlier image: re-attach the most recent one so
  // the model can see it instead of inventing an answer (§18).
  let priorImage = null;
  if (!imageDataUrl) {
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
  if (!userText.trim() && !imageDataUrl && !priorImage) {
    const att = lastUser?.attachments?.[0];
    if (att?.kind === 'document') userText = 'Please read the attached document and tell me what it contains.';
    else if (att) userText = 'Please tell me about the file I attached.';
  }

  const prefs = replyPrefsPrompt(req.body, req.headers);
  const codeDelivery = codeDeliveryPrompt(userText);
  const messages = chatService.buildMessages({
    systemPrompt: [cfg.system_prompt, prefs, codeDelivery].filter(Boolean).join('\n\n'), memory, ragContext,
    history: kept, summary, documentContext,
    userText,
    imageDataUrl,
    priorImage,
  });
  const model = chatService.pickModel({ imageDataUrl, priorImage });

  send('start', { streaming: true });

  let aiText = '';
  let usageTokens = null;
  const stream = await provider.chatCompleteStream({
    messages, model,
    maxTokens: codeDelivery ? Math.max(Number(cfg.max_tokens) || 2048, 8192) : cfg.max_tokens,
    temperature: cfg.temperature,
    signal: abortController.signal,
  });

  try {
    for await (const chunk of stream) {
      const delta = chunk.choices?.[0]?.delta?.content || '';
      if (chunk.usage?.total_tokens) usageTokens = chunk.usage.total_tokens;
      if (delta) { aiText += delta; send('chunk', { text: delta }); }
      if (clientClosed) break;
    }
  } catch (err) {
    if (!clientClosed) throw err;
  }

  // Client cancelled mid-generation → keep the partial answer honestly (§17)
  if (clientClosed) {
    if (aiText.trim()) {
      await Message.create({
        chat_id: chatId, role: 'assistant', content: aiText,
        model, provider: aiConfig.provider, tokens: usageTokens,
        processing_ms: Date.now() - startedAt, status: 'cancelled',
      });
    }
    return;
  }

  if (!aiText.trim()) { const e = new Error('EMPTY_AI_RESPONSE'); e.code = 'EMPTY_AI_RESPONSE'; throw e; }

  // Source references ONLY when the backend actually knows them (§7)
  const sources = (!imageDataUrl && documentContext)
    ? [`${documentContext.name}${documentContext.pages ? ` (${documentContext.pages} pages)` : ''}`]
    : [];

  const aiMsg = await Message.create({
    chat_id: chatId, role: 'assistant', content: aiText,
    model, provider: aiConfig.provider, tokens: usageTokens,
    processing_ms: Date.now() - startedAt, status: 'completed', sources,
  });
  chat.updated_at = new Date();
  await chat.save();

  const tokens = usageTokens || estimateTokens(messages.map(m => (m.content || (Array.isArray(m.content) ? m.content.map(c => c.text || '').join(' ') : '')).slice(0, 400)).join('\n') + aiText);
  await trackUsage(req.user.id, chatId, tokens, trackType, Date.now() - startedAt, true);
  await extractMemoryFromConversation(req.user.id, lastUser?.content || '', aiText);

  const io = req.app.get('io');
  if (io) {
    io.to(`chat_${chatId}`).emit('new_message', { userMessage: null, aiMessage: fmtMessage(aiMsg), chatId });
    io.to(`user_${req.user.id}`).emit('chat_updated', { chatId });
  }

  send('done', { aiMessage: fmtMessage(aiMsg), userMessage: null });
  res.end();
}

/* Validate + prepare a chat attachment (server-side truth, §19) */
function prepareAttachment(req) {
  if (!req.file) return { meta: null, imageDataUrl: null, documentExtract: null, messageType: 'text' };
  const kind = documentService.classify(req.file.originalname, req.file.mimetype);
  if (kind === 'unknown')
    throw documentService.coded('UNSUPPORTED_FILE', 'That file type is not supported. Attach an image, PDF, DOCX, TXT or code file.');

  const valid = documentService.validateUpload(req.file.path, kind === 'image' ? 'image' : kind, req.file.originalname);
  const url = `/uploads/${req.file.filename}`;
  const baseMeta = { kind, url, name: req.file.originalname, mime: req.file.mimetype, size: valid.size };

  if (kind === 'image') {
    const b64 = fs.readFileSync(req.file.path).toString('base64');
    return { meta: baseMeta, imageDataUrl: `data:${req.file.mimetype};base64,${b64}`, documentExtract: null, messageType: 'image' };
  }
  if (kind === 'document') {
    return { meta: baseMeta, imageDataUrl: null, documentExtract: null, messageType: 'document', needsExtract: true };
  }
  throw documentService.coded('UNSUPPORTED_FILE', 'That file type cannot be used in chat.');
}

/* ── SEND MESSAGE (SSE Streaming, multimodal) ────────────────── */
app.post('/api/chats/:id/messages/stream', authGuard, uploadChat.single('file'), async (req, res) => {
  const { content } = req.body;
  const chatId = req.params.id;
  if (!content && !req.file) return res.status(400).json({ error: 'Message or file required' });

  // Abuse protection (§20): burst rate + existing daily quota
  const rl = rateLimiter.allow(req.user.id, 'chat', aiConfig.rateLimits.chat);
  if (!rl.ok) return rateLimiter.tooMany(res, rl.retryAfterSec);
  if (req.file) {
    const ul = rateLimiter.allow(req.user.id, 'upload', aiConfig.rateLimits.upload);
    if (!ul.ok) return rateLimiter.tooMany(res, ul.retryAfterSec);
  }
  const quota = await rateLimiter.dailyQuotaOk(req.user.id, cfg.free_daily_limit);
  if (!quota.ok)
    return res.status(429).json({ error: `You have reached your daily limit of ${quota.limit} messages. Your quota resets tomorrow.` });

  const startTime = Date.now();

  try {
    const chat = await Chat.findOne({ _id: chatId, user_id: req.user.id });
    if (!chat) return res.status(404).json({ error: 'Chat not found' });

    if (content) {
      const mod = await moderateContent(content);
      if (mod.flagged) {
        await FlaggedContent.create({ chat_id: chatId, user_id: req.user.id, reason: mod.reason, auto_flagged: true });
        return res.status(400).json({ error: 'Your message was flagged. Please keep conversations respectful.' });
      }
    }

    // Validate/prepare the attachment BEFORE any SSE output so client
    // errors arrive as normal JSON the frontend can display honestly.
    let prepared;
    try { prepared = prepareAttachment(req); }
    catch (err) { return res.status(400).json({ error: friendlyError(err) }); }

    let documentExtract = null;
    if (prepared.needsExtract) {
      try {
        documentExtract = await documentService.extractText(req.file.path, req.file.originalname, req.file.mimetype);
      } catch (err) {
        // Honest failure (§6): no fabricated reading of the document
        return res.status(422).json({ error: friendlyError(err), attachmentSaved: false });
      }
    }

    res.setHeader('Content-Type', 'text/event-stream');
    res.setHeader('Cache-Control', 'no-cache');
    res.setHeader('Connection', 'keep-alive');
    res.setHeader('X-Accel-Buffering', 'no');
    res.flushHeaders();

    const send = (event, data) => res.write(`event: ${event}\ndata: ${JSON.stringify(data)}\n\n`);

    const meta = prepared.meta ? { ...prepared.meta } : null;
    if (meta && documentExtract) {
      meta.extracted_text = documentExtract.text;
      meta.pages = documentExtract.pages;
    }

    const userMsg = await Message.create({
      chat_id: chatId, role: 'user', content: content || '',
      file_url: meta ? meta.url : null,
      message_type: prepared.messageType,
      attachments: meta ? [meta] : [],
    });
    send('user_message', fmtMessage(userMsg));
    logActivity('message', { username: req.user.username, user_id: req.user.id, meta: { chatId } });

    // Auto-title
    const msgCount = await Message.countDocuments({ chat_id: chatId });
    if (msgCount <= 1 && content) {
      chat.title = content.slice(0, 60);
      await chat.save();
    }

    await runAssistantTurn(req, res, { chat, send, startedAt: startTime, trackType: prepared.messageType === 'image' ? 'image' : (prepared.messageType === 'document' ? 'document' : 'chat') });
  } catch (err) {
    console.error('[Stream]', err);
    // Headers may not be sent yet if a pre-stream step threw
    if (!res.headersSent) {
      res.setHeader('Content-Type', 'text/event-stream');
      res.flushHeaders();
    }
    try {
      res.write(`event: error\ndata: ${JSON.stringify({ message: friendlyError(err) })}\n\n`);
      await trackUsage(req.user.id, chatId, 0, 'chat', Date.now() - startTime, false);
      res.end();
    } catch { res.end(); }
  }
});

/* ── REGENERATE last response (SSE, §16) ─────────────────────── */
app.post('/api/chats/:id/regenerate/stream', authGuard, async (req, res) => {
  const chatId = req.params.id;
  const rl = rateLimiter.allow(req.user.id, 'chat', aiConfig.rateLimits.chat);
  if (!rl.ok) return rateLimiter.tooMany(res, rl.retryAfterSec);
  const quota = await rateLimiter.dailyQuotaOk(req.user.id, cfg.free_daily_limit);
  if (!quota.ok)
    return res.status(429).json({ error: `You have reached your daily limit of ${quota.limit} messages. Your quota resets tomorrow.` });

  try {
    const chat = await Chat.findOne({ _id: chatId, user_id: req.user.id });
    if (!chat) return res.status(404).json({ error: 'Chat not found' });

    const lastUser = await Message.findOne({ chat_id: chatId, role: 'user' }).sort({ created_at: -1, _id: -1 }).lean();
    if (!lastUser) return res.status(400).json({ error: 'Nothing to regenerate yet.' });

    // Drop assistant messages generated after the last user message
    await Message.deleteMany({ chat_id: chatId, role: 'assistant', _id: { $gt: lastUser._id } });

    res.setHeader('Content-Type', 'text/event-stream');
    res.setHeader('Cache-Control', 'no-cache');
    res.setHeader('Connection', 'keep-alive');
    res.setHeader('X-Accel-Buffering', 'no');
    res.flushHeaders();
    const send = (event, data) => res.write(`event: ${event}\ndata: ${JSON.stringify(data)}\n\n`);
    send('user_message', fmtMessage(lastUser));

    await runAssistantTurn(req, res, { chat, send, startedAt: Date.now(), trackType: 'regenerate' });
  } catch (err) {
    console.error('[Regenerate]', err);
    if (!res.headersSent) { res.setHeader('Content-Type', 'text/event-stream'); res.flushHeaders(); }
    try { res.write(`event: error\ndata: ${JSON.stringify({ message: friendlyError(err) })}\n\n`); res.end(); } catch { res.end(); }
  }
});

/* ── SPEECH-TO-TEXT (voice input, §11/§12) ───────────────────── */
app.post('/api/stt', authGuard, uploadAudio.single('audio'), async (req, res) => {
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
/* ── SEND MESSAGE (non-streaming fallback) ───────────────────── */
app.post('/api/chats/:id/messages', authGuard, uploadChat.single('file'), async (req, res) => {
  const { content } = req.body;
  const chatId = req.params.id;
  if (!content && !req.file) return res.status(400).json({ error: 'Message or file required' });
  const startTime = Date.now();

  const rl = rateLimiter.allow(req.user.id, 'chat', aiConfig.rateLimits.chat);
  if (!rl.ok) return rateLimiter.tooMany(res, rl.retryAfterSec);
  const quota = await rateLimiter.dailyQuotaOk(req.user.id, cfg.free_daily_limit);
  if (!quota.ok)
    return res.status(429).json({ error: `You have reached your daily limit of ${quota.limit} messages. Your quota resets tomorrow.` });

  try {
    const chat = await Chat.findOne({ _id: chatId, user_id: req.user.id });
    if (!chat) return res.status(404).json({ error: 'Chat not found' });

    if (content) {
      const mod = await moderateContent(content);
      if (mod.flagged) {
        await FlaggedContent.create({ chat_id: chatId, user_id: req.user.id, reason: mod.reason, auto_flagged: true });
        return res.status(400).json({ error: 'Message flagged. Please keep conversations respectful.' });
      }
    }

    let prepared;
    try { prepared = prepareAttachment(req); }
    catch (err) { return res.status(400).json({ error: friendlyError(err) }); }

    let documentExtract = null;
    if (prepared.needsExtract) {
      try { documentExtract = await documentService.extractText(req.file.path, req.file.originalname, req.file.mimetype); }
      catch (err) { return res.status(422).json({ error: friendlyError(err) }); }
    }

    const meta = prepared.meta ? { ...prepared.meta } : null;
    if (meta && documentExtract) { meta.extracted_text = documentExtract.text; meta.pages = documentExtract.pages; }

    const userMsg = await Message.create({
      chat_id: chatId, role: 'user', content: content || '',
      file_url: meta ? meta.url : null,
      message_type: prepared.messageType,
      attachments: meta ? [meta] : [],
    });
    logActivity('message', { username: req.user.username, user_id: req.user.id, meta: { chatId } });

    const msgCount = await Message.countDocuments({ chat_id: chatId });
    if (msgCount <= 1 && content) { chat.title = content.slice(0, 60); await chat.save(); }

    // Context via AI Core (bounded window + budget + rolling summary)
    const fullHistory = await chatService.loadHistory(chatId);
    const { kept, droppedCount } = chatService.trimToBudget(fullHistory);
    const summary = await chatService.ensureSummary(chat, kept, droppedCount);
    const memory = await getUserMemory(req.user.id);
    const ragCtx = cfg.knowledge_base_enabled && content ? await searchKnowledgeBase(content) : '';
    const documentContext = chatService.findRecentDocumentContext(kept);

    // Vision turn (image understanding — new attachment or re-attached prior image)
    let result;
    let priorImage = null;
    if (!prepared.imageDataUrl) {
      const priorAtt = chatService.findRecentImageContext(kept);
      if (priorAtt) {
        try {
          const priorPath = priorAtt.url.replace('/uploads', './uploads');
          const b64 = fs.readFileSync(priorPath).toString('base64');
          priorImage = { name: priorAtt.name, dataUrl: `data:${priorAtt.mime || 'image/jpeg'};base64,${b64}` };
        } catch (e) { console.warn('[Message] prior image unavailable:', e.message); }
      }
    }

    if (prepared.imageDataUrl || priorImage) {
      const historyText = kept.filter(m => !(String(m._id) === String(userMsg._id)) && m.content?.trim())
        .slice(-6).map(m => ({ role: m.role, content: m.content.trim() }));
      result = await provider.visionComplete({
        prompt: content || (prepared.imageDataUrl ? 'What is in this image? Describe it in detail.' : `Tell me more about this image (${priorImage.name}).`),
        imageDataUrl: prepared.imageDataUrl || priorImage.dataUrl,
        history: historyText, systemPrompt: cfg.system_prompt,
        maxTokens: cfg.max_tokens, temperature: cfg.temperature,
      });
    } else {
      const messages = chatService.buildMessages({
        systemPrompt: cfg.system_prompt, memory, ragContext: ragCtx,
        history: kept, summary, documentContext,
        userText: content || '',
      });
      result = await provider.chatComplete({
        messages, model: chatService.pickModel({}),
        maxTokens: cfg.max_tokens, temperature: cfg.temperature,
      });
    }
    const aiText = result.text;

    const sources = (!prepared.imageDataUrl && documentContext)
      ? [`${documentContext.name}${documentContext.pages ? ` (${documentContext.pages} pages)` : ''}`]
      : [];

    const aiMsg = await Message.create({
      chat_id: chatId, role: 'assistant', content: aiText,
      model: result.model, provider: aiConfig.provider, tokens: result.tokens,
      processing_ms: Date.now() - startTime, status: 'completed', sources,
    });
    chat.updated_at = new Date();
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
    res.status(500).json({ error: friendlyError(err) });
  }
});

app.delete('/api/messages/:id', authGuard, async (req, res) => {
  try {
    const msg = await Message.findById(req.params.id);
    if (!msg) return res.status(404).json({ error: 'Message not found' });
    const chat = await Chat.findOne({ _id: msg.chat_id, user_id: req.user.id });
    if (!chat) return res.status(403).json({ error: 'Forbidden' });
    await Message.deleteOne({ _id: req.params.id });
    res.json({ success: true });
  } catch { res.status(500).json({ error: 'Could not delete message' }); }
});

app.get('/api/search', authGuard, async (req, res) => {
  const { q } = req.query;
  if (!q) return res.json([]);
  try {
    const userChats = await Chat.find({ user_id: req.user.id }).select('_id title').lean();
    const chatIds = userChats.map(c => c._id);
    const chatMap = {};
    userChats.forEach(c => { chatMap[c._id.toString()] = c.title; });
    const messages = await Message.find({
      chat_id: { $in: chatIds },
      content: { $regex: q, $options: 'i' }
    }).sort({ created_at: -1 }).limit(20).lean();
    const result = messages.map(m => ({
      ...m, id: m._id.toString(), _id: undefined,
      chat_id: m.chat_id.toString(),
      chat_title: chatMap[m.chat_id.toString()] || 'Unknown'
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

app.get('/api/usage', authGuard, async (req, res) => {
  try {
    const uid = new mongoose.Types.ObjectId(req.user.id);
    const todayStart = new Date(); todayStart.setHours(0, 0, 0, 0);
    const monthStart = new Date(); monthStart.setDate(1); monthStart.setHours(0, 0, 0, 0);
    const today = await UsageTracking.countDocuments({ user_id: uid, created_at: { $gte: todayStart } });
    const month = await UsageTracking.countDocuments({ user_id: uid, created_at: { $gte: monthStart } });
    const tokenAgg = await UsageTracking.aggregate([
      { $match: { user_id: uid } },
      { $group: { _id: null, total: { $sum: '$tokens_used' } } }
    ]);
    const tokens = tokenAgg[0]?.total || 0;
    const plan = await UserPlan.findOne({ user_id: uid }).lean();
    const daily_limit = plan?.daily_limit || cfg.free_daily_limit;
    res.json({ today, month, tokens, daily_limit, remaining: Math.max(0, daily_limit - today) });
  } catch { res.json({ today: 0, month: 0, tokens: 0, daily_limit: 50, remaining: 50 }); }
});
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
app.get('/api/health', (_, res) => res.json({ status: 'ok', version: '7.0.0', db: mongoose.connection.readyState === 1 ? 'connected' : 'disconnected', uptime: process.uptime(), memory: process.memoryUsage().rss, timestamp: new Date().toISOString() }));

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
connectDB().then(async () => {
  // Normalize legacy admin roles — KinyaBot has exactly ONE role:
  // super_admin. Any legacy 'admin'/'moderator' rows are upgraded.
  try {
    const r = await Admin.updateMany({ role: { $ne: 'super_admin' } }, { $set: { role: 'super_admin' } });
    if (r.modifiedCount) console.log(`✅ Normalized ${r.modifiedCount} admin account(s) to super_admin`);
  } catch {}
  server.listen(PORT, () => {
    const pkg = require('./package.json');
    console.log(`\n✅ KinyaBot v${pkg.version} (MongoDB) → http://localhost:${PORT}`);
    console.log(`   Superadmin  → http://localhost:5173/admin\n`);
  });
});
