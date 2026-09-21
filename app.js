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

const {
  User, Chat, Message, Admin, Notification, PageView,
  SystemLog, UserMemory, KnowledgeBase, UsageTracking,
  UserPlan, FlaggedContent
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

/* ── SETTINGS ────────────────────────────────────────────────── */
const SETTINGS_FILE = './admin-settings.json';
let cfg = {
  max_tokens: 2048, temperature: 0.7, max_context_messages: 10,
  system_prompt: 'You are KinyaBot, a helpful AI assistant. Be concise, friendly, and accurate.',
  image_gen_enabled: true, file_uploads_enabled: true,
  maintenance_mode: false, app_name: 'KinyaBot AI',
  blocked_ips: [], cost_per_1k_tokens: 0.002,
  free_daily_limit: 50, premium_daily_limit: 500,
  moderation_enabled: true, knowledge_base_enabled: true
};
try { cfg = { ...cfg, ...JSON.parse(fs.readFileSync(SETTINGS_FILE, 'utf8')) }; } catch {}
function saveCfg() { try { fs.writeFileSync(SETTINGS_FILE, JSON.stringify(cfg, null, 2)); } catch {} }

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

async function trackUsage(userId, chatId, tokens, type, responseMs, success) {
  try {
    await UsageTracking.create({ user_id: userId, chat_id: chatId, tokens_used: tokens, request_type: type, response_ms: responseMs, success });
  } catch {}
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
    const user = await User.create({ username, email: email.toLowerCase(), password_hash: hash });
    const token = jwt.sign({ id: user._id.toString(), username, email: user.email }, JWT_SECRET, { expiresIn: '30d' });
    await sysLog('info', 'auth', `Registered: ${username}`, null, user._id);
    res.status(201).json({ token, user: { id: user._id.toString(), username, email: user.email, onboarded: false } });
  } catch (err) { console.error('[Register]', err); res.status(500).json({ error: 'Registration failed. Please try again.' }); }
});

app.post('/api/auth/login', async (req, res) => {
  const { email, password } = req.body;
  if (!email || !password) return res.status(400).json({ error: 'Email and password required' });
  try {
    const user = await User.findOne({ email: email.toLowerCase() });
    if (!user) return res.status(401).json({ error: 'Invalid email or password' });
    if (user.is_banned) return res.status(403).json({ error: 'Account suspended. Please contact support.' });
    if (cfg.maintenance_mode) return res.status(503).json({ error: 'KinyaBot is in maintenance mode. Please check back soon.' });
    const ok = await bcrypt.compare(password, user.password_hash);
    if (!ok) return res.status(401).json({ error: 'Invalid email or password' });
    user.last_login = new Date();
    await user.save();
    const token = jwt.sign({ id: user._id.toString(), username: user.username, email: user.email }, JWT_SECRET, { expiresIn: '30d' });
    res.json({ token, user: { id: user._id.toString(), username: user.username, email: user.email, avatar_url: user.avatar_url, onboarded: user.onboarded, profession: user.profession } });
  } catch (err) { console.error('[Login]', err); res.status(500).json({ error: 'Login failed. Please try again.' }); }
});

app.post('/api/auth/google', async (req, res) => {
  const { idToken } = req.body;
  if (!idToken) return res.status(400).json({ error: 'ID Token required' });
  try {
    const decodedToken = await admin.auth().verifyIdToken(idToken);
    const { email, name, picture, uid } = decodedToken;
    let user = await User.findOne({ email: email.toLowerCase() });
    if (!user) {
      const randomPass = crypto.randomBytes(16).toString('hex');
      const hash = await bcrypt.hash(randomPass, 12);
      let username = name || email.split('@')[0];
      const existingUser = await User.findOne({ username });
      if (existingUser) username = `${username}_${uid.slice(0, 5)}`;
      user = await User.create({ username, email: email.toLowerCase(), password_hash: hash, avatar_url: picture || null });
      await sysLog('info', 'auth', `Registered via Google: ${username}`, null, user._id);
    } else {
      if (user.is_banned) return res.status(403).json({ error: 'Account suspended.' });
      user.last_login = new Date();
      if (picture) user.avatar_url = picture;
      await user.save();
    }
    const token = jwt.sign({ id: user._id.toString(), username: user.username, email: user.email }, JWT_SECRET, { expiresIn: '30d' });
    res.json({ token, user: { id: user._id.toString(), username: user.username, email: user.email, avatar_url: user.avatar_url, onboarded: user.onboarded, profession: user.profession } });
  } catch (err) {
    console.error('[Google Auth]', err);
    res.status(401).json({ error: 'Google authentication failed. Please try again.' });
  }
});

app.get('/api/auth/me', authGuard, async (req, res) => {
  try {
    const user = await User.findById(req.user.id).select('username email avatar_url profession onboarded created_at last_login').lean();
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
  const { username, referral_source, profession } = req.body;
  try {
    const update = { onboarded: true, referral_source: referral_source || null, profession: profession || null };
    if (username) update.username = username;
    await User.findByIdAndUpdate(req.user.id, update);
    if (username) await setUserMemory(req.user.id, 'name', username);
    if (profession) await setUserMemory(req.user.id, 'profession', profession);
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

  // Multimodal: image attached to the most recent user turn (§8)
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

  const messages = chatService.buildMessages({
    systemPrompt: cfg.system_prompt, memory, ragContext,
    history: kept, summary, documentContext,
    userText: lastUser?.content || '',
    imageDataUrl,
  });
  const model = chatService.pickModel({ imageDataUrl });

  send('start', { streaming: true });

  let aiText = '';
  let usageTokens = null;
  const stream = await provider.chatCompleteStream({
    messages, model,
    maxTokens: cfg.max_tokens, temperature: cfg.temperature,
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
    const { buffer, model } = await speechService.synthesize(String(text));
    await trackUsage(req.user.id, null, estimateTokens(String(text)), 'tts', 0, true);
    res.setHeader('Content-Type', 'audio/wav');
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

    const msgCount = await Message.countDocuments({ chat_id: chatId });
    if (msgCount <= 1 && content) { chat.title = content.slice(0, 60); await chat.save(); }

    // Context via AI Core (bounded window + budget + rolling summary)
    const fullHistory = await chatService.loadHistory(chatId);
    const { kept, droppedCount } = chatService.trimToBudget(fullHistory);
    const summary = await chatService.ensureSummary(chat, kept, droppedCount);
    const memory = await getUserMemory(req.user.id);
    const ragCtx = cfg.knowledge_base_enabled && content ? await searchKnowledgeBase(content) : '';
    const documentContext = chatService.findRecentDocumentContext(kept);

    // Vision turn (image understanding)
    let result;
    if (prepared.imageDataUrl) {
      const historyText = kept.filter(m => !(String(m._id) === String(userMsg._id)) && m.content?.trim())
        .slice(-6).map(m => ({ role: m.role, content: m.content.trim() }));
      result = await provider.visionComplete({
        prompt: content || 'What is in this image?',
        imageDataUrl: prepared.imageDataUrl,
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
   ADMIN AUTH
══════════════════════════════════════════════════════════════ */
app.post('/api/admin/login', async (req, res) => {
  const { email, password } = req.body;
  if (!email || !password) return res.status(400).json({ error: 'Email and password required' });
  try {
    const adm = await Admin.findOne({ email: email.toLowerCase() });
    if (!adm) return res.status(401).json({ error: 'Invalid credentials' });
    const ok = await bcrypt.compare(password, adm.password_hash);
    if (!ok) return res.status(401).json({ error: 'Invalid credentials' });
    adm.last_login = new Date();
    await adm.save();
    const token = jwt.sign({ id: adm._id.toString(), username: adm.username, email: adm.email, role: adm.role, isAdmin: true }, ADMIN_SECRET, { expiresIn: '8h' });
    await sysLog('info', 'admin', `Admin login: ${adm.username}`);
    res.json({ token, admin: { id: adm._id.toString(), username: adm.username, email: adm.email, role: adm.role } });
  } catch (err) { console.error('[AdminLogin]', err); res.status(500).json({ error: 'Login failed.' }); }
});

app.post('/api/admin/register', async (req, res) => {
  const { username, email, password, invite_code, role = 'admin' } = req.body;
  if (!username || !email || !password) return res.status(400).json({ error: 'All fields required' });
  if (username.length < 3) return res.status(400).json({ error: 'Username min 3 chars' });
  if (password.length < 8) return res.status(400).json({ error: 'Password min 8 chars' });
  const INVITE_CODE = process.env.ADMIN_INVITE_CODE || 'KinyaBot-Admin-2024';
  try {
    const totalAdmins = await Admin.countDocuments();
    if (totalAdmins > 0 && (invite_code || '').trim() !== INVITE_CODE)
      return res.status(403).json({ error: `Invalid invite code. Use: ${INVITE_CODE}` });
    const existing = await Admin.findOne({ $or: [{ email: email.toLowerCase() }, { username }] });
    if (existing) return res.status(409).json({ error: 'Email or username already taken' });
    const hash = await bcrypt.hash(password, 12);
    const assignedRole = totalAdmins === 0 ? 'super_admin' : role;
    const adm = await Admin.create({ username, email: email.toLowerCase(), password_hash: hash, role: assignedRole });
    const token = jwt.sign({ id: adm._id.toString(), username, email: adm.email, role: assignedRole, isAdmin: true }, ADMIN_SECRET, { expiresIn: '8h' });
    await sysLog('info', 'admin', `Admin registered: ${username}`);
    res.status(201).json({ token, admin: { id: adm._id.toString(), username, email: adm.email, role: assignedRole } });
  } catch (err) { console.error('[AdminReg]', err); res.status(500).json({ error: 'Registration failed: ' + err.message }); }
});

/* ══════════════════════════════════════════════════════════════
   ADMIN — DASHBOARD & ANALYTICS
══════════════════════════════════════════════════════════════ */
app.get('/api/admin/dashboard', adminGuard, async (req, res) => {
  try {
    const now = new Date();
    const todayStart = new Date(now); todayStart.setHours(0, 0, 0, 0);
    const sevenDaysAgo = new Date(now - 7 * 24 * 60 * 60 * 1000);

    const [total_users, total_chats, total_messages, active_today, new_today, msgs_today,
           total_views, views_today, tokenAgg, flagged_count] = await Promise.all([
      User.countDocuments(),
      Chat.countDocuments(),
      Message.countDocuments(),
      User.countDocuments({ last_login: { $gte: todayStart } }),
      User.countDocuments({ created_at: { $gte: todayStart } }),
      Message.countDocuments({ created_at: { $gte: todayStart } }),
      PageView.countDocuments(),
      PageView.countDocuments({ created_at: { $gte: todayStart } }),
      UsageTracking.aggregate([{ $group: { _id: null, total: { $sum: '$tokens_used' } } }]),
      FlaggedContent.countDocuments({ reviewed: false }),
    ]);

    const total_tokens = tokenAgg[0]?.total || 0;
    const total_cost = (total_tokens / 1000 * (cfg.cost_per_1k_tokens || 0.002)).toFixed(4);

    const [daily_users, daily_messages, daily_views, professions, referrals] = await Promise.all([
      User.aggregate([
        { $match: { created_at: { $gte: sevenDaysAgo } } },
        { $group: { _id: { $dateToString: { format: '%Y-%m-%d', date: '$created_at' } }, count: { $sum: 1 } } },
        { $sort: { _id: 1 } }, { $project: { date: '$_id', count: 1, _id: 0 } }
      ]),
      Message.aggregate([
        { $match: { created_at: { $gte: sevenDaysAgo } } },
        { $group: { _id: { $dateToString: { format: '%Y-%m-%d', date: '$created_at' } }, count: { $sum: 1 } } },
        { $sort: { _id: 1 } }, { $project: { date: '$_id', count: 1, _id: 0 } }
      ]),
      PageView.aggregate([
        { $match: { created_at: { $gte: sevenDaysAgo } } },
        { $group: { _id: { $dateToString: { format: '%Y-%m-%d', date: '$created_at' } }, count: { $sum: 1 } } },
        { $sort: { _id: 1 } }, { $project: { date: '$_id', count: 1, _id: 0 } }
      ]),
      User.aggregate([
        { $match: { profession: { $ne: null } } },
        { $group: { _id: '$profession', count: { $sum: 1 } } },
        { $sort: { count: -1 } }, { $limit: 8 },
        { $project: { profession: '$_id', count: 1, _id: 0 } }
      ]),
      User.aggregate([
        { $match: { referral_source: { $ne: null } } },
        { $group: { _id: '$referral_source', count: { $sum: 1 } } },
        { $sort: { count: -1 } }, { $limit: 8 },
        { $project: { referral_source: '$_id', count: 1, _id: 0 } }
      ]),
    ]);

    res.json({ total_users, total_chats, total_messages, active_today, new_today, msgs_today, total_views, views_today, total_tokens, total_cost, daily_users, daily_messages, daily_views, professions, referrals, flagged_count });
  } catch (err) { console.error('[AdminDash]', err); res.status(500).json({ error: 'Could not load dashboard' }); }
});

app.get('/api/admin/analytics', adminGuard, async (req, res) => {
  try {
    const twelveMonthsAgo = new Date(); twelveMonthsAgo.setMonth(twelveMonthsAgo.getMonth() - 12);
    const sevenDaysAgo = new Date(Date.now() - 7 * 24 * 60 * 60 * 1000);
    const thirtyDaysAgo = new Date(Date.now() - 30 * 24 * 60 * 60 * 1000);

    const [top_users, hourly_activity, monthly_users, monthly_messages, role_dist, token_usage, success_rate] = await Promise.all([
      User.aggregate([
        { $lookup: { from: 'chats', localField: '_id', foreignField: 'user_id', as: 'chats' } },
        { $lookup: { from: 'messages', localField: 'chats._id', foreignField: 'chat_id', as: 'msgs' } },
        { $project: { username: 1, email: 1, msg_count: { $size: '$msgs' } } },
        { $sort: { msg_count: -1 } }, { $limit: 10 }
      ]),
      Message.aggregate([
        { $match: { created_at: { $gte: sevenDaysAgo } } },
        { $group: { _id: { $hour: '$created_at' }, count: { $sum: 1 } } },
        { $sort: { _id: 1 } }, { $project: { hour: '$_id', count: 1, _id: 0 } }
      ]),
      User.aggregate([
        { $match: { created_at: { $gte: twelveMonthsAgo } } },
        { $group: { _id: { $dateToString: { format: '%Y-%m', date: '$created_at' } }, count: { $sum: 1 } } },
        { $sort: { _id: 1 } }, { $project: { month: '$_id', count: 1, _id: 0 } }
      ]),
      Message.aggregate([
        { $match: { created_at: { $gte: twelveMonthsAgo } } },
        { $group: { _id: { $dateToString: { format: '%Y-%m', date: '$created_at' } }, count: { $sum: 1 } } },
        { $sort: { _id: 1 } }, { $project: { month: '$_id', count: 1, _id: 0 } }
      ]),
      User.aggregate([
        { $group: { _id: '$onboarded', count: { $sum: 1 } } },
        { $project: { onboarded: '$_id', count: 1, _id: 0 } }
      ]),
      UsageTracking.aggregate([
        { $match: { created_at: { $gte: thirtyDaysAgo } } },
        { $group: { _id: { $dateToString: { format: '%Y-%m-%d', date: '$created_at' } }, tokens: { $sum: '$tokens_used' }, requests: { $sum: 1 }, avg_ms: { $avg: '$response_ms' } } },
        { $sort: { _id: 1 } }, { $project: { date: '$_id', tokens: 1, requests: 1, avg_ms: 1, _id: 0 } }
      ]),
      UsageTracking.aggregate([
        { $match: { created_at: { $gte: sevenDaysAgo } } },
        { $group: { _id: null, ok: { $sum: { $cond: ['$success', 1, 0] } }, total: { $sum: 1 } } }
      ]),
    ]);

    res.json({ top_users, hourly_activity, monthly_users, monthly_messages, role_dist, token_usage, success_rate: success_rate[0] || { ok: 0, total: 0 } });
  } catch (err) { res.json({ top_users: [], hourly_activity: [], monthly_users: [], monthly_messages: [], role_dist: [], token_usage: [], success_rate: { ok: 0, total: 0 } }); }
});

/* ── USERS (admin) ───────────────────────────────────────────── */
app.get('/api/admin/users', adminGuard, async (req, res) => {
  const { page = 1, limit = 20, search = '' } = req.query;
  const skip = (parseInt(page) - 1) * parseInt(limit);
  try {
    const filter = search ? { $or: [{ username: { $regex: search, $options: 'i' } }, { email: { $regex: search, $options: 'i' } }] } : {};
    const [users, total] = await Promise.all([
      User.find(filter).select('username email profession referral_source onboarded is_banned created_at last_login avatar_url').sort({ created_at: -1 }).skip(skip).limit(parseInt(limit)).lean(),
      User.countDocuments(filter)
    ]);
    res.json({ users: users.map(u => ({ ...u, id: u._id.toString(), _id: undefined })), total, page: parseInt(page), pages: Math.ceil(total / parseInt(limit)) || 1 });
  } catch { res.status(500).json({ error: 'Could not load users' }); }
});

app.get('/api/admin/users/:id/stats', adminGuard, async (req, res) => {
  try {
    const uid = new mongoose.Types.ObjectId(req.params.id);
    const chats = await Chat.find({ user_id: uid }).select('_id').lean();
    const chatIds = chats.map(c => c._id);
    const [total_chats, total_messages, tokenAgg, lastView, memory] = await Promise.all([
      Promise.resolve(chats.length),
      Message.countDocuments({ chat_id: { $in: chatIds } }),
      UsageTracking.aggregate([{ $match: { user_id: uid } }, { $group: { _id: null, total: { $sum: '$tokens_used' } } }]),
      PageView.findOne({ user_id: uid }).sort({ created_at: -1 }).select('ip_address').lean(),
      getUserMemory(req.params.id),
    ]);
    res.json({ total_chats, total_messages, total_tokens: tokenAgg[0]?.total || 0, last_ip: lastView?.ip_address || null, memory });
  } catch { res.json({ total_chats: 0, total_messages: 0, total_tokens: 0, last_ip: null, memory: {} }); }
});

app.put('/api/admin/users/:id/ban', adminGuard, async (req, res) => {
  const { banned } = req.body;
  try {
    await User.findByIdAndUpdate(req.params.id, { is_banned: !!banned });
    await sysLog('warn', 'admin', `${banned ? 'Banned' : 'Unbanned'} user ${req.params.id}`);
    res.json({ success: true });
  } catch { res.status(500).json({ error: 'Could not update user' }); }
});

app.put('/api/admin/users/:id/plan', adminGuard, async (req, res) => {
  const { plan, daily_limit, monthly_limit, tokens_limit } = req.body;
  try {
    await UserPlan.findOneAndUpdate(
      { user_id: req.params.id },
      { plan, daily_limit: daily_limit || 50, monthly_limit: monthly_limit || 500, tokens_limit: tokens_limit || 100000 },
      { upsert: true, new: true }
    );
    res.json({ success: true });
  } catch { res.status(500).json({ error: 'Could not update plan' }); }
});

app.put('/api/admin/users/:id/reset-password', adminGuard, async (req, res) => {
  const { password } = req.body;
  if (!password || password.length < 8) return res.status(400).json({ error: 'Password min 8 chars' });
  try {
    const hash = await bcrypt.hash(password, 12);
    await User.findByIdAndUpdate(req.params.id, { password_hash: hash });
    await sysLog('warn', 'admin', `Password reset for user ${req.params.id}`);
    res.json({ success: true });
  } catch { res.status(500).json({ error: 'Failed' }); }
});

app.delete('/api/admin/users/:id/memory', adminGuard, async (req, res) => {
  try { await UserMemory.deleteMany({ user_id: req.params.id }); res.json({ success: true }); }
  catch { res.status(500).json({ error: 'Failed' }); }
});

app.delete('/api/admin/users/:id', adminGuard, async (req, res) => {
  try {
    const chats = await Chat.find({ user_id: req.params.id }).select('_id').lean();
    const chatIds = chats.map(c => c._id);
    await Message.deleteMany({ chat_id: { $in: chatIds } });
    await Chat.deleteMany({ user_id: req.params.id });
    await UserMemory.deleteMany({ user_id: req.params.id });
    await UsageTracking.deleteMany({ user_id: req.params.id });
    await UserPlan.deleteOne({ user_id: req.params.id });
    await User.findByIdAndDelete(req.params.id);
    await sysLog('warn', 'admin', `Deleted user ${req.params.id}`);
    res.json({ success: true });
  } catch { res.status(500).json({ error: 'Could not delete user' }); }
});

/* ── CHATS (admin) ───────────────────────────────────────────── */
app.get('/api/admin/chats', adminGuard, async (req, res) => {
  const { page = 1, limit = 20, search = '' } = req.query;
  const skip = (parseInt(page) - 1) * parseInt(limit);
  try {
    const matchStage = search ? { title: { $regex: search, $options: 'i' } } : {};
    const [chats, total] = await Promise.all([
      Chat.find(matchStage).populate('user_id', 'username email').sort({ updated_at: -1 }).skip(skip).limit(parseInt(limit)).lean(),
      Chat.countDocuments()
    ]);
    const enriched = await Promise.all(chats.map(async c => {
      const msg_count = await Message.countDocuments({ chat_id: c._id });
      return { ...c, id: c._id.toString(), _id: undefined, username: c.user_id?.username, email: c.user_id?.email, user_id: c.user_id?._id?.toString(), msg_count };
    }));
    res.json({ chats: enriched, total });
  } catch { res.status(500).json({ error: 'Could not load chats' }); }
});

app.get('/api/admin/chats/:id/messages', adminGuard, async (req, res) => {
  try {
    const chat = await Chat.findById(req.params.id).populate('user_id', 'username email').lean();
    if (!chat) return res.status(404).json({ error: 'Not found' });
    const messages = await Message.find({ chat_id: req.params.id }).sort({ created_at: 1 }).lean();
    res.json({ chat: { ...chat, id: chat._id.toString(), _id: undefined }, messages: fmtArr(messages), user: { username: chat.user_id?.username, email: chat.user_id?.email } });
  } catch { res.status(500).json({ error: 'Failed' }); }
});

app.delete('/api/admin/chats/:id', adminGuard, async (req, res) => {
  try {
    await Message.deleteMany({ chat_id: req.params.id });
    await Chat.findByIdAndDelete(req.params.id);
    await sysLog('warn', 'admin', `Admin deleted chat ${req.params.id}`);
    res.json({ success: true });
  } catch { res.status(500).json({ error: 'Failed' }); }
});

/* ── NOTIFICATIONS ───────────────────────────────────────────── */
app.get('/api/admin/notifications', adminGuard, async (req, res) => {
  try { res.json(fmtArr(await Notification.find().sort({ created_at: -1 }).limit(50).lean())); }
  catch { res.json([]); }
});

app.post('/api/admin/notifications', adminGuard, async (req, res) => {
  const { title, message, type = 'info', expires_at } = req.body;
  if (!title || !message) return res.status(400).json({ error: 'Title and message required' });
  try {
    const notif = await Notification.create({ title, message, type, is_active: true, created_by: req.admin.id, expires_at: expires_at || null });
    const io = req.app.get('io'); if (io) io.emit('admin_notification', fmt(notif));
    await sysLog('info', 'admin', `Notification: ${title}`);
    res.json(fmt(notif));
  } catch { res.status(500).json({ error: 'Failed' }); }
});

app.put('/api/admin/notifications/:id', adminGuard, async (req, res) => {
  try { await Notification.findByIdAndUpdate(req.params.id, { is_active: !!req.body.is_active }); res.json({ success: true }); }
  catch { res.status(500).json({ error: 'Failed' }); }
});

app.delete('/api/admin/notifications/:id', adminGuard, async (req, res) => {
  try { await Notification.findByIdAndDelete(req.params.id); res.json({ success: true }); }
  catch { res.status(500).json({ error: 'Failed' }); }
});

/* ── SETTINGS ────────────────────────────────────────────────── */
app.get('/api/admin/settings', adminGuard, (_, res) => res.json({ ...cfg, groq_model: process.env.GROQ_MODEL || DEFAULT_MODEL }));
app.put('/api/admin/settings', adminGuard, async (req, res) => {
  try {
    const allowedSettings = [
      'max_tokens', 'temperature', 'system_prompt', 'image_gen_enabled',
      'file_uploads_enabled', 'maintenance_mode', 'app_name', 'max_context_messages',
      'blocked_ips', 'cost_per_1k_tokens', 'free_daily_limit', 'premium_daily_limit',
      'moderation_enabled', 'knowledge_base_enabled'
    ];
    const safeSettings = Object.fromEntries(
      allowedSettings.filter(key => Object.prototype.hasOwnProperty.call(req.body, key))
        .map(key => [key, req.body[key]])
    );
    cfg = { ...cfg, ...safeSettings };
    saveCfg();
    await sysLog('info', 'admin', `Settings updated by ${req.admin.username}`);
    const io = req.app.get('io');
    if (io && req.body.maintenance_mode !== undefined) io.emit('maintenance_mode', { active: req.body.maintenance_mode });
    res.json({ success: true, settings: { ...cfg, groq_model: process.env.GROQ_MODEL || DEFAULT_MODEL } });
  } catch { res.status(500).json({ error: 'Failed to save settings' }); }
});

/* ── USAGE & BILLING ─────────────────────────────────────────── */
app.get('/api/admin/usage', adminGuard, async (req, res) => {
  try {
    const thirtyDaysAgo = new Date(Date.now() - 30 * 24 * 60 * 60 * 1000);
    const [tokenAgg, total_requests, success_requests, by_user, by_day, plans] = await Promise.all([
      UsageTracking.aggregate([{ $group: { _id: null, total: { $sum: '$tokens_used' } } }]),
      UsageTracking.countDocuments(),
      UsageTracking.countDocuments({ success: true }),
      UsageTracking.aggregate([
        { $group: { _id: '$user_id', tokens: { $sum: '$tokens_used' }, requests: { $sum: 1 } } },
        { $lookup: { from: 'users', localField: '_id', foreignField: '_id', as: 'user' } },
        { $unwind: '$user' },
        { $project: { username: '$user.username', tokens: 1, requests: 1, _id: 0 } },
        { $sort: { tokens: -1 } }, { $limit: 10 }
      ]),
      UsageTracking.aggregate([
        { $match: { created_at: { $gte: thirtyDaysAgo } } },
        { $group: { _id: { $dateToString: { format: '%Y-%m-%d', date: '$created_at' } }, tokens: { $sum: '$tokens_used' }, requests: { $sum: 1 }, avg_ms: { $avg: '$response_ms' } } },
        { $sort: { _id: 1 } }, { $project: { date: '$_id', tokens: 1, requests: 1, avg_ms: 1, _id: 0 } }
      ]),
      UserPlan.aggregate([{ $group: { _id: '$plan', count: { $sum: 1 } } }, { $project: { plan: '$_id', count: 1, _id: 0 } }])
    ]);
    const total_tokens = tokenAgg[0]?.total || 0;
    const total_cost = (total_tokens / 1000 * (cfg.cost_per_1k_tokens || 0.002)).toFixed(4);
    res.json({ total_tokens, total_requests, success_requests, total_cost, by_user, by_day, plans });
  } catch { res.json({ total_tokens: 0, total_requests: 0, total_cost: 0, by_user: [], by_day: [], plans: [] }); }
});

/* ── MODERATION ──────────────────────────────────────────────── */
app.get('/api/admin/moderation', adminGuard, async (req, res) => {
  try {
    const flagged = await FlaggedContent.find({ reviewed: false })
      .populate('message_id', 'content')
      .populate('user_id', 'username')
      .sort({ created_at: -1 }).limit(50).lean();
    res.json(flagged.map(f => ({
      ...f, id: f._id.toString(), _id: undefined,
      content: f.message_id?.content,
      username: f.user_id?.username,
    })));
  } catch { res.json([]); }
});

app.put('/api/admin/moderation/:id/review', adminGuard, async (req, res) => {
  try { await FlaggedContent.findByIdAndUpdate(req.params.id, { reviewed: true }); res.json({ success: true }); }
  catch { res.status(500).json({ error: 'Failed' }); }
});

/* ── KNOWLEDGE BASE ──────────────────────────────────────────── */
app.get('/api/admin/knowledge', adminGuard, async (req, res) => {
  try { res.json(fmtArr(await KnowledgeBase.find().select('title file_type created_at').sort({ created_at: -1 }).lean())); }
  catch { res.json([]); }
});

app.post('/api/admin/knowledge', adminGuard, upload.single('file'), async (req, res) => {
  const { title, content } = req.body;
  if (!title) return res.status(400).json({ error: 'Title required' });
  try {
    let fileContent = content || '';
    let fileUrl = null, fileType = 'text';
    if (req.file) {
      fileUrl = `/uploads/${req.file.filename}`;
      fileType = req.file.mimetype;
      const extracted = extractTextFromFile(req.file.path);
      if (extracted) fileContent = extracted;
    }
    if (!fileContent) return res.status(400).json({ error: 'Content or file required' });
    const kb = await KnowledgeBase.create({ title, content: fileContent, file_url: fileUrl, file_type: fileType, uploaded_by: req.admin.id });
    res.json({ id: kb._id.toString(), title, success: true });
  } catch { res.status(500).json({ error: 'Failed to add knowledge' }); }
});

app.delete('/api/admin/knowledge/:id', adminGuard, async (req, res) => {
  try { await KnowledgeBase.findByIdAndDelete(req.params.id); res.json({ success: true }); }
  catch { res.status(500).json({ error: 'Failed' }); }
});

/* ── FILES ───────────────────────────────────────────────────── */
app.get('/api/admin/files', adminGuard, async (req, res) => {
  try {
    const dir = './uploads';
    if (!fs.existsSync(dir)) return res.json({ files: [], total_size: 0 });
    const files = fs.readdirSync(dir).map(name => {
      const stat = fs.statSync(`${dir}/${name}`);
      const ext = name.split('.').pop()?.toLowerCase() || '';
      return { name, size: stat.size, created: stat.birthtime, url: `/uploads/${name}`, type: /^(jpg|jpeg|png|gif|webp|svg)$/.test(ext) ? 'image' : 'file', ext };
    }).sort((a, b) => new Date(b.created) - new Date(a.created));
    res.json({ files, total_size: files.reduce((s, f) => s + f.size, 0) });
  } catch { res.json({ files: [], total_size: 0 }); }
});

app.delete('/api/admin/files/:name', adminGuard, async (req, res) => {
  try {
    const p = `./uploads/${req.params.name.replace(/\.\./g, '')}`;
    if (fs.existsSync(p)) fs.unlinkSync(p);
    await sysLog('warn', 'admin', `Deleted file: ${req.params.name}`);
    res.json({ success: true });
  } catch { res.status(500).json({ error: 'Failed' }); }
});

/* ── VISITORS ────────────────────────────────────────────────── */
app.get('/api/admin/visitors', adminGuard, async (req, res) => {
  try {
    const last24h = new Date(Date.now() - 24 * 60 * 60 * 1000);
    const todayStart = new Date(); todayStart.setHours(0, 0, 0, 0);
    const [totalAgg, todayAgg, by_page, by_hour, recent] = await Promise.all([
      PageView.aggregate([{ $group: { _id: '$session_id' } }, { $count: 'total' }]),
      PageView.aggregate([{ $match: { created_at: { $gte: todayStart } } }, { $group: { _id: '$session_id' } }, { $count: 'total' }]),
      PageView.aggregate([{ $group: { _id: '$page', views: { $sum: 1 } } }, { $sort: { views: -1 } }, { $limit: 10 }, { $project: { page: '$_id', views: 1, _id: 0 } }]),
      PageView.aggregate([
        { $match: { created_at: { $gte: last24h } } },
        { $group: { _id: { $hour: '$created_at' }, views: { $sum: 1 } } },
        { $sort: { _id: 1 } }, { $project: { hour: '$_id', views: 1, _id: 0 } }
      ]),
      PageView.find().sort({ created_at: -1 }).limit(20).lean()
    ]);
    res.json({ total: totalAgg[0]?.total || 0, today: todayAgg[0]?.total || 0, by_page, by_hour, recent: fmtArr(recent) });
  } catch { res.json({ total: 0, today: 0, by_page: [], by_hour: [], recent: [] }); }
});

/* ── LOGS ────────────────────────────────────────────────────── */
app.get('/api/admin/logs', adminGuard, async (req, res) => {
  const { level, page = 1, limit = 50 } = req.query;
  const skip = (parseInt(page) - 1) * parseInt(limit);
  try {
    const filter = level && level !== 'all' ? { level } : {};
    const [logs, total] = await Promise.all([
      SystemLog.find(filter).sort({ created_at: -1 }).skip(skip).limit(parseInt(limit)).lean(),
      SystemLog.countDocuments(filter)
    ]);
    res.json({ logs: fmtArr(logs), total });
  } catch { res.json({ logs: [], total: 0 }); }
});

/* ── SECURITY ────────────────────────────────────────────────── */
app.get('/api/admin/security', adminGuard, async (req, res) => {
  try {
    const suspicious = await PageView.aggregate([
      { $match: { ip_address: { $ne: null } } },
      { $group: { _id: '$ip_address', hits: { $sum: 1 }, last_seen: { $max: '$created_at' } } },
      { $sort: { hits: -1 } }, { $limit: 20 },
      { $project: { ip_address: '$_id', hits: 1, last_seen: 1, _id: 0 } }
    ]);
    res.json({ blocked_ips: cfg.blocked_ips || [], suspicious });
  } catch { res.json({ blocked_ips: [], suspicious: [] }); }
});

app.post('/api/admin/security/block-ip', adminGuard, async (req, res) => {
  const { ip } = req.body;
  if (!ip) return res.status(400).json({ error: 'IP required' });
  try {
    if (!cfg.blocked_ips) cfg.blocked_ips = [];
    if (!cfg.blocked_ips.includes(ip)) cfg.blocked_ips.push(ip);
    saveCfg(); await sysLog('warn', 'admin', `Blocked IP: ${ip}`);
    res.json({ success: true });
  } catch { res.status(500).json({ error: 'Failed' }); }
});

app.delete('/api/admin/security/block-ip/:ip', adminGuard, async (req, res) => {
  try {
    cfg.blocked_ips = (cfg.blocked_ips || []).filter(i => i !== req.params.ip);
    saveCfg(); res.json({ success: true });
  } catch { res.status(500).json({ error: 'Failed' }); }
});

/* ── ADMINS LIST ─────────────────────────────────────────────── */
app.get('/api/admin/admins', adminGuard, async (req, res) => {
  try { res.json(fmtArr(await Admin.find().select('username email role created_at last_login').sort({ created_at: 1 }).lean())); }
  catch { res.json([]); }
});

app.delete('/api/admin/admins/:id', adminGuard, async (req, res) => {
  if (req.admin.id === req.params.id) return res.status(400).json({ error: 'Cannot delete yourself' });
  try { await Admin.findByIdAndDelete(req.params.id); res.json({ success: true }); }
  catch { res.status(500).json({ error: 'Failed' }); }
});

/* ── EXPORT ──────────────────────────────────────────────────── */
app.get('/api/admin/export/users', adminGuard, async (req, res) => {
  try {
    const users = await User.find().select('username email profession referral_source onboarded is_banned created_at last_login').sort({ created_at: -1 }).lean();
    res.setHeader('Content-Type', 'text/csv');
    res.setHeader('Content-Disposition', 'attachment; filename=users.csv');
    const header = 'id,username,email,profession,referral,onboarded,banned,created_at,last_login\n';
    const rows = users.map(u => `${u._id},"${u.username}","${u.email}","${u.profession || ''}","${u.referral_source || ''}",${u.onboarded},${u.is_banned},"${u.created_at}","${u.last_login || ''}"`).join('\n');
    res.send(header + rows);
  } catch { res.status(500).json({ error: 'Export failed' }); }
});

app.get('/api/admin/export/chats', adminGuard, async (req, res) => {
  try {
    const chats = await Chat.find().populate('user_id', 'username email').sort({ created_at: -1 }).lean();
    const enriched = await Promise.all(chats.map(async c => ({
      ...c, msg_count: await Message.countDocuments({ chat_id: c._id })
    })));
    res.setHeader('Content-Type', 'text/csv');
    res.setHeader('Content-Disposition', 'attachment; filename=chats.csv');
    const header = 'id,title,username,email,messages,created_at,updated_at\n';
    const rows = enriched.map(c => `${c._id},"${c.title}","${c.user_id?.username || ''}","${c.user_id?.email || ''}",${c.msg_count},"${c.created_at}","${c.updated_at}"`).join('\n');
    res.send(header + rows);
  } catch { res.status(500).json({ error: 'Export failed' }); }
});

/* ── AI TEST PANEL ───────────────────────────────────────────── */
app.post('/api/admin/ai/test', adminGuard, async (req, res) => {
  const { prompt } = req.body;
  if (!prompt) return res.status(400).json({ error: 'Prompt required' });
  const start = Date.now();
  try {
    const data = await completeWithGroq({
      history: [{ role: 'user', content: prompt }],
      systemPrompt: cfg.system_prompt,
      maxTokens: cfg.max_tokens,
      temperature: cfg.temperature
    });
    res.json({ response: data.text, model: data.model, response_ms: Date.now() - start, status: 'success' });
  } catch (err) { res.status(503).json({ error: friendlyError(err), response_ms: Date.now() - start }); }
});

/* ── PERFORMANCE ─────────────────────────────────────────────── */
app.get('/api/admin/performance', adminGuard, async (req, res) => {
  try {
    const last24h = new Date(Date.now() - 24 * 60 * 60 * 1000);
    const [avgAgg, errorAgg, by_hour] = await Promise.all([
      UsageTracking.aggregate([{ $match: { success: true } }, { $group: { _id: null, avg: { $avg: '$response_ms' } } }]),
      UsageTracking.aggregate([
        { $match: { created_at: { $gte: last24h } } },
        { $group: { _id: null, total: { $sum: 1 }, errors: { $sum: { $cond: ['$success', 0, 1] } } } }
      ]),
      UsageTracking.aggregate([
        { $match: { created_at: { $gte: last24h } } },
        { $group: { _id: { $hour: '$created_at' }, avg_ms: { $avg: '$response_ms' }, requests: { $sum: 1 } } },
        { $sort: { _id: 1 } }, { $project: { hour: '$_id', avg_ms: 1, requests: 1, _id: 0 } }
      ])
    ]);
    res.json({ avg_response_ms: Math.round(avgAgg[0]?.avg || 0), error_rate: errorAgg[0] || { total: 0, errors: 0 }, by_hour, uptime_ms: process.uptime() * 1000, memory: process.memoryUsage() });
  } catch { res.json({ avg_response_ms: 0, error_rate: { total: 0, errors: 0 }, by_hour: [] }); }
});

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

io.use((socket, next) => {
  const t = socket.handshake.auth?.token;
  const a = socket.handshake.auth?.adminToken;
  if (t) { try { socket.user = jwt.verify(t, JWT_SECRET); return next(); } catch {} }
  if (a) { try { const d = jwt.verify(a, ADMIN_SECRET); if (d.isAdmin) { socket.admin = d; return next(); } } catch {} }
  return next(new Error('Auth required'));
});

io.on('connection', socket => {
  if (socket.user) {
    socket.join(`user_${socket.user.id}`);
    socket.on('join_chat', id => socket.join(`chat_${id}`));
    socket.on('leave_chat', id => socket.leave(`chat_${id}`));
    socket.on('typing', ({ chatId, isTyping }) => {
      socket.to(`chat_${chatId}`).emit('user_typing', { userId: socket.user.id, username: socket.user.username, isTyping });
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
connectDB().then(() => {
  server.listen(PORT, () => {
    console.log(`\n✅ KinyaBot v7.0 (MongoDB) → http://localhost:${PORT}`);
    console.log(`   Admin  → http://localhost:5173/admin\n`);
  });
});
