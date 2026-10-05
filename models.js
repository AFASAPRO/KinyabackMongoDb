/**
 * KinyaBot — MongoDB Models (Mongoose)
 * Replaces all MySQL tables with equivalent Mongoose schemas.
 */
const mongoose = require('mongoose');
const { Schema } = mongoose;

/* ── USER ─────────────────────────────────────────────────────── */
const userSchema = new Schema({
  username:        { type: String, required: true, unique: true, trim: true, minlength: 3 },
  email:           { type: String, required: true, unique: true, lowercase: true, trim: true },
  password_hash:   { type: String, required: true },
  avatar_url:      { type: String, default: null },
  profession:      { type: String, default: null },
  referral_source: { type: String, default: null },
  onboarded:       { type: Boolean, default: false },
  email_verified:  { type: Boolean, default: false },
  usage_type:      { type: String, default: null },   // 'personal' | 'team' | 'organization' | 'other'
  workspace_name:  { type: String, default: null },
  use_cases:       { type: [String], default: [] },
  otp_code:        { type: String, default: null },
  otp_expires:     { type: Date,   default: null },
  email_otp_code:    { type: String, default: null },
  email_otp_expires: { type: Date,   default: null },
  reset_token:     { type: String, default: null },
  reset_token_expires: { type: Date, default: null },
  is_banned:       { type: Boolean, default: false },
  last_login:      { type: Date,   default: null },
}, { timestamps: { createdAt: 'created_at', updatedAt: false } });

userSchema.index({ reset_token: 1 });
// Superadmin filters / analytics (username & email are already indexed
// via unique: true — no duplicate declarations here)
userSchema.index({ created_at: -1 });
userSchema.index({ last_login: -1 });
userSchema.index({ is_banned: 1 });

/* ── CHAT ─────────────────────────────────────────────────────── */
const chatSchema = new Schema({
  user_id:   { type: Schema.Types.ObjectId, ref: 'User', required: true },
  title:     { type: String, default: 'New Chat', maxlength: 255 },
  is_pinned: { type: Boolean, default: false },
  // Rolling context summary for very long conversations (AI Core §5)
  summary:       { type: String, default: null },
  summary_depth: { type: Number, default: 0 },   // message count covered by the summary
}, { timestamps: { createdAt: 'created_at', updatedAt: 'updated_at' } });

chatSchema.index({ user_id: 1, updated_at: -1 });
chatSchema.index({ updated_at: -1 });
chatSchema.index({ created_at: -1 });
chatSchema.index({ title: 'text' });

/* ── MESSAGE ──────────────────────────────────────────────────── */
const attachmentSchema = new Schema({
  kind:           { type: String, enum: ['image', 'document', 'audio'], required: true },
  url:            { type: String, required: true },   // served via authenticated /api/files/:name
  name:           { type: String, default: '' },
  mime:           { type: String, default: null },
  size:           { type: Number, default: 0 },
  pages:          { type: Number, default: null },    // PDFs where known — never fabricated
  extracted_text: { type: String, default: null },    // bounded document text for follow-ups
}, { _id: false });

const messageSchema = new Schema({
  chat_id:       { type: Schema.Types.ObjectId, ref: 'Chat', required: true },
  role:          { type: String, enum: ['user', 'assistant'], required: true },
  // Empty content is allowed for attachment-only messages (image/document
  // uploads without a caption); the UI renders just the attachment.
  content:       { type: String, default: '' },
  file_url:      { type: String, default: null },            // legacy single-attachment field
  message_type:  { type: String, enum: ['text', 'image', 'document', 'audio'], default: 'text' },
  attachments:   { type: [attachmentSchema], default: [] },
  // AI provenance (assistant messages)
  model:         { type: String, default: null },
  provider:      { type: String, default: null },
  tokens:        { type: Number, default: null },
  processing_ms: { type: Number, default: null },
  // generation lifecycle: completed | cancelled (partial) | failed
  status:        { type: String, enum: ['completed', 'cancelled', 'failed'], default: 'completed' },
  // surfaced sources (only when the backend actually knows them)
  sources:       { type: [String], default: [] },
}, { timestamps: { createdAt: 'created_at', updatedAt: false } });

messageSchema.index({ chat_id: 1, created_at: 1 });
messageSchema.index({ content: 'text' });
// Superadmin analytics (time-series, per-model usage)
messageSchema.index({ created_at: -1 });
messageSchema.index({ model: 1, created_at: -1 });
messageSchema.index({ status: 1 });

/* ── ADMIN ──────────────────────────────────────────────────────
   KinyaBot has exactly ONE administrative role: super_admin.
   No admin / moderator / sub-admin hierarchy exists or will exist.
   Legacy documents created with other roles are normalized to
   super_admin on startup (see app.js).                          */
const adminSchema = new Schema({
  username:      { type: String, required: true, unique: true, trim: true },
  email:         { type: String, required: true, unique: true, lowercase: true },
  password_hash: { type: String, required: true },
  role:          { type: String, enum: ['super_admin'], default: 'super_admin' },
  last_login:    { type: Date, default: null },
}, { timestamps: { createdAt: 'created_at', updatedAt: false } });

/* ── NOTIFICATION ─────────────────────────────────────────────── */
const notificationSchema = new Schema({
  title:      { type: String, required: true },
  message:    { type: String, required: true },
  type:       { type: String, enum: ['info', 'success', 'warning', 'error'], default: 'info' },
  is_active:  { type: Boolean, default: true },
  created_by: { type: Schema.Types.ObjectId, ref: 'Admin', default: null },
  expires_at: { type: Date, default: null },
}, { timestamps: { createdAt: 'created_at', updatedAt: false } });

/* ── ADMIN NOTIFICATION (Superadmin control-center feed) ────────
   Generated ONLY from real system events (AI failures, security
   events, moderation flags, config changes, milestones…).
   Distinct from `Notification`, which is the user-facing broadcast. */
const adminNotificationSchema = new Schema({
  title:     { type: String, required: true },
  message:   { type: String, required: true },
  // display severity
  type:      { type: String, enum: ['info', 'success', 'warning', 'error', 'critical'], default: 'info' },
  // event domain — used by the notification center filters
  category:  { type: String, enum: ['system', 'ai', 'security', 'user', 'moderation', 'config', 'usage'], default: 'system' },
  read:      { type: Boolean, default: false },
  // deep link path inside the Superadmin app (e.g. '/admin/ai')
  link:      { type: String, default: null },
  resource:  { kind: { type: String, default: null }, id: { type: String, default: null } },
  meta:      { type: Schema.Types.Mixed, default: null },
}, { timestamps: { createdAt: 'created_at', updatedAt: false } });

adminNotificationSchema.index({ read: 1, created_at: -1 });
adminNotificationSchema.index({ category: 1, created_at: -1 });
adminNotificationSchema.index({ type: 1 });

/* ── AUDIT LOG (immutable Superadmin action trail) ──────────────
   One row per administrative mutation. Never updated or deleted by
   any endpoint — only created.                                    */
const auditLogSchema = new Schema({
  actor_id:       { type: String, default: null },   // Admin id string
  actor_username: { type: String, default: null },
  action:         { type: String, required: true },  // e.g. 'user.ban'
  resource_type:  { type: String, default: null },   // e.g. 'user'
  resource_id:    { type: String, default: null },
  resource_label: { type: String, default: null },   // human-readable name
  result:         { type: String, enum: ['success', 'failure'], default: 'success' },
  meta:           { type: Schema.Types.Mixed, default: null },
  ip:             { type: String, default: null },   // only what the server genuinely sees
}, { timestamps: { createdAt: 'created_at', updatedAt: false } });

auditLogSchema.index({ created_at: -1 });
auditLogSchema.index({ actor_id: 1, created_at: -1 });
auditLogSchema.index({ action: 1, created_at: -1 });
auditLogSchema.index({ resource_type: 1, created_at: -1 });

/* ── SECURITY EVENT (real auth/security telemetry) ──────────────
   Written at the exact moment a real security-relevant thing
   happens: failed logins, successful admin sign-ins, bans,
   password resets, IP blocks, unauthorized API access, rate-limit
   trips. No synthetic entries, ever.                              */
const securityEventSchema = new Schema({
  type:       { type: String, required: true },  // login_failed, admin_login_failed, admin_login, password_reset, banned, unbanned, ip_blocked, ip_unblocked, unauthorized_access, rate_limited, moderation_flag
  severity:   { type: String, enum: ['info', 'warning', 'critical'], default: 'info' },
  username:   { type: String, default: null },
  ip:         { type: String, default: null },
  user_agent: { type: String, default: null },
  message:    { type: String, default: null },
  meta:       { type: Schema.Types.Mixed, default: null },
}, { timestamps: { createdAt: 'created_at', updatedAt: false } });

securityEventSchema.index({ created_at: -1 });
securityEventSchema.index({ type: 1, created_at: -1 });
securityEventSchema.index({ severity: 1, created_at: -1 });
securityEventSchema.index({ ip: 1, created_at: -1 });

/* ── PUSH SUBSCRIPTION (Superadmin PWA web-push endpoints) ───── */
const pushSubscriptionSchema = new Schema({
  endpoint:   { type: String, required: true, unique: true },
  keys: {
    p256dh: { type: String, required: true },
    auth:   { type: String, required: true },
  },
  user_agent: { type: String, default: null },
}, { timestamps: { createdAt: 'created_at', updatedAt: false } });

/* ── PAGE VIEW ────────────────────────────────────────────────── */
const pageViewSchema = new Schema({
  session_id: { type: String, default: null },
  page:       { type: String, default: null },
  user_id:    { type: Schema.Types.ObjectId, ref: 'User', default: null },
  ip_address: { type: String, default: null },
  user_agent: { type: String, default: null },
}, { timestamps: { createdAt: 'created_at', updatedAt: false } });

pageViewSchema.index({ created_at: -1 });
pageViewSchema.index({ session_id: 1 });

/* ── SYSTEM LOG ───────────────────────────────────────────────── */
const systemLogSchema = new Schema({
  level:   { type: String, enum: ['info', 'warn', 'error', 'debug'], default: 'info' },
  source:  { type: String, default: null },
  message: { type: String, required: true },
  data:    { type: Schema.Types.Mixed, default: null },
  user_id: { type: Schema.Types.ObjectId, ref: 'User', default: null },
}, { timestamps: { createdAt: 'created_at', updatedAt: false } });

systemLogSchema.index({ created_at: -1 });
systemLogSchema.index({ level: 1 });
systemLogSchema.index({ source: 1, created_at: -1 });

/* ── USER MEMORY ──────────────────────────────────────────────── */
const userMemorySchema = new Schema({
  user_id:      { type: Schema.Types.ObjectId, ref: 'User', required: true },
  memory_key:   { type: String, required: true },
  memory_value: { type: String, required: true },
}, { timestamps: { createdAt: 'created_at', updatedAt: 'updated_at' } });

userMemorySchema.index({ user_id: 1, memory_key: 1 }, { unique: true });

/* ── KNOWLEDGE BASE ───────────────────────────────────────────── */
const knowledgeBaseSchema = new Schema({
  title:       { type: String, required: true },
  content:     { type: String, required: true },
  file_url:    { type: String, default: null },
  file_type:   { type: String, default: null },
  uploaded_by: { type: Schema.Types.ObjectId, ref: 'Admin', default: null },
}, { timestamps: { createdAt: 'created_at', updatedAt: false } });

knowledgeBaseSchema.index({ content: 'text', title: 'text' });

/* ── USAGE TRACKING ───────────────────────────────────────────── */
const usageTrackingSchema = new Schema({
  user_id:      { type: Schema.Types.ObjectId, ref: 'User', required: true },
  chat_id:      { type: Schema.Types.ObjectId, ref: 'Chat', default: null },
  tokens_used:  { type: Number, default: 0 },
  request_type: { type: String, enum: ['chat', 'image', 'file', 'regenerate', 'stt', 'tts', 'document', 'ai_test'], default: 'chat' },
  response_ms:  { type: Number, default: 0 },
  success:      { type: Boolean, default: true },
}, { timestamps: { createdAt: 'created_at', updatedAt: false } });

usageTrackingSchema.index({ user_id: 1, created_at: -1 });
usageTrackingSchema.index({ created_at: -1 });
usageTrackingSchema.index({ success: 1, created_at: -1 });
usageTrackingSchema.index({ request_type: 1, created_at: -1 });

/* ── USER PLAN ────────────────────────────────────────────────── */
const userPlanSchema = new Schema({
  user_id:       { type: Schema.Types.ObjectId, ref: 'User', required: true, unique: true },
  plan:          { type: String, enum: ['free', 'premium', 'enterprise'], default: 'free' },
  daily_limit:   { type: Number, default: 50 },
  monthly_limit: { type: Number, default: 500 },
  tokens_limit:  { type: Number, default: 100000 },
}, { timestamps: { createdAt: false, updatedAt: 'updated_at' } });

/* ── FLAGGED CONTENT ──────────────────────────────────────────── */
const flaggedContentSchema = new Schema({
  message_id:   { type: Schema.Types.ObjectId, ref: 'Message', default: null },
  chat_id:      { type: Schema.Types.ObjectId, ref: 'Chat', default: null },
  user_id:      { type: Schema.Types.ObjectId, ref: 'User', default: null },
  reason:       { type: String, default: null },
  auto_flagged: { type: Boolean, default: false },
  reviewed:     { type: Boolean, default: false },
  // Superadmin moderation workflow — pending | reviewed | resolved | dismissed
  status:       { type: String, enum: ['pending', 'reviewed', 'resolved', 'dismissed'], default: 'pending' },
  resolved_by:  { type: String, default: null },
  resolved_at:  { type: Date, default: null },
}, { timestamps: { createdAt: 'created_at', updatedAt: false } });

flaggedContentSchema.index({ reviewed: 1 });
flaggedContentSchema.index({ status: 1, created_at: -1 });

/* ── EXPORTS ──────────────────────────────────────────────────── */
module.exports = {
  User:              mongoose.model('User',              userSchema),
  Chat:              mongoose.model('Chat',              chatSchema),
  Message:           mongoose.model('Message',           messageSchema),
  Admin:             mongoose.model('Admin',             adminSchema),
  Notification:      mongoose.model('Notification',      notificationSchema),
  AdminNotification: mongoose.model('AdminNotification', adminNotificationSchema),
  AuditLog:          mongoose.model('AuditLog',          auditLogSchema),
  SecurityEvent:     mongoose.model('SecurityEvent',     securityEventSchema),
  PushSubscription:  mongoose.model('PushSubscription',  pushSubscriptionSchema),
  PageView:          mongoose.model('PageView',          pageViewSchema),
  SystemLog:         mongoose.model('SystemLog',         systemLogSchema),
  UserMemory:        mongoose.model('UserMemory',        userMemorySchema),
  KnowledgeBase:     mongoose.model('KnowledgeBase',     knowledgeBaseSchema),
  UsageTracking:     mongoose.model('UsageTracking',     usageTrackingSchema),
  UserPlan:          mongoose.model('UserPlan',          userPlanSchema),
  FlaggedContent:    mongoose.model('FlaggedContent',    flaggedContentSchema),
};
