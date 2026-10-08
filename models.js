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
  /* Public, collision-resistant conversation identifier (UUID v4).
     Used in URLs as /chat/c/{conversation_id} — Mongo ObjectIds are
     NEVER exposed in URLs. Unique + sparse so legacy documents
     created before this field exist safely until the idempotent
     startup migration backfills them (see app.js).               */
  conversation_id: { type: String, default: null },
  /* Conversation mode: 'chat' (default), 'web_search' (explicit web
     research — Pro feature) and 'agent' reserved for the upcoming
     Agent mode (tool calls, artifacts, execution logs).
     Restored on load so the composer reopens in the right mode.   */
  mode:  { type: String, enum: ['chat', 'web_search', 'agent'], default: 'chat' },
  /* Model that produced the latest assistant response (display +
     restoration purposes — the backend always picks the real model). */
  model: { type: String, default: null },
  // Rolling context summary for very long conversations (AI Core §5)
  summary:       { type: String, default: null },
  summary_depth: { type: Number, default: 0 },   // message count covered by the summary
}, { timestamps: { createdAt: 'created_at', updatedAt: 'updated_at' } });

chatSchema.index({ conversation_id: 1 }, { unique: true, sparse: true });
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
  /* ── Edit history (user messages) ────────────────────────────
     Previous versions of an edited user message. The visible
     conversation shows only `content`; edits stay recoverable
     internally without cluttering the thread (§18).             */
  edit_history:  {
    type: [{ content: { type: String, default: '' }, edited_at: { type: Date, default: null } }],
    default: [],
  },
  /* ── Response versions (assistant messages, §20) ─────────────
     Regeneration appends the previous answer here instead of
     destroying it. `content` always mirrors
     versions[active_version] so context building stays simple.
     versions = [oldest … newest]; active_version indexes into it
     (null for legacy messages that were never regenerated).     */
  versions: {
    type: [{
      content:      { type: String, default: '' },
      model:        { type: String, default: null },
      tokens:       { type: Number, default: null },
      created_at:   { type: Date, default: null },
      processing_ms:{ type: Number, default: null },
      status:       { type: String, enum: ['completed', 'cancelled'], default: 'completed' },
    }],
    default: [],
  },
  active_version: { type: Number, default: null },
  /* Branching: messages superseded by an edit/regenerate of an
     earlier turn. Hidden from the active conversation and context
     but preserved in the database for recovery/audit (§18).     */
  superseded:    { type: Boolean, default: false },
  // AI provenance (assistant messages)
  model:         { type: String, default: null },
  provider:      { type: String, default: null },
  tokens:        { type: Number, default: null },
  processing_ms: { type: Number, default: null },
  // generation lifecycle: completed | cancelled (partial) | failed
  status:        { type: String, enum: ['completed', 'cancelled', 'failed'], default: 'completed' },
  // surfaced sources (only when the backend actually knows them)
  sources:       { type: [String], default: [] },
  /* ── Web-grounded answer provenance (Web Search §12/§42) ────
     Populated ONLY when the backend actually performed a real web
     search for this turn. All URLs originate from the search
     provider — never fabricated. Null for ordinary turns.       */
  web_search: {
    type: {
      performed:    { type: Boolean, default: false },
      mode:         { type: String, enum: ['auto', 'manual', 'agent'], default: 'auto' },
      queries:      { type: [String], default: [] },        // the ACTUAL queries sent
      sources:      { type: [{
        title:          { type: String, default: '' },
        url:            { type: String, required: true },
        domain:         { type: String, default: '' },
        snippet:        { type: String, default: '' },
        published_date: { type: String, default: null },   // as returned by the provider
        icon:           { type: String, default: null },    // provider-provided site icon or null
      }], default: [] },
      result_count: { type: Number, default: 0 },
      duration_ms:  { type: Number, default: 0 },
      status:       { type: String, enum: ['success', 'empty', 'unavailable'], default: 'success' },
      cached:       { type: Boolean, default: false },
    },
    default: null,
  },
}, { timestamps: { createdAt: 'created_at', updatedAt: false } });

messageSchema.index({ chat_id: 1, created_at: 1 });
messageSchema.index({ chat_id: 1, superseded: 1, created_at: 1 });
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
/* KinyaBot plan system: FREE / PLUS / PRO.
   One document per user — users without a document are treated as
   FREE by services/plans.js, so existing accounts keep working.
   Legacy 'premium'/'enterprise' values are normalized to 'pro'
   at startup (see app.js).                                      */
const userPlanSchema = new Schema({
  user_id:       { type: Schema.Types.ObjectId, ref: 'User', required: true, unique: true, index: true },
  plan:          { type: String, enum: ['free', 'plus', 'pro'], default: 'free' },
  daily_limit:   { type: Number, default: 50 },   // denormalized snapshot at assignment time
  monthly_limit: { type: Number, default: 0 },
  tokens_limit:  { type: Number, default: 0 },
  // Subscription lifecycle (§26). Manual approvals only for now —
  // payment providers can set activation_source later (§25).
  status:            { type: String, enum: ['active', 'pending', 'expired', 'cancelled', 'suspended'], default: 'active' },
  activation_source: { type: String, enum: ['manual_admin_approval', 'stripe', 'paypal', 'other'], default: 'manual_admin_approval' },
  activated_by:      { type: String, default: null },   // admin username
  activated_at:      { type: Date,   default: null },
  previous_plan:     { type: String, default: null },
  // Last plan change awaiting user acknowledgement (celebration UI)
  last_change: {
    from: { type: String, default: null },
    to:   { type: String, default: null },
    at:   { type: Date,   default: null },
    ack:  { type: Boolean, default: true },
  },
}, { timestamps: { createdAt: false, updatedAt: 'updated_at' } });

userPlanSchema.index({ plan: 1 });

/* ── PLAN CONFIG (centralized, SuperAdmin-editable) ─────────────
   One document per plan. The application NEVER hard-codes plan
   limits — services/plans.js reads these (cached) so limits and
   feature flags can change without code changes (§2).            */
const planConfigSchema = new Schema({
  plan_id:  { type: String, required: true, unique: true, lowercase: true, trim: true }, // free | plus | pro
  name:     { type: String, required: true },
  tagline:  { type: String, default: '' },
  daily_chat_limit:  { type: Number, required: true, min: 1, max: 100000 },
  context_messages:  { type: Number, default: 10, min: 1, max: 200 },  // recent messages kept in context
  doc_size_multiplier: { type: Number, default: 1, min: 1, max: 10 },  // document upload allowance vs baseline
  burst_multiplier:    { type: Number, default: 1, min: 1, max: 10 },  // short-burst rate limit multiplier
  // Feature flags (§27) — future capabilities ship by adding a flag
  features: {
    chatAccess:          { type: Boolean, default: true },
    voiceAccess:         { type: Boolean, default: true },
    imageGeneration:     { type: Boolean, default: true },
    documentAnalysis:    { type: Boolean, default: true },
    advancedContext:     { type: Boolean, default: false },
    agentAccess:         { type: Boolean, default: false },
    priorityProcessing:  { type: Boolean, default: false },
    advancedTools:       { type: Boolean, default: true },
    webSearch:           { type: Boolean, default: false }, // PRO-only (Web Search §2)
  },
  is_active: { type: Boolean, default: true },
  sort_order: { type: Number, default: 0 },
}, { timestamps: { createdAt: 'created_at', updatedAt: 'updated_at' } });

planConfigSchema.index({ sort_order: 1 });

/* ── DAILY USAGE (single authoritative source for daily usage) ──
   One document per user per day keyed by an application-timezone
   date string (services/usage.js). Atomic $inc counters keep
   concurrent requests from exceeding the plan limit (§36).       */
const usageDailySchema = new Schema({
  user_id:     { type: Schema.Types.ObjectId, ref: 'User', required: true },
  date:        { type: String, required: true },  // 'YYYY-MM-DD' in APP_TIMEZONE
  chats_used:  { type: Number, default: 0, min: 0 },
  // One-time flags so near-limit / limit notifications fire once per day
  near_notified:   { type: Boolean, default: false },
  reached_notified:{ type: Boolean, default: false },
}, { timestamps: { createdAt: 'created_at', updatedAt: 'updated_at' } });

usageDailySchema.index({ user_id: 1, date: 1 }, { unique: true });
usageDailySchema.index({ date: 1, chats_used: -1 });

/* ── PLAN REQUEST (manual upgrade workflow §9-§16) ───────────── */
const planRequestSchema = new Schema({
  user_id:       { type: Schema.Types.ObjectId, ref: 'User', required: true, index: true },
  full_name:     { type: String, required: true, trim: true, maxlength: 120 },
  email:         { type: String, required: true, lowercase: true, trim: true, maxlength: 200 },
  country:       { type: String, required: true, trim: true, maxlength: 80 },
  country_code:  { type: String, default: null, maxlength: 8 },   // ISO-3166 alpha-2, e.g. RW
  phone:         { type: String, required: true, trim: true, maxlength: 32 },
  current_plan:  { type: String, required: true, enum: ['free', 'plus', 'pro'] },
  requested_plan:{ type: String, required: true, enum: ['free', 'plus', 'pro'] },
  message:       { type: String, default: '', maxlength: 1000 },
  status:        { type: String, enum: ['pending', 'approved', 'rejected'], default: 'pending', index: true },
  // Review trail
  reviewed_at:     { type: Date, default: null },
  reviewed_by:     { type: String, default: null },           // admin username
  reviewed_by_id:  { type: String, default: null },           // admin id
  rejection_reason:{ type: String, default: null, maxlength: 500 },
  approval_notes:  { type: String, default: null, maxlength: 500 },
  // Snapshot of the user's plan when the request was created
  current_daily_limit: { type: Number, default: null },
}, { timestamps: { createdAt: 'created_at', updatedAt: 'updated_at' } });

planRequestSchema.index({ status: 1, created_at: -1 });
planRequestSchema.index({ user_id: 1, status: 1 });
planRequestSchema.index({ requested_plan: 1, created_at: -1 });

/* ── SEARCH LOG (Web Search metadata §21) ───────────────────────
   One row per REAL search attempt (success, empty or error).
   Metadata only — no full webpage content is ever stored here
   (privacy + storage cost, §21). The query itself is kept for the
   SuperAdmin "most searched" analytics and for the user's own
   history view; users can only ever read their own rows.         */
const searchLogSchema = new Schema({
  user_id:         { type: Schema.Types.ObjectId, ref: 'User', required: true, index: true },
  chat_id:         { type: Schema.Types.ObjectId, ref: 'Chat', default: null },
  conversation_id: { type: String, default: null },            // public UUID when known
  query:           { type: String, required: true, maxlength: 1000 },
  queries:         { type: [String], default: [] },            // optimized queries actually executed
  // What triggered the search: automatic decision, explicit user mode, or the Agent tool
  trigger:         { type: String, enum: ['auto', 'manual', 'agent'], required: true },
  plan:            { type: String, enum: ['free', 'plus', 'pro'], default: 'free' },
  result_count:    { type: Number, default: 0 },
  source_domains:  { type: [String], default: [] },
  duration_ms:     { type: Number, default: 0 },
  status:          { type: String, enum: ['success', 'empty', 'error', 'rate_limited'], default: 'success', index: true },
  error_code:      { type: String, default: null },            // LANGSEARCH_TIMEOUT, LANGSEARCH_AUTH, …
  cached:          { type: Boolean, default: false },
  usage: {         // provider-reported token usage when available
    input_tokens:  { type: Number, default: null },
    output_tokens: { type: Number, default: null },
  },
}, { timestamps: { createdAt: 'created_at', updatedAt: false } });

searchLogSchema.index({ created_at: -1 });
searchLogSchema.index({ user_id: 1, created_at: -1 });
searchLogSchema.index({ trigger: 1, created_at: -1 });
searchLogSchema.index({ plan: 1, created_at: -1 });
searchLogSchema.index({ status: 1, created_at: -1 });

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
  PlanConfig:        mongoose.model('PlanConfig',        planConfigSchema),
  UsageDaily:        mongoose.model('UsageDaily',        usageDailySchema),
  PlanRequest:       mongoose.model('PlanRequest',       planRequestSchema),
  FlaggedContent:    mongoose.model('FlaggedContent',    flaggedContentSchema),
  SearchLog:         mongoose.model('SearchLog',         searchLogSchema),
};
