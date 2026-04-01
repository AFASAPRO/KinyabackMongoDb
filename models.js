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
  otp_code:        { type: String, default: null },
  otp_expires:     { type: Date,   default: null },
  reset_token:     { type: String, default: null },
  reset_token_expires: { type: Date, default: null },
  is_banned:       { type: Boolean, default: false },
  last_login:      { type: Date,   default: null },
}, { timestamps: { createdAt: 'created_at', updatedAt: false } });

userSchema.index({ reset_token: 1 });

/* ── CHAT ─────────────────────────────────────────────────────── */
const chatSchema = new Schema({
  user_id:   { type: Schema.Types.ObjectId, ref: 'User', required: true },
  title:     { type: String, default: 'New Chat', maxlength: 255 },
  is_pinned: { type: Boolean, default: false },
}, { timestamps: { createdAt: 'created_at', updatedAt: 'updated_at' } });

chatSchema.index({ user_id: 1, updated_at: -1 });

/* ── MESSAGE ──────────────────────────────────────────────────── */
const messageSchema = new Schema({
  chat_id:  { type: Schema.Types.ObjectId, ref: 'Chat', required: true },
  role:     { type: String, enum: ['user', 'assistant'], required: true },
  content:  { type: String, required: true },
  file_url: { type: String, default: null },
}, { timestamps: { createdAt: 'created_at', updatedAt: false } });

messageSchema.index({ chat_id: 1, created_at: 1 });
messageSchema.index({ content: 'text' });

/* ── ADMIN ────────────────────────────────────────────────────── */
const adminSchema = new Schema({
  username:      { type: String, required: true, unique: true, trim: true },
  email:         { type: String, required: true, unique: true, lowercase: true },
  password_hash: { type: String, required: true },
  role:          { type: String, enum: ['super_admin', 'admin', 'moderator'], default: 'admin' },
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
  request_type: { type: String, enum: ['chat', 'image', 'file'], default: 'chat' },
  response_ms:  { type: Number, default: 0 },
  success:      { type: Boolean, default: true },
}, { timestamps: { createdAt: 'created_at', updatedAt: false } });

usageTrackingSchema.index({ user_id: 1, created_at: -1 });
usageTrackingSchema.index({ created_at: -1 });

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
}, { timestamps: { createdAt: 'created_at', updatedAt: false } });

flaggedContentSchema.index({ reviewed: 1 });

/* ── EXPORTS ──────────────────────────────────────────────────── */
module.exports = {
  User:           mongoose.model('User',           userSchema),
  Chat:           mongoose.model('Chat',           chatSchema),
  Message:        mongoose.model('Message',        messageSchema),
  Admin:          mongoose.model('Admin',          adminSchema),
  Notification:   mongoose.model('Notification',   notificationSchema),
  PageView:       mongoose.model('PageView',       pageViewSchema),
  SystemLog:      mongoose.model('SystemLog',      systemLogSchema),
  UserMemory:     mongoose.model('UserMemory',     userMemorySchema),
  KnowledgeBase:  mongoose.model('KnowledgeBase',  knowledgeBaseSchema),
  UsageTracking:  mongoose.model('UsageTracking',  usageTrackingSchema),
  UserPlan:       mongoose.model('UserPlan',       userPlanSchema),
  FlaggedContent: mongoose.model('FlaggedContent', flaggedContentSchema),
};
