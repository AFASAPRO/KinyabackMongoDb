/**
 * KinyaBot AI Core — Centralized configuration
 * ─────────────────────────────────────────────────────────────
 * Single source of truth for every AI capability flag.
 * NOTHING in the AI stack reads process.env directly except this
 * file, so models/providers can be swapped through environment
 * variables or admin settings without touching feature code.
 *
 * Backward compatibility: GROQ_MODEL (legacy) is still honoured as
 * the chat model when GROQ_CHAT_MODEL is not set.
 */

function env(name, fallback = null) {
  const v = process.env[name]
  return v === undefined || v === null || String(v).trim() === '' ? fallback : String(v).trim()
}

function num(name, fallback) {
  const v = Number(process.env[name])
  return Number.isFinite(v) && v > 0 ? v : fallback
}

const chatModel = env('GROQ_CHAT_MODEL', env('GROQ_MODEL', 'llama-3.3-70b-versatile'))

const config = {
  /* ── Provider ─────────────────────────────────────────────── */
  provider: 'groq',
  apiKey: env('GROQ_API_KEY'),

  /* ── Models (per capability — §4 of the spec) ─────────────── */
  models: {
    chat:     chatModel,
    vision:   env('GROQ_VISION_MODEL', 'meta-llama/llama-4-scout-17b-16e-instruct'),
    document: env('GROQ_DOCUMENT_MODEL', chatModel),
    stt:      env('GROQ_STT_MODEL',   'whisper-large-v3-turbo'),
    tts:      env('GROQ_TTS_MODEL',   'playai-tts'),
  },
  ttsVoice: env('GROQ_TTS_VOICE', 'Celeste-PlayAI'),

  /* ── Context management (§5) ──────────────────────────────── */
  context: {
    maxMessages:      num('AI_CONTEXT_MAX_MESSAGES', 20),   // window of recent messages
    tokenBudget:      num('AI_CONTEXT_TOKEN_BUDGET', 6000), // ≈ chars/4 across history
    summarizeAfter:   num('AI_CONTEXT_SUMMARIZE_AFTER', 24),// summarize when history exceeds this
    summaryMaxTokens: num('AI_CONTEXT_SUMMARY_TOKENS', 256),
  },

  /* ── Upload / capability limits (§20, configurable) ───────── */
  limits: {
    imageSizeBytes:      num('MAX_IMAGE_SIZE',  4 * 1024 * 1024),   // 4 MB (Groq base64 vision limit)
    documentSizeBytes:   num('MAX_DOCUMENT_SIZE', 15 * 1024 * 1024),// 15 MB
    audioSizeBytes:      num('MAX_AUDIO_SIZE',  15 * 1024 * 1024),  // 15 MB (~10 min compressed)
    documentMaxChars:    num('MAX_DOCUMENT_CHARS', 24000),          // extracted text bound
    documentFollowChars: num('MAX_DOCUMENT_FOLLOW_CHARS', 9000),    // per follow-up injection
    ttsMaxChars:         num('MAX_TTS_CHARS', 4000),
    sttTimeoutMs:        num('STT_TIMEOUT_MS', 60000),
    ttsTimeoutMs:        num('TTS_TIMEOUT_MS', 60000),
    chatTimeoutMs:       num('CHAT_TIMEOUT_MS', 120000),
    firstTokenTimeoutMs: num('FIRST_TOKEN_TIMEOUT_MS', 45000),
  },

  /* ── Rate limiting (§20) ──────────────────────────────────── */
  rateLimits: {
    chat:     { limit: num('RL_CHAT_LIMIT', 20),    windowMs: num('RL_CHAT_WINDOW_MS', 5 * 60 * 1000) },
    upload:   { limit: num('RL_UPLOAD_LIMIT', 12),  windowMs: num('RL_UPLOAD_WINDOW_MS', 5 * 60 * 1000) },
    stt:      { limit: num('RL_STT_LIMIT', 20),     windowMs: num('RL_STT_WINDOW_MS', 5 * 60 * 1000) },
    tts:      { limit: num('RL_TTS_LIMIT', 30),     windowMs: num('RL_TTS_WINDOW_MS', 5 * 60 * 1000) },
  },

  /* ── Supported types (server-side truth — §19) ────────────── */
  imageExts:  ['.jpg', '.jpeg', '.png', '.gif', '.webp'],
  documentExts: ['.pdf', '.txt', '.md', '.csv', '.json', '.docx', '.doc',
                 '.py', '.js', '.ts', '.html', '.css', '.xml', '.yaml', '.yml'],
  audioExts:  ['.mp3', '.wav', '.m4a', '.ogg', '.webm', '.flac', '.mp4', '.aac'],
}

/* Image mime → ext map used when sniffing content type */
config.imageMimes = {
  'image/jpeg': '.jpg', 'image/png': '.png', 'image/gif': '.gif', 'image/webp': '.webp',
}

module.exports = config
