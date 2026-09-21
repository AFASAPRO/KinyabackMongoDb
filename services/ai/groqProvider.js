/**
 * KinyaBot AI Core — Groq Provider
 * ─────────────────────────────────────────────────────────────
 * The ONLY place that talks to the Groq SDK. Every capability is
 * exposed as a clean, provider-shaped function so the rest of the
 * app (Chat today, Agent tomorrow) never imports `groq-sdk`
 * directly and models can be switched purely through config.
 *
 * Capabilities:
 *   chatComplete()      – non-streaming text completion
 *   chatCompleteStream()– streaming text completion (async iterator)
 *   visionComplete()    – multimodal (text + image) completion
 *   transcribeAudio()   – speech-to-text (Whisper)
 *   synthesizeSpeech()  – text-to-speech (PlayAI TTS)
 *   summarizeText()     – internal helper used for context compression
 */
const Groq = require('groq-sdk')
const config = require('./config')

let client = null

function getClient() {
  if (!config.apiKey) {
    const error = new Error('GROQ_NOT_CONFIGURED')
    error.code = 'GROQ_NOT_CONFIGURED'
    throw error
  }
  if (!client) client = new Groq({ apiKey: config.apiKey, timeout: config.limits.chatTimeoutMs })
  return client
}

/* Normalize provider errors into coded errors the API layer can
   translate into honest, user-facing messages (§25). */
function normalizeError(err) {
  if (err?.code === 'GROQ_NOT_CONFIGURED' || err?.code === 'INVALID_CONVERSATION' || err?.code === 'EMPTY_AI_RESPONSE') return err
  const status = err?.status || err?.response?.status
  const normalized = new Error(err?.message || 'AI provider error')
  if (status === 401 || status === 403) { normalized.code = 'AI_AUTH'; normalized.status = status }
  else if (status === 404) { normalized.code = 'AI_MODEL_UNAVAILABLE'; normalized.status = status }
  else if (status === 429) { normalized.code = 'AI_RATE_LIMIT'; normalized.status = status }
  else if (err?.name === 'AbortError') { normalized.code = 'AI_TIMEOUT' }
  else normalized.code = err?.code || 'AI_PROVIDER_ERROR'
  return normalized
}

function withTimeout(signal, ms, label) {
  const controller = new AbortController()
  const timer = setTimeout(() => controller.abort(new Error(`${label} timed out`)), ms)
  if (signal) {
    if (signal.aborted) controller.abort(signal.reason)
    else signal.addEventListener('abort', () => controller.abort(signal.reason), { once: true })
  }
  return { signal: controller.signal, cleanup: () => clearTimeout(timer) }
}

/* ── Text completion ─────────────────────────────────────────── */
async function chatComplete({ messages, model, maxTokens = 2048, temperature = 0.7, signal }) {
  const { signal: timed, cleanup } = withTimeout(signal, config.limits.chatTimeoutMs, 'Chat')
  try {
    const completion = await getClient().chat.completions.create({
      model: model || config.models.chat,
      messages,
      max_tokens: maxTokens,
      temperature,
    }, { signal: timed })
    const text = completion.choices?.[0]?.message?.content?.trim()
    if (!text) { const e = new Error('Empty AI response'); e.code = 'EMPTY_AI_RESPONSE'; throw e }
    return {
      text,
      model: completion.model || model || config.models.chat,
      tokens: completion.usage?.total_tokens || null,
    }
  } catch (err) { throw normalizeError(err) } finally { cleanup() }
}

/* ── Streaming text completion ───────────────────────────────── */
async function chatCompleteStream({ messages, model, maxTokens = 2048, temperature = 0.7, signal }) {
  const { signal: timed, cleanup } = withTimeout(signal, config.limits.firstTokenTimeoutMs, 'AI connection')
  try {
    const stream = await getClient().chat.completions.create({
      model: model || config.models.chat,
      messages,
      max_tokens: maxTokens,
      temperature,
      stream: true,
      stream_options: { include_usage: true },
    }, { signal: timed })
    // The caller is responsible for consuming; timeout only guards connect.
    return {
      async * [Symbol.asyncIterator]() {
        try {
          for await (const chunk of stream) yield chunk
        } catch (err) { throw normalizeError(err) }
      },
    }
  } catch (err) { throw normalizeError(err) } finally { cleanup() }
}

/* ── Vision (image understanding) ────────────────────────────── */
async function visionComplete({ prompt, imageDataUrl, history = [], systemPrompt, maxTokens = 2048, temperature = 0.6, signal }) {
  const messages = []
  if (systemPrompt) messages.push({ role: 'system', content: systemPrompt })
  for (const m of history) {
    if (['user', 'assistant'].includes(m.role) && m.content?.trim()) {
      messages.push({ role: m.role, content: m.content.trim() })
    }
  }
  messages.push({
    role: 'user',
    content: [
      { type: 'text', text: prompt || 'Describe this image.' },
      { type: 'image_url', image_url: { url: imageDataUrl } },
    ],
  })
  const { signal: timed, cleanup } = withTimeout(signal, config.limits.chatTimeoutMs, 'Vision')
  try {
    const completion = await getClient().chat.completions.create({
      model: config.models.vision,
      messages,
      max_tokens: maxTokens,
      temperature,
    }, { signal: timed })
    const text = completion.choices?.[0]?.message?.content?.trim()
    if (!text) { const e = new Error('Empty AI response'); e.code = 'EMPTY_AI_RESPONSE'; throw e }
    return {
      text,
      model: completion.model || config.models.vision,
      tokens: completion.usage?.total_tokens || null,
    }
  } catch (err) { throw normalizeError(err) } finally { cleanup() }
}

/* ── Speech-to-text ──────────────────────────────────────────── */
async function transcribeAudio({ filePath, signal }) {
  const { signal: timed, cleanup } = withTimeout(signal, config.limits.sttTimeoutMs, 'Transcription')
  try {
    const fs = require('fs')
    const result = await getClient().audio.transcriptions.create({
      file: fs.createReadStream(filePath),
      model: config.models.stt,
      response_format: 'verbose_json',
    }, { signal: timed })
    return {
      text: (result?.text || '').trim(),
      language: result?.language || null,
      duration: result?.duration || null,
      model: config.models.stt,
    }
  } catch (err) { throw normalizeError(err) } finally { cleanup() }
}

/* ── Text-to-speech (Orpheus TTS) ──────────────────────────────
   Tries the configured voice/format first, then degrades
   gracefully: wav → mp3, and falls back to the default Orpheus
   voice when the configured voice is rejected. Every attempt is
   logged so administrators can see what the provider accepted. */
const TTS_FALLBACK_VOICE = 'tara'

async function ttsAttempt({ text, voice, format, signal }) {
  const response = await getClient().audio.speech.create({
    model: config.models.tts,
    voice,
    input: text,
    response_format: format,
  }, { signal })
  const buffer = Buffer.from(await response.arrayBuffer())
  if (!buffer.length) { const e = new Error('Empty audio'); e.code = 'TTS_EMPTY'; throw e }
  return buffer
}

async function synthesizeSpeech({ text, signal }) {
  const { signal: timed, cleanup } = withTimeout(signal, config.limits.ttsTimeoutMs, 'Speech synthesis')
  try {
    let lastErr = null
    // Attempt 1: configured voice + configured format (default wav)
    try {
      const buffer = await ttsAttempt({ text, voice: config.ttsVoice, format: config.ttsFormat, signal: timed })
      return { buffer, model: config.models.tts, voice: config.ttsVoice, format: config.ttsFormat }
    } catch (err) { lastErr = err }

    // Attempt 2: same voice, alternate container (some builds only ship mp3)
    const altFormat = config.ttsFormat === 'wav' ? 'mp3' : 'wav'
    try {
      const buffer = await ttsAttempt({ text, voice: config.ttsVoice, format: altFormat, signal: timed })
      console.warn(`[TTS] primary format "${config.ttsFormat}" rejected, "${altFormat}" succeeded`)
      return { buffer, model: config.models.tts, voice: config.ttsVoice, format: altFormat }
    } catch (err) { lastErr = err }

    // Attempt 3: default Orpheus voice (configured voice may not exist on the model)
    if (config.ttsVoice !== TTS_FALLBACK_VOICE) {
      try {
        const buffer = await ttsAttempt({ text, voice: TTS_FALLBACK_VOICE, format: config.ttsFormat, signal: timed })
        console.warn(`[TTS] voice "${config.ttsVoice}" rejected, fallback voice "${TTS_FALLBACK_VOICE}" succeeded`)
        return { buffer, model: config.models.tts, voice: TTS_FALLBACK_VOICE, format: config.ttsFormat }
      } catch (err) { lastErr = err }
    }
    throw lastErr
  } catch (err) { throw normalizeError(err) } finally { cleanup() }
}

module.exports = {
  getClient,
  chatComplete,
  chatCompleteStream,
  visionComplete,
  transcribeAudio,
  synthesizeSpeech,
  normalizeError,
  DEFAULT_MODEL: config.models.chat,
}
