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
 *   chatCompleteWithTools() – AGENT: native function/tool calling,
 *                         returns the raw assistant message with
 *                         tool_calls for the Agent execution loop.
 *   visionComplete()    – multimodal (text + image) completion
 *   transcribeAudio()   – speech-to-text (Whisper)
 *   synthesizeSpeech()  – text-to-speech (PlayAI TTS)
 *   summarizeText()     – internal helper used for context compression
 */
const Groq = require('groq-sdk')
const config = require('./config')

let client = null
let clientOverride = null   // test seam (never used in production paths)

function getClient() {
  if (clientOverride) return clientOverride
  if (!config.apiKey) {
    const error = new Error('GROQ_NOT_CONFIGURED')
    error.code = 'GROQ_NOT_CONFIGURED'
    throw error
  }
  if (!client) client = new Groq({ apiKey: config.apiKey, timeout: config.limits.chatTimeoutMs })
  return client
}

/** Test-only injection point so retries/normalisation are testable
    without network access. Setting it back to null restores the real
    client resolution. */
function setClientForTests(fake) {
  clientOverride = fake
  if (!fake) client = null
}

/* Normalize provider errors into coded errors the API layer can
   translate into honest, user-facing messages (§25). */
function normalizeError(err) {
  if (err?.code === 'GROQ_NOT_CONFIGURED' || err?.code === 'INVALID_CONVERSATION' || err?.code === 'EMPTY_AI_RESPONSE') return err
  /* V1.1: exhausted tool-call retries → honest, readable reason. */
  if (err?.code === 'AI_TOOL_USE_FAILED') {
    const e = new Error('The AI provider repeatedly returned malformed tool calls after several retries. Please try the task again.')
    e.code = 'AI_TOOL_USE_FAILED'; e.userSafe = true
    return e
  }
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

/* ── Tool-calling completion (Agent V1, §20) ────────────────────
   Uses the provider's NATIVE structured tool-calling (OpenAI-
   compatible `tools` + `tool_choice` on Groq). The Agent loop
   never parses natural-language command text — every tool
   request arrives as a structured tool_call object.

   V1.1 PRODUCTION FIX (reported 400 tool_use_failed):
   Groq occasionally emits a tool_call whose arguments JSON is
   malformed and rejects the whole generation with
     400 {"code":"tool_use_failed",
          "message":"Failed to parse tool call arguments as JSON",
          "failed_generation":"{\"name\":… truncated …"}
   The request itself is fine — only the sampled generation was
   bad. We therefore RETRY the identical request a bounded number
   of times (fresh sampling almost always produces valid JSON),
   and on each retry we inject a short strict-JSON reminder so the
   model converges instead of repeating the drift. Every attempt
   is logged (redacted) for observability; after the final attempt
   the coded error surfaces honestly to the caller.            */
const { normalizeAssistantMessage } = require('../agent/toolCallRepair')

const TOOL_CALL_RETRY_HINT = 'Reminder: when you call a tool, the arguments MUST be a single valid JSON object — complete, properly quoted, fully closed. Never truncate arguments.'

function isToolUseFailure(err) {
  if (err?.code === 'AI_TOOL_USE_FAILED') return true
  const status = err?.status || err?.response?.status
  const body = err?.error || err?.responseBody || err?.message || ''
  return status === 400 && /tool_use_failed|parse tool call arguments/i.test(String(typeof body === 'string' ? body : JSON.stringify(body)))
}

function withToolCallRetry({ attempts = 3, backoffMs = 600, jitter = 400 } = {}) {
  return async (attempt) => {
    let lastErr = null
    for (let i = 0; i < attempts; i++) {
      try {
        return await attempt(i, i > 0)
      } catch (err) {
        if (!isToolUseFailure(err)) throw err
        lastErr = err
        const failed = err?.failedGeneration || ''
        console.warn(`[Agent] Groq tool_use_failed (attempt ${i + 1}/${attempts}): malformed tool-call arguments${failed ? ` — failed_generation (${String(failed).length} chars)` : ''}`)
        if (i === attempts - 1) break
        await new Promise(r => setTimeout(r, backoffMs + Math.random() * jitter))
      }
    }
    throw lastErr
  }
}

async function chatCompleteWithTools({ messages, tools, toolChoice = 'auto', model, maxTokens = 2048, temperature = 0.4, signal }) {
  const { signal: timed, cleanup } = withTimeout(signal, config.limits.chatTimeoutMs, 'Agent tool-calling')
  const retry = withToolCallRetry({ attempts: Number(process.env.GROQ_TOOL_CALL_RETRIES) > 0 ? Number(process.env.GROQ_TOOL_CALL_RETRIES) : 3 })
  try {
    return await retry(async (attemptIndex, isRetry) => {
      // On retries, append the strict-JSON reminder as the last system
      // message — a bounded, targeted correction for the observed drift.
      const payloadMessages = isRetry && messages.some(m => m.role === 'tool')
        ? [...messages, { role: 'system', content: TOOL_CALL_RETRY_HINT }]
        : messages
      const payload = {
        model: model || config.models.chat,
        messages: payloadMessages,
        max_tokens: maxTokens,
        temperature,
      }
      if (tools?.length) {
        payload.tools = tools
        payload.tool_choice = toolChoice
      }
      let completion
      try {
        completion = await getClient().chat.completions.create(payload, { signal: timed })
      } catch (err) {
        // Attach the failed_generation for observability before normalize.
        const status = err?.status || err?.response?.status
        if (status === 400) {
          const bodyText = err?.error ? (typeof err.error === 'string' ? err.error : JSON.stringify(err.error)) : (err?.message || '')
          if (/tool_use_failed|parse tool call arguments/i.test(bodyText)) {
            err.code = 'AI_TOOL_USE_FAILED'
            try {
              const parsed = JSON.parse(bodyText)
              err.failedGeneration = parsed?.error?.failed_generation || null
            } catch { err.failedGeneration = null }
          }
        }
        throw err
      }
      const choice = completion.choices?.[0]
      const message = choice?.message
      if (!message) { const e = new Error('Empty AI response'); e.code = 'EMPTY_AI_RESPONSE'; throw e }
      // Defensive normalisation: arguments are always a JSON STRING that
      // parses, ids/names always present — downstream code sees one shape.
      const normalized = normalizeAssistantMessage(message)
      if (normalized.tool_calls.some(c => c._args_repaired)) {
        console.warn('[Agent] repaired malformed tool-call arguments from a 200 response (truncated/malformed JSON)')
      }
      return {
        message: normalized,
        finish_reason: choice?.finish_reason || null,
        model: completion.model || model || config.models.chat,
        tokens: completion.usage?.total_tokens || null,
      }
    })
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
  setClientForTests,
  chatComplete,
  chatCompleteStream,
  chatCompleteWithTools,
  visionComplete,
  transcribeAudio,
  synthesizeSpeech,
  normalizeError,
  DEFAULT_MODEL: config.models.chat,
}
