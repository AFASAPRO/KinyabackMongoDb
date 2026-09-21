/**
 * KinyaBot AI Core — Speech Services (STT + TTS facade)
 * ─────────────────────────────────────────────────────────────
 * Thin, honest wrappers used by the API layer. All provider
 * credentials stay server-side (§12/§19). Failures surface as
 * user-safe coded errors — never fabricated output.
 */
const fs = require('fs')
const provider = require('./groqProvider')
const config = require('./config')

function userSafe(code, message) { const e = new Error(message); e.code = code; e.userSafe = true; return e }

/* Speech-to-text: audio file → { text, language } */
async function transcribe(filePath) {
  if (!fs.existsSync(filePath) || fs.statSync(filePath).size === 0) {
    throw userSafe('EMPTY_RECORDING', 'The recording was empty. Please try again.')
  }
  try {
    return await provider.transcribeAudio({ filePath })
  } catch (err) {
    if (err.userSafe) throw err
    if (err.code === 'AI_AUTH') throw userSafe('STT_UNAVAILABLE', 'Speech recognition is temporarily unavailable. Please try again later.')
    if (err.code === 'AI_TIMEOUT') throw userSafe('STT_TIMEOUT', 'Transcription took too long. Try a shorter recording.')
    throw userSafe('STT_FAILED', 'KinyaBot could not transcribe that recording. Please try again.')
  }
}

/* Text-to-speech: text → WAV buffer */
async function synthesize(text) {
  const clean = (text || '').replace(/```[\s\S]*?```/g, ' Code block omitted. ').replace(/[*_#>`~|]/g, ' ').replace(/\s+/g, ' ').trim()
  if (!clean) throw userSafe('TTS_EMPTY_INPUT', 'There is nothing to read aloud.')
  if (clean.length > config.limits.ttsMaxChars) {
    throw userSafe('TTS_TOO_LONG', 'This response is too long to read aloud. Try reading it directly or regenerate a shorter answer.')
  }
  try {
    return await provider.synthesizeSpeech({ text: clean })
  } catch (err) {
    if (err.userSafe) throw err
    if (err.code === 'AI_AUTH' || err.code === 'AI_MODEL_UNAVAILABLE')
      throw userSafe('TTS_UNAVAILABLE', 'Voice output is not enabled on the AI provider yet. Ask the administrator to enable the TTS model.')
    if (err.code === 'AI_RATE_LIMIT') throw userSafe('TTS_RATE_LIMIT', 'Voice output is busy right now. Please wait a moment and try again.')
    throw userSafe('TTS_FAILED', 'KinyaBot could not generate audio for this response. Please try again.')
  }
}

module.exports = { transcribe, synthesize }
