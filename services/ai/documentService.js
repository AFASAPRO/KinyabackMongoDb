/**
 * KinyaBot AI Core — Document Service
 * ─────────────────────────────────────────────────────────────
 * Validates and extracts text from uploaded documents (§6).
 * Security: never trusts the client — extension AND magic bytes are
 * checked server-side, size is bounded, extraction is honest: if the
 * content cannot be read, the caller receives an error instead of a
 * fabricated answer.
 */
const fs = require('fs')
const path = require('path')
const config = require('./config')

/* ── Magic-byte sniffing (never trust client metadata, §19) ──── */
function sniffKind(filePath) {
  let fd
  try {
    fd = fs.openSync(filePath, 'r')
    const buf = Buffer.alloc(8)
    fs.readSync(fd, buf, 0, 8, 0)
    const hex = buf.toString('hex')
    if (hex.startsWith('25504446')) return 'pdf'                          // %PDF
    if (hex.startsWith('504b0304')) return 'zip'                          // zip container (docx)
    if (hex.startsWith('89504e47')) return 'png'
    if (hex.startsWith('ffd8ff'))   return 'jpg'
    if (hex.startsWith('47494638')) return 'gif'
    if (hex.startsWith('52494646')) return 'riff'                         // webp/wav
    if (buf.slice(0, 4).toString('ascii') === 'RIFF') return 'riff'
    if (buf[0] === 0x1a && buf.slice(0, 4).toString('ascii').startsWith('\x1aE')) return 'ebml' // webm/mkv
    if (hex.startsWith('494433') || hex.startsWith('fffb') || hex.startsWith('fff3') || hex.startsWith('fff2')) return 'mp3'
    return 'unknown'
  } catch { return 'unknown' } finally { if (fd !== undefined) try { fs.closeSync(fd) } catch {} }
}

function extOf(name) { return path.extname(name || '').toLowerCase() }

function classify(filename, mimetype) {
  const ext = extOf(filename)
  if (config.imageExts.includes(ext) || config.imageMimes[mimetype]) return 'image'
  if (config.audioExts.includes(ext) || (mimetype || '').startsWith('audio/')) return 'audio'
  if (config.documentExts.includes(ext)) return 'document'
  return 'unknown'
}

/* Cross-check declared type against actual bytes. Throws with a
   user-safe message on mismatch/unsupported (never leaks internals). */
function validateUpload(filePath, declaredKind, originalName) {
  const ext = extOf(originalName)
  const kind = sniffKind(filePath)
  const stat = fs.statSync(filePath)

  if (declaredKind === 'image') {
    if (!config.imageExts.includes(ext)) throw coded('UNSUPPORTED_FILE', 'This image format is not supported. Use JPG, PNG, GIF or WebP.')
    if (stat.size > config.limits.imageSizeBytes) throw coded('FILE_TOO_LARGE', `That image is too large. Maximum size is ${Math.round(config.limits.imageSizeBytes / 1024 / 1024)} MB.`)
    if (!['jpg', 'png', 'gif', 'riff'].includes(kind)) throw coded('INVALID_FILE', 'That file is not a valid image.')
    return { kind: 'image', ext, size: stat.size }
  }

  if (declaredKind === 'audio') {
    if (!config.audioExts.includes(ext)) throw coded('UNSUPPORTED_FILE', 'That audio format is not supported.')
    if (stat.size > config.limits.audioSizeBytes) throw coded('FILE_TOO_LARGE', 'That recording is too long or too large.')
    // Browsers may produce containers we cannot all sniff; accept known audio magic or ogg/webm ext
    if (!['mp3', 'riff', 'ebml', 'unknown'].includes(kind) && !['.ogg', '.webm', '.m4a', '.aac', '.flac'].includes(ext))
      throw coded('INVALID_FILE', 'That file is not a valid audio recording.')
    return { kind: 'audio', ext, size: stat.size }
  }

  // document
  if (!config.documentExts.includes(ext)) throw coded('UNSUPPORTED_FILE', 'That document type is not supported. Supported: PDF, DOCX, TXT, MD, CSV, JSON and code files.')
  if (stat.size > config.limits.documentSizeBytes) throw coded('FILE_TOO_LARGE', 'That document is too large. Maximum size is 15 MB.')
  if (['.pdf', '.docx', '.doc'].includes(ext)) {
    const expected = ext === '.pdf' ? 'pdf' : 'zip'
    if (kind !== expected) throw coded('INVALID_FILE', ext === '.pdf'
      ? 'That file is not a valid PDF document.'
      : 'That file is not a valid DOCX document.')
  }
  return { kind: 'document', ext, size: stat.size }
}

function coded(code, message) { const e = new Error(message); e.code = code; e.userSafe = true; return e }

/* ── Text extraction ─────────────────────────────────────────── */

/** Extract raw text from a file path. Returns
 *  { text, pages, info } — or throws a user-safe error. */
async function extractText(filePath, originalName, mimetype) {
  const ext = extOf(originalName)
  const meta = { name: originalName, ext, pages: null }

  if (ext === '.pdf') {
    let data
    try {
      // pdf-parse debug quirk: require the library entry directly
      const pdfParse = require('pdf-parse')
      data = await pdfParse(fs.readFileSync(filePath))
    } catch {
      throw coded('DOC_PROCESS_FAILED', 'KinyaBot could not read that PDF. It may be corrupted or password-protected.')
    }
    const text = (data.text || '').replace(/\u0000/g, '').trim()
    meta.pages = data.numpages || null
    if (!text || text.length < 8) {
      throw coded('DOC_NO_TEXT', 'That PDF has no extractable text — it may be a scanned document. Try a text-based PDF.')
    }
    return { text: bound(text), pages: meta.pages, info: meta, processor: 'pdf-parse' }
  }

  if (ext === '.docx' || ext === '.doc') {
    if (ext === '.doc') throw coded('UNSUPPORTED_FILE', 'Legacy .doc is not supported. Please save as .docx, PDF or TXT.')
    let result
    try {
      const mammoth = require('mammoth')
      result = await mammoth.extractRawText({ path: filePath })
    } catch {
      throw coded('DOC_PROCESS_FAILED', 'KinyaBot could not read that DOCX document. It may be corrupted.')
    }
    const text = (result.value || '').trim()
    if (!text) throw coded('DOC_NO_TEXT', 'That document appears to be empty.')
    return { text: bound(text), pages: null, info: meta, processor: 'mammoth' }
  }

  // Plain-text families
  try {
    const raw = fs.readFileSync(filePath, 'utf8')
    // Reject binaries that snuck through (lots of NUL bytes)
    if ((raw.match(/\u0000/g) || []).length > 10) throw coded('INVALID_FILE', 'That file type cannot be read as a document.')
    const text = raw.trim()
    if (!text) throw coded('DOC_NO_TEXT', 'That document appears to be empty.')
    return { text: bound(text), pages: null, info: meta, processor: 'plain' }
  } catch (err) {
    if (err.userSafe) throw err
    throw coded('DOC_PROCESS_FAILED', 'KinyaBot could not read that document.')
  }
}

function bound(text) {
  if (text.length <= config.limits.documentMaxChars) return text
  // Keep the head (structure/TOC) and a slice of the tail (conclusions)
  const head = Math.floor(config.limits.documentMaxChars * 0.8)
  const tail = config.limits.documentMaxChars - head
  return text.slice(0, head) + '\n\n[…document truncated for length…]\n\n' + text.slice(-tail)
}

/* Page-aware slicing: when the model gets a follow-up question we
   re-inject a smaller window; "Source: <file> (N pages)" is only
   surfaced when we actually know it. */
function followContext(extracted, maxChars = config.limits.documentFollowChars) {
  const text = extracted || ''
  if (text.length <= maxChars) return text
  return text.slice(0, maxChars) + '\n[…truncated…] '
}

module.exports = { classify, validateUpload, extractText, followContext, sniffKind, coded }
