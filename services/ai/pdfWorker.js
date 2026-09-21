/**
 * KinyaBot AI Core — PDF extraction worker
 * ─────────────────────────────────────────────────────────────
 * Standalone child process. MUST stay free of app dependencies
 * (especially mongoose): mongoose 8 + the pdf.js bundled inside
 * pdf-parse 1.1.1 corrupt each other's globals, so PDF parsing
 * runs here in a clean VM where mongoose is never loaded.
 *
 * Usage (fork + IPC):
 *   parent: fork(pdfWorker.js, [filePath, maxChars])
 *   worker: process.send({ ok, text, pages } | { ok:false, code, message })
 */
const fs = require('fs')

const filePath = process.argv[2]
const maxChars = Number(process.argv[3]) || 24000

function bound(text) {
  if (text.length <= maxChars) return text
  const head = Math.floor(maxChars * 0.8)
  const tail = maxChars - head
  return text.slice(0, head) + '\n\n[…document truncated for length…]\n\n' + text.slice(-tail)
}

function fail(code, message) {
  process.send({ ok: false, code, message })
  process.exit(0)
}

if (!filePath) return fail('PDF_NO_FILE', 'No file supplied to the PDF worker.')

try {
  // Resolved from the backend's own node_modules (same dir tree).
  const pdfParse = require('pdf-parse')
  pdfParse(fs.readFileSync(filePath))
    .then(data => {
      const text = (data.text || '').replace(/\u0000/g, '').trim()
      process.send({ ok: true, text: bound(text), pages: data.numpages || null })
      process.exit(0)
    })
    .catch(err => fail('PDF_PARSE_FAILED', err?.message || 'Could not parse this PDF.'))
} catch (err) {
  fail('PDF_WORKER_ERROR', err?.message || 'PDF worker failed to start.')
}
