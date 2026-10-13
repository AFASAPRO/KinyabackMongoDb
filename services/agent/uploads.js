/**
 * KinyaBot Agent V1.2 — Agent Uploads (§8, §9)
 * ─────────────────────────────────────────────────────────────
 * Authenticated, validated storage for the two Agent upload kinds:
 *
 *   • reference_image — images that guide generation (vision input)
 *   • project_zip     — an existing project archive the Agent will
 *                       modify (extracted into the TASK workspace at
 *                       task start, never executed during extraction)
 *
 * Storage layout (OUTSIDE public reach — served only through
 * ownership-checked endpoints):
 *   agent-uploads/{user_id}/{uploadId}.{ext}
 *
 * Every access path validates: authentication (route guard),
 * ownership (user_id match), type and size (here). Uploaded bytes
 * are never executable and never served publicly.
 */
const fs = require('fs')
const fsp = fs.promises
const path = require('path')
const crypto = require('crypto')
const multer = require('multer')

const { AgentUpload } = require('../../models')
const agentConfig = require('./config')

const UPLOAD_ROOT = path.resolve(process.cwd(), agentConfig.uploads?.rootDir || 'agent-uploads')

/* ── Validation tables ──────────────────────────────────────────── */
const IMAGE_TYPES = { 'image/png': 'png', 'image/jpeg': 'jpg', 'image/webp': 'webp', 'image/gif': 'gif' }
const IMAGE_MAGIC = [
  { ext: 'png',  sig: Buffer.from([0x89, 0x50, 0x4e, 0x47]) },
  { ext: 'jpg',  sig: Buffer.from([0xff, 0xd8, 0xff]) },
  { ext: 'webp', sig: Buffer.from('RIFF') },          // RIFF....WEBP
  { ext: 'gif',  sig: Buffer.from('GIF8') },
]
const ZIP_MAGIC = Buffer.from([0x50, 0x4b, 0x03, 0x04])

function limits() {
  return {
    imageMaxBytes: agentConfig.uploads?.imageMaxBytes || 6 * 1024 * 1024,
    zipMaxBytes: agentConfig.uploads?.zipMaxBytes || 60 * 1024 * 1024,
    maxReferenceImages: agentConfig.uploads?.maxReferenceImages || 4,
    maxProjectZips: agentConfig.uploads?.maxProjectZips || 1,
  }
}

/** Storage engine: per-user dir, random filename, original bytes. */
function buildMulter() {
  const storage = multer.diskStorage({
    destination: (req, _file, cb) => {
      const dir = path.join(UPLOAD_ROOT, String(req.user?.id || 'anon'))
      fs.mkdirSync(dir, { recursive: true })
      cb(null, dir)
    },
    filename: (_req, file, cb) => {
      const id = crypto.randomBytes(12).toString('hex')
      const kind = file.fieldname === 'file' ? (String(file.originalname || '').toLowerCase().endsWith('.zip') ? 'zip' : 'image') : 'bin'
      cb(null, `${id}.${kind === 'zip' ? 'zip' : 'bin'}`)
    },
  })
  const maxBytes = Math.max(limits().imageMaxBytes, limits().zipMaxBytes) * 1.05
  return multer({ storage, limits: { fileSize: Math.ceil(maxBytes), files: 1 } })
}

/** Sniff the real type from magic bytes (never trust the mime header). */
async function sniffType(absPath) {
  const fh = await fsp.open(absPath, 'r').catch(() => null)
  if (!fh) return null
  const buf = Buffer.alloc(16)
  await fh.read(buf, 0, 16, 0)
  await fh.close()
  if (buf.subarray(0, 4).equals(ZIP_MAGIC)) return { kind: 'zip', ext: 'zip' }
  for (const m of IMAGE_MAGIC) {
    if (m.ext === 'webp') {
      if (buf.subarray(0, 4).toString('ascii') === 'RIFF' && buf.subarray(8, 12).toString('ascii') === 'WEBP') return { kind: 'image', ext: 'webp' }
    } else if (buf.subarray(0, m.sig.length).equals(m.sig)) {
      return { kind: 'image', ext: m.ext }
    }
  }
  return null
}

/**
 * Validate + persist one uploaded file as an AgentUpload document.
 * The multer file has already been written to disk; we sniff, size-
 * check, and record it — or delete it and throw honestly.
 */
async function persistUpload({ req, file, kind }) {
  const lim = limits()
  const wanted = kind === 'project_zip' ? 'zip' : 'image'
  const sniffed = await sniffType(file.path)
  if (!sniffed || sniffed.kind !== wanted) {
    await fsp.rm(file.path, { force: true }).catch(() => {})
    const e = new Error(wanted === 'zip'
      ? 'That file is not a valid ZIP archive.'
      : 'Reference images must be PNG, JPEG, WebP or GIF files.')
    e.code = 'UPLOAD_INVALID_TYPE'; e.userSafe = true; e.status = 400
    throw e
  }
  const max = wanted === 'zip' ? lim.zipMaxBytes : lim.imageMaxBytes
  if (file.size > max) {
    await fsp.rm(file.path, { force: true }).catch(() => {})
    const e = new Error(`That ${wanted === 'zip' ? 'archive' : 'image'} is larger than the ${Math.round(max / 1048576)} MB limit.`)
    e.code = 'UPLOAD_TOO_LARGE'; e.userSafe = true; e.status = 413
    throw e
  }

  // Keep the extension honest (from sniffed type, not client name).
  const finalPath = `${file.path.slice(0, -(file.filename ? 0 : 0))}`
  const newName = `${path.basename(file.path, '.bin')}.${sniffed.ext}`
  const finalAbs = path.join(path.dirname(file.path), newName)
  if (finalAbs !== file.path) {
    await fsp.rename(file.path, finalAbs).catch(() => {})
  }

  const doc = await AgentUpload.create({
    user_id: req.user.id,
    kind: wanted === 'zip' ? 'project_zip' : 'reference_image',
    storage_path: path.relative(UPLOAD_ROOT, finalAbs),
    original_name: String(file.originalname || 'upload').slice(0, 180),
    size_bytes: file.size,
    mime_type: wanted === 'zip' ? 'application/zip' : (Object.entries(IMAGE_TYPES).find(([, ext]) => ext === sniffed.ext)?.[0] || 'application/octet-stream'),
  })
  return doc
}

/** Resolve an owned upload (absolute path + doc) or null. */
async function getOwnUpload(userId, uploadId) {
  const doc = await AgentUpload.findOne({ _id: uploadId, user_id: userId }).catch(() => null)
  if (!doc) return null
  const abs = path.resolve(UPLOAD_ROOT, doc.storage_path)
  // Containment guard — storage_path is server-written but verify anyway.
  if (!abs.startsWith(UPLOAD_ROOT + path.sep)) return null
  return { doc, abs }
}

/** Read a reference image as a data: URL for vision model input. */
async function readReferenceImageAsDataUrl(userId, uploadId) {
  const got = await getOwnUpload(userId, uploadId)
  if (!got || got.doc.kind !== 'reference_image') return null
  const buf = await fsp.readFile(got.abs).catch(() => null)
  if (!buf) return null
  return `data:${got.doc.mime_type};base64,${buf.toString('base64')}`
}

/** Cleanup: delete stored bytes for an upload doc. */
async function removeUploadFile(doc) {
  if (!doc?.storage_path) return
  const abs = path.resolve(UPLOAD_ROOT, doc.storage_path)
  if (!abs.startsWith(UPLOAD_ROOT + path.sep)) return
  await fsp.rm(abs, { force: true }).catch(() => {})
}

module.exports = { buildMulter, persistUpload, getOwnUpload, readReferenceImageAsDataUrl, removeUploadFile, limits, UPLOAD_ROOT, sniffType }
