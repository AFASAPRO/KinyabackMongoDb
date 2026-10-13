/**
 * KinyaBot Agent V1.2 — Hardened ZIP Extraction (§9)
 * ─────────────────────────────────────────────────────────────
 * Safely extracts a USER-UPLOADED project archive into an isolated
 * task workspace. This module never executes anything — extraction
 * only writes files.
 *
 * Hardening (all limits configurable through agent uploads config):
 *   • Zip-slip / path traversal — every entry name is normalized and
 *     containment-checked BEFORE writing; entries with '..', absolute
 *     paths, drive letters or backslash tricks are rejected.
 *   • Symlink escape — symlink/pointer entries are SKIPPED entirely
 *     (never recreated); written files must stay regular files.
 *   • ZIP bombs — cumulative decompressed size cap + per-file cap +
 *     a compression-ratio ceiling (stored uncompressed > 100:1 is a
 *     classic bomb signature).
 *   • File-count bombs — hard cap on entries.
 *   • Malformed archives — detected by yauzl-level errors + a strict
 *     ZIP magic-byte pre-check.
 *   • No execution — nothing extracted is ever executed implicitly;
 *     scripts in the archive are inert data until the Agent (under
 *     the command-safety policy) chooses to run something.
 *   • Secrets — well-known secret files (.env*) are NEVER extracted;
 *     they are skipped and REPORTED so the Agent cannot leak them
 *     into a preview or a download.
 */
const fs = require('fs')
const fsp = fs.promises
const path = require('path')
const crypto = require('crypto')

const ZIP_MAGIC = Buffer.from([0x50, 0x4b, 0x03, 0x04])

/** Files that must never be extracted from a user archive. */
const DENIED_NAME_PATTERNS = [
  /^\.env(\..*)?$/i,          // dotenv secrets at any depth
  /(^|\/)\.env(\..*)?$/i,
  /^id_rsa\b/i, /^id_ed25519\b/i, /^\.npmrc$/i, /^\.pypirc$/i,
  /^\.aws\/credentials$/i, /^\.ssh\//i,
  /^credentials\.json$/i, /^service[-_]?account.*\.json$/i,
  /\.pem$/i, /\.key$/i,
]

function isDeniedEntry(name) {
  const base = name.split('/').pop()
  return DENIED_NAME_PATTERNS.some(re => re.test(base) || re.test(name))
}

/**
 * Validate + extract.
 * @param {object} p
 * @param {string} p.zipPath      absolute path of the uploaded archive
 * @param {string} p.destDir      absolute destination directory (the task workspace)
 * @param {object} p.limits       { maxEntries, maxTotalBytes, maxFileBytes, maxRatio }
 * @returns {Promise<{files:number, bytes:number, skipped:{secrets:string[], symlinks:string[]}, rootDir:string|null}>}
 * @throws Error with .code when validation fails (userSafe messages)
 */
async function extractZipSafely({ zipPath, destDir, limits = {} }) {
  const maxEntries = limits.maxEntries || 3000
  const maxTotalBytes = limits.maxTotalBytes || 150 * 1024 * 1024
  const maxFileBytes = limits.maxFileBytes || 30 * 1024 * 1024
  const maxRatio = limits.maxRatio || 100

  // 1. Magic-byte pre-check (rejects non-zip payloads early).
  const fh = await fsp.open(zipPath, 'r').catch(() => null)
  if (!fh) { const e = new Error('The uploaded archive could not be read.'); e.code = 'ZIP_READ_FAILED'; e.userSafe = true; throw e }
  const magic = Buffer.alloc(4)
  await fh.read(magic, 0, 4, 0)
  await fh.close()
  if (!magic.equals(ZIP_MAGIC)) {
    const e = new Error('That file is not a valid ZIP archive.'); e.code = 'ZIP_INVALID'; e.userSafe = true; throw e
  }

  const yauzl = require('yauzl')
  const entries = await readEntries(yauzl, zipPath)

  if (entries.length > maxEntries) {
    const e = new Error(`The archive contains too many files (${entries.length} — limit ${maxEntries}).`); e.code = 'ZIP_TOO_MANY_FILES'; e.userSafe = true; throw e
  }
  if (entries.some(en => isDeniedEntry(en.fileName))) {
    // Continue but skip — never fail the whole upload over secrets;
    // they are reported so the UI can warn honestly.
  }

  await fsp.mkdir(destDir, { recursive: true })

  const skipped = { secrets: [], symlinks: [], dirs: 0 }
  let files = 0, bytes = 0
  const writtenDirs = new Set()

  return new Promise((resolve, reject) => {
    yauzl.open(zipPath, { lazyEntries: true, autoClose: true }, (err, zip) => {
      if (err || !zip) return reject(mapZipError(err))
      zip.readEntry()
      zip.on('error', (e) => reject(mapZipError(e)))
      zip.on('entry', (entry) => {
        const name = String(entry.fileName || '')
        if (name.endsWith('/')) { // directory marker
          skipped.dirs += 1
          return zip.readEntry()
        }
        // Symlink / pointer entries are skipped, never recreated.
        const mode = (entry.externalFileAttributes >>> 16) & 0o170000
        if (mode === 0o120000) { skipped.symlinks.push(name); return zip.readEntry() }
        if (isDeniedEntry(name)) { skipped.secrets.push(name); return zip.readEntry() }

        // Path hardening: normalize, containment-check against dest.
        const rel = name.replace(/\\/g, '/')
        if (rel.includes('\0') || /^[a-zA-Z]:/.test(rel) || rel.startsWith('/') || rel.split('/').includes('..')) {
          return reject(fail('ZIP_PATH_TRAVERSAL', `The archive contains an unsafe path ("${name.slice(0, 80)}") and was rejected.`))
        }
        if (entry.uncompressedSize > maxFileBytes) {
          return reject(fail('ZIP_FILE_TOO_LARGE', `A file in the archive ("${rel.slice(0, 80)}") exceeds the ${Math.round(maxFileBytes / 1048576)} MB per-file limit.`))
        }
        if (entry.uncompressedSize > 0 && entry.compressedSize > 0 &&
            entry.uncompressedSize / entry.compressedSize > maxRatio) {
          return reject(fail('ZIP_BOMB_RATIO', `A file in the archive ("${rel.slice(0, 80)}") has a suspicious compression ratio and the archive was rejected.`))
        }
        bytes += entry.uncompressedSize
        if (bytes > maxTotalBytes) {
          return reject(fail('ZIP_TOO_LARGE', `The archive decompresses beyond the ${Math.round(maxTotalBytes / 1048576)} MB limit.`))
        }

        const abs = path.resolve(destDir, rel)
        if (abs !== destDir && !abs.startsWith(destDir + path.sep)) {
          return reject(fail('ZIP_PATH_TRAVERSAL', 'The archive contains an unsafe path and was rejected.'))
        }

        // Materialize parent dirs (tracked to bound mkdir calls).
        const parent = path.dirname(abs)
        if (!writtenDirs.has(parent)) {
          try { fs.mkdirSync(parent, { recursive: true }) } catch {}
          writtenDirs.add(parent)
        }

        zip.openReadStream(entry, (rerr, rs) => {
          if (rerr || !rs) return reject(mapZipError(rerr))
          const ws = fs.createWriteStream(abs, { flags: 'wx' })
          let hash = null
          rs.pipe(ws)
          ws.on('error', () => reject(fail('ZIP_WRITE_FAILED', 'The project could not be extracted.')))
          ws.on('finish', () => {
            files += 1
            hash = null
            zip.readEntry()
          })
        })
      })
      zip.on('end', async () => {
        try {
          // Post-pass: verify no symlink escaped in (defense in depth).
          await assertNoSymlinks(destDir)
          const rootDir = await detectSingleRoot(destDir)
          resolve({ files, bytes, skipped, rootDir })
        } catch (e) { reject(e) }
      })
    })
  })
}

/** Walk destDir and fail if ANY symlink is present (defense in depth). */
async function assertNoSymlinks(dir) {
  const stack = [dir]
  while (stack.length) {
    const cur = stack.pop()
    let dirents = []
    try { dirents = await fsp.readdir(cur, { withFileTypes: true }) } catch { continue }
    for (const d of dirents) {
      if (d.isSymbolicLink()) {
        const e = new Error('The archive contained a symbolic link, which is not allowed.'); e.code = 'ZIP_SYMLINK'; e.userSafe = true; throw e
      }
      if (d.isDirectory()) stack.push(path.join(cur, d.name))
    }
  }
}

/** If the archive had a single wrapper folder ("myproject/…"), return it. */
async function detectSingleRoot(dir) {
  let dirents = []
  try { dirents = await fsp.readdir(dir, { withFileTypes: true }) } catch { return null }
  const visible = dirents.filter(d => !d.name.startsWith('.'))
  if (visible.length === 1 && visible[0].isDirectory()) {
    // Single top dir AND it (or a child) holds an index.html/package.json
    const name = visible[0].name
    for (const probe of ['index.html', 'package.json', path.join('public', 'index.html'), path.join('src', 'index.html')]) {
      try { await fsp.stat(path.join(dir, name, probe)); return name } catch {}
    }
  }
  return null
}

function fail(code, message) {
  const e = new Error(message || 'The archive could not be processed.')
  e.code = code; e.userSafe = true
  return e
}

/** Map raw yauzl errors to honest, user-safe extraction errors.
 *  yauzl validates entry names itself ("invalid relative path") —
 *  surface those as ZIP_PATH_TRAVERSAL so clients always get a
 *  meaningful code, never a library stack. */
function mapZipError(err) {
  const msg = String(err?.message || '')
  if (msg.includes('invalid relative path') || msg.includes('invalid characters in fileName')) {
    return fail('ZIP_PATH_TRAVERSAL', 'The archive contains an unsafe path and was rejected.')
  }
  if (msg.includes('malformed') || msg.includes('invalid') || msg.includes('end of file') || msg.includes('unexpected')) {
    return fail('ZIP_CORRUPT', 'The archive appears to be corrupted and could not be opened.')
  }
  return fail('ZIP_CORRUPT', msg || 'The archive could not be read.')
}

/** Cheap pre-scan of entry metadata (also validates central directory). */
function readEntries(yauzl, zipPath) {
  return new Promise((resolve, reject) => {
    const list = []
    yauzl.open(zipPath, { lazyEntries: true, autoClose: true }, (err, zip) => {
      if (err || !zip) return reject(mapZipError(err))
      zip.readEntry()
      zip.on('error', (e) => reject(mapZipError(e)))
      zip.on('entry', (entry) => {
        list.push({ fileName: entry.fileName, uncompressedSize: entry.uncompressedSize, compressedSize: entry.compressedSize })
        zip.readEntry()
      })
      zip.on('end', () => resolve(list))
    })
  })
}

/** Is this a zip we should even accept for upload? (magic bytes) */
async function looksLikeZip(filePath) {
  try {
    const fh = await fsp.open(filePath, 'r')
    const buf = Buffer.alloc(4)
    await fh.read(buf, 0, 4, 0)
    await fh.close()
    return buf.equals(ZIP_MAGIC)
  } catch { return false }
}

module.exports = { extractZipSafely, looksLikeZip, isDeniedEntry }
