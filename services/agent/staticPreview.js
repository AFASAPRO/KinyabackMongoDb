/**
 * KinyaBot Agent V1.2 — Static Project Preview (§3)
 * ─────────────────────────────────────────────────────────────
 * Serves generated HTML/CSS/JS projects DIRECTLY from the task
 * workspace through the authenticated preview proxy — no web
 * server process, no package installation, no reliance on the
 * model remembering to start one.
 *
 * What this fixes (V1.2 §3):
 *   • Correct project root  — detects the directory that actually
 *     contains index.html (root, public/, dist/, site/, src/, … or
 *     any first-level subdir). Never assumes one layout.
 *   • Correct relative paths — assets referenced by HTML/CSS are
 *     resolved against the preview URL by the browser and served
 *     from disk as real files.
 *   • Correct MIME types     — full table for HTML/CSS/JS modules/
 *     JSON/SVG/images/fonts/media.
 *   • Correct URL resolution — every subpath maps to a real file;
 *     nothing is blindly rewritten to index.html. Query strings
 *     pass through. Directories serve their index.html.
 *
 * Security (§3.G):
 *   • Runs INSIDE the preview proxy route — after preview-token
 *     verification, task-ownership check and the same route guards.
 *   • Path resolution is containment-checked (no .., no absolute
 *     paths, no symlink escape) before any byte is read.
 *   • One task's preview can only ever touch that task's workspace.
 *   • Files are served with no-store for HTML and short immutable
 *     cache for fingerprinted assets; hidden dotfiles (.env etc.)
 *     are REFUSED — they must never be previewable.
 */
const fsp = require('fs').promises
const path = require('path')

/* ── MIME table (§3.C) ──────────────────────────────────────────── */
const MIME_TYPES = {
  '.html': 'text/html; charset=utf-8',
  '.htm':  'text/html; charset=utf-8',
  '.css':  'text/css; charset=utf-8',
  '.js':   'text/javascript; charset=utf-8',
  '.mjs':  'text/javascript; charset=utf-8',
  '.cjs':  'text/javascript; charset=utf-8',
  '.json': 'application/json; charset=utf-8',
  '.jsonl':'application/json; charset=utf-8',
  '.webmanifest': 'application/manifest+json',
  '.xml':  'application/xml; charset=utf-8',
  '.svg':  'image/svg+xml',
  '.png':  'image/png',
  '.jpg':  'image/jpeg',
  '.jpeg': 'image/jpeg',
  '.gif':  'image/gif',
  '.webp': 'image/webp',
  '.avif': 'image/avif',
  '.bmp':  'image/bmp',
  '.ico':  'image/x-icon',
  '.woff': 'font/woff',
  '.woff2':'font/woff2',
  '.ttf':  'font/ttf',
  '.otf':  'font/otf',
  '.eot':  'application/vnd.ms-fontobject',
  '.txt':  'text/plain; charset=utf-8',
  '.md':   'text/markdown; charset=utf-8',
  '.csv':  'text/csv; charset=utf-8',
  '.mp4':  'video/mp4',
  '.webm': 'video/webm',
  '.mp3':  'audio/mpeg',
  '.wav':  'audio/wav',
  '.ogg':  'audio/ogg',
  '.pdf':  'application/pdf',
  '.wasm': 'application/wasm',
  '.map':  'application/json; charset=utf-8',
}

function mimeFor(file) {
  return MIME_TYPES[path.extname(file).toLowerCase()] || 'application/octet-stream'
}

/* Directories that commonly hold the real site root inside a
 * generated or uploaded project. Ordered by convention priority. */
const COMMON_ROOT_DIRS = ['.', 'public', 'dist', 'build', 'site', 'web', 'app', 'src', 'static', 'out', '_site']

/**
 * Detect the project root for static serving (§3.A).
 * Walks COMMON_ROOT_DIRS plus one level of arbitrary subdirectories,
 * looking for an index.html. The workspace root itself wins when it
 * has index.html; otherwise the shallowest match is preferred.
 * @param {string} wsRoot absolute workspace root
 * @returns {Promise<string|null>} relative root dir ('.' or 'sub/dir') or null
 */
async function detectProjectRoot(wsRoot) {
  const hasIndex = async (rel) => {
    try {
      const st = await fsp.stat(path.join(wsRoot, rel, 'index.html'))
      return st.isFile()
    } catch { return false }
  }

  for (const d of COMMON_ROOT_DIRS) {
    if (await hasIndex(d)) return d === '.' ? '.' : d
  }
  // One more level of arbitrary directories (e.g. "my-site/",
  // "frontend/" from an uploaded archive). Dependency dirs never
  // hold the real site root — skip them explicitly.
  let entries = []
  try { entries = await fsp.readdir(wsRoot, { withFileTypes: true }) } catch { return null }
  const dirs = entries.filter(e => e.isDirectory() && !e.name.startsWith('.') && !['node_modules', 'vendor', '__pycache__', 'target'].includes(e.name))
  for (const d of dirs) {
    for (const sub of ['.', 'public', 'dist', 'build', 'site', 'src']) {
      const rel = sub === '.' ? d.name : path.join(d.name, sub)
      if (await hasIndex(rel)) return rel
    }
  }
  return null
}

/** Resolve a preview subpath to an absolute file INSIDE root.
 *  Returns null for anything that escapes, is a dotfile, or has no
 *  extension and no index (directory without index). The detected
 *  root itself is ALSO containment-checked against the workspace —
 *  defense in depth (rootRel is server-computed, never trusted). */
async function resolveSafeFile(wsRoot, rootRel, subPath) {
  // Normalize: strip query-free path, decode URI components.
  let rel = String(subPath || '')
  try { rel = decodeURIComponent(rel) } catch { return null }
  rel = rel.split('?')[0].split('#')[0]
  if (rel.includes('\0')) return null

  const base = path.resolve(wsRoot, rootRel)
  // The project root must itself live inside the workspace.
  if (base !== wsRoot && !base.startsWith(wsRoot + path.sep)) return null
  const abs = path.resolve(base, '.' + path.posix.normalize('/' + rel.replace(/\\/g, '/')))

  // Containment guard (§3.G): the file must live under the root.
  if (abs !== base && !abs.startsWith(base + path.sep)) return null

  // Symlink escape guard: every component must stay a real path
  // inside root after resolution.
  let realBase = base, realAbs = abs
  try {
    realBase = await fsp.realpath(base)
    realAbs = await fsp.realpath(abs)
  } catch { /* target may simply not exist yet — checked below */ }
  if (realAbs !== realBase && !realAbs.startsWith(realBase + path.sep)) return null

  let st = null
  try { st = await fsp.stat(abs) } catch { return null }

  if (st.isDirectory()) {
    const idx = path.join(abs, 'index.html')
    try {
      const ist = await fsp.stat(idx)
      if (ist.isFile()) return { abs: idx, dir: true }
    } catch {}
    return null
  }
  if (!st.isFile()) return null
  // Refuse dotfiles/dot-dirs (secrets, .env, .git internals — §3.G).
  const relInside = path.relative(base, abs)
  if (relInside.split(path.sep).some(seg => seg.startsWith('.') && seg !== '.')) return null
  return { abs, dir: false }
}

/**
 * Serve one static file for a preview request. Express-style.
 * @param {object} req express request (subPath in req.params[0])
 * @param {object} res express response
 * @param {string} wsRoot absolute workspace root
 * @param {string} rootRel detected project root ('.' or subdir)
 */
async function serveStatic(req, res, wsRoot, rootRel) {
  const subPath = req.params[0] || ''
  const safe = await resolveSafeFile(wsRoot, rootRel, subPath || 'index.html')
  if (!safe) {
    // Honest 404 with diagnostics (§3.H) — never a silent rewrite.
    return res.status(404).type('html').send(
      `<!doctype html><meta charset="utf-8"><title>Preview — not found</title>` +
      `<body style="font:14px/1.5 system-ui;padding:32px;color:#3f3f46;background:#fff">` +
      `<h2 style="margin:0 0 8px">404 — asset not found in preview</h2>` +
      `<p style="margin:4px 0"><code>${String(subPath).slice(0, 200) || '(root)'}</code> does not exist in this project` +
      `${rootRel && rootRel !== '.' ? ` (preview root: <code>${rootRel}</code>)` : ''}.</p>` +
      `<p style="color:#71717a;margin:8px 0 0">Check the file path in the generated HTML/CSS, then ask the Agent to fix it.</p></body>`)
  }

  const isHtml = safe.abs.endsWith('.html') || safe.abs.endsWith('.htm')
  res.setHeader('Content-Type', mimeFor(safe.abs))
  res.setHeader('Cache-Control', isHtml ? 'no-store' : 'public, max-age=60')
  if (req.method === 'HEAD') return res.end()

  // Stream from disk with a hard size ceiling (defensive).
  const st = await fsp.stat(safe.abs)
  if (st.size > 64 * 1024 * 1024) {
    return res.status(413).type('text/plain').send('This preview file is too large to serve.')
  }
  const stream = require('fs').createReadStream(safe.abs)
  stream.on('error', () => {
    if (!res.headersSent) res.status(500).end()
    else { try { res.end() } catch {} }
  })
  stream.pipe(res)
}

module.exports = { MIME_TYPES, mimeFor, detectProjectRoot, resolveSafeFile, serveStatic }
