/**
 * KinyaBot Agent V1 — Filesystem Tools (§8)
 * ─────────────────────────────────────────────────────────────
 * list_files · read_file · search_files · create_file ·
 * write_file · edit_file · delete_file
 *
 * Every path is resolved through the Workspace sandbox (§12):
 * traversal attempts, absolute escapes and symlink jumps raise
 * SANDBOX_VIOLATION and surface honestly in the task log.
 * Write tools record REAL diffs (tools/diff.js) — no change is
 * ever reported without an actual content difference.
 */
const fs = require('fs')
const fsp = fs.promises
const path = require('path')

const { registerTool } = require('./registry')
const { buildChange, toUnifiedText } = require('./diff')

const MAX_TREE_ENTRIES = 2000
const BINARY_EXT_RE = /\.(png|jpe?g|gif|webp|bmp|ico|pdf|zip|gz|tar|bz2|xz|7z|rar|exe|dll|so|dylib|class|jar|wasm|mp3|mp4|wav|ogg|webm|mov|avi|woff2?|ttf|eot|oet|pyc|node)$/i

function assertWithinSize(ctx, bytes, cap) {
  if (bytes > cap) {
    const e = new Error(`Content exceeds the sandbox limit (${cap} bytes)`)
    e.code = 'SANDBOX_LIMIT'; e.userSafe = true; throw e
  }
}

async function statType(abs) {
  const st = await fsp.lstat(abs).catch(() => null)
  if (!st) return null
  if (st.isSymbolicLink()) return 'symlink'
  return st.isDirectory() ? 'dir' : 'file'
}

/* ── list_files ─────────────────────────────────────────────── */
registerTool({
  name: 'list_files',
  description: 'List files and folders in the workspace. Returns name, type (dir/file), size and modified time for each entry. Use "." for the workspace root. Depth controls recursion (1 = current level only).',
  parameters: {
    type: 'object',
    properties: {
      path: { type: 'string', description: 'Directory path relative to the workspace root. Default "."' },
      depth: { type: 'integer', description: 'Recursion depth (1-4). Default 1.' },
    },
    required: [],
  },
  permission: 'READ',
  risk: 'low',
  category: 'filesystem',
  handler: async ({ args, ctx }) => {
    const rel = args.path || '.'
    const depth = Math.min(4, Math.max(1, Number(args.depth) || 1))
    const abs = ctx.workspace.resolve(rel)
    if (!(await statType(abs))) { const e = new Error(`No such directory: ${rel}`); e.code = 'TOOL_TARGET_MISSING'; throw e }

    const entries = []
    async function walk(dir, level, relPrefix) {
      const children = await fsp.readdir(dir, { withFileTypes: true }).catch(() => [])
      children.sort((a, b) => (a.isDirectory() === b.isDirectory() ? a.name.localeCompare(b.name) : a.isDirectory() ? -1 : 1))
      for (const c of children) {
        if (c.name === '.tmp') continue
        if (entries.length >= MAX_TREE_ENTRIES) return
        const absChild = ctx.workspace.resolve(relPrefix ? `${relPrefix}/${c.name}` : c.name)
        const type = c.isDirectory() ? 'dir' : c.isSymbolicLink() ? 'symlink' : 'file'
        let size = null, mtime = null
        if (type === 'file' || type === 'symlink') {
          const st = await fsp.lstat(absChild).catch(() => null)
          size = st?.size ?? null; mtime = st?.mtimeMs ?? null
        }
        const relPath = relPrefix ? `${relPrefix}/${c.name}` : c.name
        entries.push({ path: relPath, name: c.name, type, size, modified: mtime ? new Date(mtime).toISOString() : null })
        if (type === 'dir' && level < depth) await walk(absChild, level + 1, relPath)
      }
    }
    await walk(abs, 1, rel === '.' ? '' : rel.replace(/\/$/, ''))
    return { path: rel, depth, entries, count: entries.length }
  },
})

/* ── read_file ──────────────────────────────────────────────── */
registerTool({
  name: 'read_file',
  description: 'Read a text file from the workspace. Binary files are refused. Supports offset/limit (line numbers) for paging through large files.',
  parameters: {
    type: 'object',
    properties: {
      path: { type: 'string', description: 'File path relative to the workspace root' },
      offset: { type: 'integer', description: '1-based starting line' },
      limit: { type: 'integer', description: 'Max lines to return (default 500)' },
    },
    required: ['path'],
  },
  permission: 'READ',
  risk: 'low',
  category: 'filesystem',
  handler: async ({ args, ctx }) => {
    const abs = ctx.workspace.resolve(args.path)
    const st = await fsp.lstat(abs).catch(() => null)
    if (!st || st.isDirectory()) { const e = new Error(`No such file: ${args.path}`); e.code = 'TOOL_TARGET_MISSING'; throw e }
    if (BINARY_EXT_RE.test(abs)) {
      const e = new Error(`Refusing to read a binary file: ${args.path}`)
      e.code = 'TOOL_BINARY_FILE'; e.userSafe = true; throw e
    }
    assertWithinSize(ctx, st.size, ctx.limits.maxFileReadBytes)
    const buf = await fsp.readFile(abs)
    if (buf.includes(0)) {
      const e = new Error(`Refusing to read a binary file: ${args.path}`)
      e.code = 'TOOL_BINARY_FILE'; e.userSafe = true; throw e
    }
    const text = buf.toString('utf8')
    // A trailing newline is a terminator, not an extra line — but it
    // must survive in the returned content for byte-faithful reads.
    const hadTrailingNewline = text.endsWith('\n')
    const allLines = text.split('\n')
    if (allLines.length > 1 && allLines[allLines.length - 1] === '') allLines.pop()
    const offset = Math.max(1, Number(args.offset) || 1)
    const limit = Math.min(2000, Math.max(1, Number(args.limit) || 500))
    const slice = allLines.slice(offset - 1, offset - 1 + limit)
    const reachesEnd = offset - 1 + limit >= allLines.length
    const content = slice.join('\n') + (reachesEnd && hadTrailingNewline ? '\n' : '')
    return {
      path: args.path,
      content,
      lineStart: offset,
      totalLines: allLines.length,
      truncated: offset - 1 + limit < allLines.length,
      size: st.size,
    }
  },
})

/* ── search_files ───────────────────────────────────────────── */
registerTool({
  name: 'search_files',
  description: 'Search file CONTENTS with a literal string or regular expression across the workspace (like grep). Returns file, line number and matching line text.',
  parameters: {
    type: 'object',
    properties: {
      query: { type: 'string', description: 'Literal text or regex source to look for' },
      isRegex: { type: 'boolean', description: 'Treat the query as a JavaScript regex. Default false (literal).' },
      glob: { type: 'string', description: 'Optional simple extension filter like "*.js" or "*.vue"' },
      path: { type: 'string', description: 'Directory to search within. Default "."' },
    },
    required: ['query'],
  },
  permission: 'READ',
  risk: 'low',
  category: 'filesystem',
  handler: async ({ args, ctx }) => {
    const query = String(args.query)
    if (!query) { const e = new Error('Empty search query'); e.code = 'TOOL_INVALID_ARGS'; throw e }
    let matcher
    if (args.isRegex) {
      try { matcher = new RegExp(query, 'i') } catch { matcher = null }
    }
    const needle = matcher ? null : query.toLowerCase()
    const extFilter = args.glob ? args.glob.replace(/^\*+/, '').toLowerCase() : null
    const root = ctx.workspace.resolve(args.path || '.')
    const matches = []
    let filesScanned = 0

    async function scan(dir, relPrefix) {
      if (filesScanned > 800 || matches.length >= ctx.limits.maxSearchResults) return
      const children = await fsp.readdir(dir, { withFileTypes: true }).catch(() => [])
      for (const c of children) {
        if (matches.length >= ctx.limits.maxSearchResults) return
        if (c.name === '.tmp' || c.name === 'node_modules' || c.name === '.git') continue
        const rel = relPrefix ? `${relPrefix}/${c.name}` : c.name
        const abs = ctx.workspace.resolve(rel)
        if (c.isDirectory()) { await scan(abs, rel); continue }
        if (c.isSymbolicLink()) continue
        if (extFilter && !c.name.toLowerCase().endsWith(extFilter)) continue
        if (BINARY_EXT_RE.test(c.name)) continue
        const st = await fsp.lstat(abs).catch(() => null)
        if (!st || st.size > ctx.limits.maxFileReadBytes) continue
        filesScanned++
        const buf = await fsp.readFile(abs).catch(() => null)
        if (!buf || buf.includes(0)) continue
        const lines = buf.toString('utf8').split('\n')
        for (let i = 0; i < lines.length; i++) {
          const hit = matcher ? matcher.test(lines[i]) : lines[i].toLowerCase().includes(needle)
          if (hit) {
            matches.push({ path: rel, line: i + 1, text: lines[i].slice(0, 300) })
            if (matches.length >= ctx.limits.maxSearchResults) return
          }
        }
      }
    }
    await scan(root, args.path && args.path !== '.' ? args.path.replace(/\/$/, '') : '')
    return { query, matches, count: matches.length, truncated: matches.length >= ctx.limits.maxSearchResults, filesScanned }
  },
})

/* ── create_file ────────────────────────────────────────────── */
registerTool({
  name: 'create_file',
  description: 'Create a NEW file with the given content. Fails if the file already exists — use edit_file for targeted changes to existing files instead of rewriting them.',
  parameters: {
    type: 'object',
    properties: {
      path: { type: 'string', description: 'File path relative to the workspace root' },
      content: { type: 'string', description: 'Full file content' },
    },
    required: ['path', 'content'],
  },
  permission: 'WRITE',
  risk: 'low',
  category: 'filesystem',
  handler: async ({ args, ctx }) => {
    const abs = ctx.workspace.resolve(args.path, { forWrite: true })
    assertWithinSize(ctx, Buffer.byteLength(String(args.content)), ctx.limits.maxFileWriteBytes)
    if (await fsp.lstat(abs).catch(() => null)) {
      const e = new Error(`File already exists: ${args.path} — use edit_file or write_file`)
      e.code = 'TOOL_ALREADY_EXISTS'; e.userSafe = true; throw e
    }
    await fsp.mkdir(path.dirname(abs), { recursive: true })
    await fsp.writeFile(abs, String(args.content), 'utf8')
    const change = buildChange({ action: 'created', path: args.path, before: '', after: String(args.content) })
    if (change) ctx.emit('file_changed', { path: args.path, action: 'created', change })
    return { ok: true, path: args.path, created: true, added: change ? change.added : 0 }
  },
})

/* ── write_file ─────────────────────────────────────────────── */
registerTool({
  name: 'write_file',
  description: 'Overwrite an existing file with new content. Prefer edit_file for small targeted changes; use this only for full rewrites or config regeneration.',
  parameters: {
    type: 'object',
    properties: {
      path: { type: 'string', description: 'File path relative to the workspace root' },
      content: { type: 'string', description: 'New full file content' },
    },
    required: ['path', 'content'],
  },
  permission: 'WRITE',
  risk: 'medium',
  category: 'filesystem',
  handler: async ({ args, ctx }) => {
    const abs = ctx.workspace.resolve(args.path, { forWrite: true })
    assertWithinSize(ctx, Buffer.byteLength(String(args.content)), ctx.limits.maxFileWriteBytes)
    const before = (await fsp.readFile(abs).catch(() => null))?.toString('utf8') ?? ''
    await fsp.mkdir(path.dirname(abs), { recursive: true })
    await fsp.writeFile(abs, String(args.content), 'utf8')
    const change = buildChange({ action: before ? 'modified' : 'created', path: args.path, before, after: String(args.content) })
    if (change) ctx.emit('file_changed', { path: args.path, action: change.action, change })
    return { ok: true, path: args.path, added: change?.added ?? 0, removed: change?.removed ?? 0 }
  },
})

/* ── edit_file ──────────────────────────────────────────────── */
registerTool({
  name: 'edit_file',
  description: 'Make a small targeted edit: replace the first occurrence of "find" with "replace" inside a file. Set replaceAll to replace every occurrence. Fails (with the nearest matches listed) when "find" is not found so you can correct yourself.',
  parameters: {
    type: 'object',
    properties: {
      path: { type: 'string', description: 'File path relative to the workspace root' },
      find: { type: 'string', description: 'Exact text to find (include enough context to be unique)' },
      replace: { type: 'string', description: 'Replacement text' },
      replaceAll: { type: 'boolean', description: 'Replace every occurrence. Default false.' },
    },
    required: ['path', 'find', 'replace'],
  },
  permission: 'WRITE',
  risk: 'low',
  category: 'filesystem',
  handler: async ({ args, ctx }) => {
    const abs = ctx.workspace.resolve(args.path, { forWrite: true })
    const before = (await fsp.readFile(abs).catch(() => null))?.toString('utf8')
    if (before === undefined || before === null) {
      const e = new Error(`No such file: ${args.path}`); e.code = 'TOOL_TARGET_MISSING'; throw e
    }
    const find = String(args.find)
    if (!before.includes(find)) {
      // Honest, helpful failure: surface similar fragments so the model can retry precisely.
      const lines = before.split('\n')
      const similar = []
      for (let i = 0; i < lines.length && similar.length < 3; i++) {
        if (lines[i].includes(find.slice(0, Math.max(6, Math.floor(find.length / 3))))) {
          similar.push({ line: i + 1, text: lines[i].slice(0, 200) })
        }
      }
      const e = new Error(`Text not found in ${args.path}. ${similar.length ? `Did you mean line ${similar[0].line}: ${JSON.stringify(similar[0].text.slice(0, 120))}` : 'No similar fragment found — read the file again.'}`)
      e.code = 'TOOL_EDIT_MISS'; e.userSafe = true; e.details = { similar }
      throw e
    }
    let after
    if (args.replaceAll) {
      after = before.split(find).join(String(args.replace))
    } else {
      const idx = before.indexOf(find)
      after = before.slice(0, idx) + String(args.replace) + before.slice(idx + find.length)
    }
    await fsp.writeFile(abs, after, 'utf8')
    const change = buildChange({ action: 'modified', path: args.path, before, after })
    if (change) ctx.emit('file_changed', { path: args.path, action: 'modified', change })
    return { ok: true, path: args.path, occurrences: args.replaceAll ? before.split(find).length - 1 : 1, added: change?.added ?? 0, removed: change?.removed ?? 0 }
  },
})

/* ── delete_file ────────────────────────────────────────────── */
registerTool({
  name: 'delete_file',
  description: 'Delete a file or an empty directory inside the workspace. The deletion is recorded as a change. Directories must be empty — remove their contents first (this is deliberate: no recursive deletes from the model).',
  parameters: {
    type: 'object',
    properties: {
      path: { type: 'string', description: 'Path relative to the workspace root' },
    },
    required: ['path'],
  },
  permission: 'WRITE',
  risk: 'medium',
  category: 'filesystem',
  handler: async ({ args, ctx }) => {
    const abs = ctx.workspace.resolve(args.path)
    const st = await fsp.lstat(abs).catch(() => null)
    if (!st) { const e = new Error(`No such file: ${args.path}`); e.code = 'TOOL_TARGET_MISSING'; throw e }
    if (st.isDirectory()) {
      const kids = await fsp.readdir(abs).catch(() => ['?'])
      if (kids.length) { const e = new Error(`Directory not empty: ${args.path}`); e.code = 'TOOL_DIR_NOT_EMPTY'; e.userSafe = true; throw e }
      await fsp.rmdir(abs)
      ctx.emit('file_changed', { path: args.path, action: 'deleted', change: { action: 'deleted', path: args.path, added: 0, removed: 0, hunks: [] } })
      return { ok: true, path: args.path, deleted: true, type: 'dir' }
    }
    const before = (await fsp.readFile(abs).catch(() => '')).toString('utf8')
    await fsp.unlink(abs)
    ctx.emit('file_changed', { path: args.path, action: 'deleted', change: { action: 'deleted', path: args.path, added: 0, removed: before ? before.split('\n').length : 0, hunks: [] } })
    return { ok: true, path: args.path, deleted: true, type: 'file' }
  },
})

/* Shared export for tests + user-side file API. */
module.exports = { BINARY_EXT_RE, toUnifiedText }
