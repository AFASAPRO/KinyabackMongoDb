/**
 * KinyaBot Agent V1 — Real line diff engine (§6 Changes tab)
 * ─────────────────────────────────────────────────────────────
 * Produces honest unified-diff records from actual before/after
 * file contents. No fake "changes": a change record only exists
 * when the tool layer observed real content differences.
 *
 * Implementation: classic LCS dynamic programming on lines with
 * the standard space optimisation (two rows). Fine for the file
 * sizes the sandbox permits (≤2 MB writes).
 */

function splitLines(text) {
  const src = String(text ?? '')
  const lines = src.split('\n')
  if (lines.length > 1 && lines[lines.length - 1] === '') lines.pop() // trailing newline artifact
  return lines
}

/** LCS-based line diff → array of {t:' '|'-'|'+', line} */
function diffLines(beforeText, afterText) {
  const A = splitLines(beforeText)
  const B = splitLines(afterText)

  // Guard: pathological inputs must not OOM the worker
  if (A.length * B.length > 4_000_000) {
    return coarseDiff(A, B)
  }

  // prev/next DP rows of LCS lengths
  let prev = new Uint32Array(B.length + 1)
  let cur = new Uint32Array(B.length + 1)
  const rows = []
  for (let i = A.length - 1; i >= 0; i--) {
    for (let j = B.length - 1; j >= 0; j--) {
      cur[j] = A[i] === B[j] ? prev[j + 1] + 1 : Math.max(prev[j], cur[j + 1])
    }
    rows.unshift(cur)
    prev = cur
    cur = new Uint32Array(B.length + 1)
  }

  const out = []
  let i = 0, j = 0
  while (i < A.length && j < B.length) {
    if (A[i] === B[j]) { out.push({ t: ' ', line: A[i] }); i++; j++ }
    else if (rows[i + 1] ? rows[i + 1][j] >= (rows[i][j + 1] ?? 0) : false) { out.push({ t: '-', line: A[i] }); i++ }
    else { out.push({ t: '+', line: B[j] }); j++ }
  }
  while (i < A.length) { out.push({ t: '-', line: A[i] }); i++ }
  while (j < B.length) { out.push({ t: '+', line: B[j] }); j++ }
  return out
}

/** Fallback for huge inputs: whole-file replace markers. */
function coarseDiff(A, B) {
  const out = []
  for (const line of A.slice(0, 200)) out.push({ t: '-', line })
  if (A.length > 200) out.push({ t: '-', line: `… ${A.length - 200} more removed lines` })
  for (const line of B.slice(0, 200)) out.push({ t: '+', line })
  if (B.length > 200) out.push({ t: '+', line: `… ${B.length - 200} more added lines` })
  return out
}

/** Compact the raw diff into hunk records the UI can render. */
function toHunks(diff, context = 3) {
  const hunks = []
  let idx = 0
  const aStartBase = 1, bStartBase = 1
  let aLine = aStartBase, bLine = bStartBase
  while (idx < diff.length) {
    if (diff[idx].t === ' ') { aLine++; bLine++; idx++; continue }
    const start = Math.max(0, idx - context)
    let end = idx
    while (end < diff.length) {
      // extend through change runs and small context gaps
      if (diff[end].t !== ' ') { end++; continue }
      let gap = 0
      while (end + gap < diff.length && diff[end + gap].t === ' ') gap++
      if (gap <= context * 2 && end + gap < diff.length) { end += gap; continue }
      break
    }
    const endCapped = Math.min(diff.length, end)
    const slice = diff.slice(start, endCapped)
    // recompute starting line numbers for the slice
    let a = aStartBase, b = bStartBase
    for (let k = 0; k < start; k++) {
      if (diff[k].t === ' ') { a++; b++ }
      else if (diff[k].t === '-') a++
      else b++
    }
    hunks.push({
      aStart: a, bStart: b,
      lines: slice.map(d => ({ ...d })),
    })
    // advance counters through consumed region
    for (let k = start; k < endCapped; k++) {
      if (diff[k].t === ' ') { aLine++; bLine++ }
      else if (diff[k].t === '-') aLine++
      else bLine++
    }
    idx = endCapped
  }
  return hunks
}

/**
 * Build a change record from real contents.
 * @returns null when nothing actually changed.
 */
function buildChange({ action, path, before, after }) {
  const diff = diffLines(before ?? '', after ?? '')
  const added = diff.filter(d => d.t === '+').length
  const removed = diff.filter(d => d.t === '-').length
  if (added === 0 && removed === 0) return null
  return {
    action,                     // 'created' | 'modified' | 'deleted'
    path,
    added,
    removed,
    hunks: toHunks(diff),
  }
}

/** Serialize a change into a unified-diff-looking text (for logs/exports). */
function toUnifiedText(change) {
  if (!change) return ''
  const lines = [`--- a/${change.path}`, `+++ b/${change.path}`]
  for (const h of change.hunks || []) {
    lines.push(`@@ -${h.aStart},${h.lines.filter(l => l.t !== '+').length} +${h.bStart},${h.lines.filter(l => l.t !== '-').length} @@`)
    for (const l of h.lines) lines.push(`${l.t}${l.line}`)
  }
  return lines.join('\n')
}

module.exports = { diffLines, toHunks, buildChange, toUnifiedText }
