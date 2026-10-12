/**
 * KinyaBot Agent V1 — Context Manager (§22)
 * ─────────────────────────────────────────────────────────────
 * The agent never re-sends the entire project or full history on
 * every step. This module keeps the model context within a char
 * budget by:
 *
 *   • preserving the system prompt + task + plan (always)
 *   • keeping the most recent turns verbatim
 *   • compressing OLDER tool results (head+tail + honest "…N
 *     truncated lines…" marker) before dropping them entirely
 *
 * Everything that is trimmed stays in the worker's local journal
 * (never fabricated) — only what the model SEES is bounded.
 */

const TRUNC_TOOL_RESULT_CHARS = 1200

/** Compress a tool result content string for context reuse. */
function compressToolResult(content) {
  const s = typeof content === 'string' ? content : JSON.stringify(content ?? '')
  if (s.length <= TRUNC_TOOL_RESULT_CHARS) return s
  const head = s.slice(0, TRUNC_TOOL_RESULT_CHARS * 0.65)
  const tail = s.slice(-TRUNC_TOOL_RESULT_CHARS * 0.25)
  const omitted = s.length - head.length - tail.length
  return `${head}\n… [${omitted} characters omitted for context budget] …\n${tail}`
}

/**
 * Trim a message list to a character budget.
 * Keeps: messages[0..anchorCount-1] verbatim (system + task + plan),
 * then the newest messages that fit; older middle messages are
 * compressed (tool results) then dropped from the front.
 *
 * @returns a NEW array — the input is never mutated (journal intact).
 */
function trimToBudget(messages, budgetChars, anchorCount = 3) {
  const total = messages.reduce((n, m) => n + messageChars(m), 0)
  if (total <= budgetChars) return messages.slice()

  // Pass 1: compress tool-result contents of non-anchor messages.
  let working = messages.map((m, i) =>
    i < anchorCount ? m : (m.role === 'tool' ? { ...m, content: compressToolResult(m.content) } : m)
  )
  let size = working.reduce((n, m) => n + messageChars(m), 0)
  if (size <= budgetChars) return working

  // Pass 2: drop oldest non-anchor messages (never the anchors, never
  // the final exchange the model just produced).
  const keep = working.slice(0, anchorCount)
  const rest = working.slice(anchorCount)
  // The last 4 messages are always preserved verbatim.
  const protectedTail = rest.slice(-4)
  const droppable = rest.slice(0, rest.length - protectedTail.length)

  let kept = []
  let used = keep.reduce((n, m) => n + messageChars(m), 0)
    + protectedTail.reduce((n, m) => n + messageChars(m), 0)
  for (let i = droppable.length - 1; i >= 0; i--) {
    const c = messageChars(droppable[i])
    if (used + c > budgetChars) break
    kept.unshift(droppable[i])
    used += c
  }
  // Continuity note so the model knows history was compacted.
  const dropped = droppable.length - kept.length
  if (dropped > 0) {
    keep.push({ role: 'user', content: `[context note: ${dropped} older exchange(s) were compacted to stay within the context budget — the workspace itself is unchanged]` })
  }
  return [...keep, ...kept, ...protectedTail]
}

function messageChars(m) {
  if (typeof m.content === 'string') return m.content.length + 24
  return (m.content ? JSON.stringify(m.content).length : 0) + 24
}

module.exports = { trimToBudget, compressToolResult }
