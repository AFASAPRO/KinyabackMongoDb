/**
 * KinyaBot Agent V1.1 — Tool-Call JSON Repair (production bugfix)
 * ─────────────────────────────────────────────────────────────
 * ROOT CAUSE (reported from production):
 *   Groq sometimes streams a tool_call whose `function.arguments`
 *   string is truncated / malformed JSON. Two failure surfaces:
 *
 *   1. The API itself rejects the generation and answers
 *      400 {"error":{"code":"tool_use_failed","message":"Failed to
 *      parse tool call arguments as JSON","failed_generation":…}}
 *      — the request never produces an assistant message.
 *      (Handled with a bounded RETRY in groqProvider.)
 *
 *   2. A 200 response still carries `tool_calls[].function.arguments`
 *      as a broken JSON string — e.g. `{"path": "src/a` with the
 *      closing quote/brace lost to generation drift.
 *      (Handled HERE: a conservative, side-effect-free repair.)
 *
 * This module only ever WARNS and repairs syntactically — it never
 * invents keys or values that are not present in the raw text, so a
 * repaired call is still exactly what the model attempted.
 *
 * Exposed as pure functions so they are trivially unit-testable.
 */

/**
 * Best-effort repair of a JSON object literal with common LLM drift:
 *   • truncated tails            {"path": "src/ap     → close quote+brace
 *   • unterminated strings       {"cmd": "ls -la       → same
 *   • trailing commas            {"a":1,}              → {"a":1}
 *   • smart quotes               {“a”: “b”}            → {"a":"b"}
 *   • single-quoted strings      {'a': 'b'}            → {"a":"b"}
 *   • unquoted keys              {path: "x"}           → {"path":"x"}
 *   • loose whitespace/newlines (already fine for JSON.parse)
 * Returns { ok, value, repaired } — ok=false means "give up, send
 * the error back to the model so it can retry properly".
 */
function repairJsonArguments(raw) {
  if (raw == null) return { ok: true, value: {}, repaired: false }
  if (typeof raw === 'object') return { ok: true, value: raw, repaired: false } // already parsed

  let text = String(raw).trim()
  if (!text) return { ok: true, value: {}, repaired: false }

  // Fast path — valid as-is (the overwhelmingly common case).
  try { return { ok: true, value: JSON.parse(text), repaired: false } } catch {}

  /* ── Pass 1: character-level normalisation ─────────────────── */
  text = text
    .replace(/[\u201C\u201D]/g, '"')        // smart double quotes
    .replace(/\u2018\u2019/g, "'")          // smart apostrophes
    .replace(/[\u00A0\u2007\u202F]/g, ' ')  // odd spaces
    .replace(/,(\s*[}\]])/g, '$1')          // trailing commas

  try { return { ok: true, value: JSON.parse(text), repaired: true } } catch {}

  /* ── Pass 2: single-quoted strings → double-quoted ─────────── */
  const singleQuoted = text.replace(/'([^'\\]*(?:\\.[^'\\]*)*)'/g, (m, inner) => `"${inner}"`)
  try { return { ok: true, value: JSON.parse(singleQuoted), repaired: true } } catch {}

  /* ── Pass 3: unquoted bare keys → quoted ───────────────────── */
  const bareKeys = singleQuoted.replace(/([{,]\s*)([A-Za-z_$][\w$]*)(\s*:)/g, '$1"$2"$3')
  try { return { ok: true, value: JSON.parse(bareKeys), repaired: true } } catch {}

  /* ── Pass 4: truncation repair — balance quotes/braces/brackets.
     Applied to the *last* pass's text; only appends closers, never
     removes content, so the result stays faithful to the attempt. */
  let candidate = bareKeys

  // Strip a dangling half-written final token that can never parse:
  // {"path": "src/ap   or   {"path": "src/ap,
  candidate = candidate.replace(/,\s*$/, '')

  const stack = []
  let inString = false
  let escape = false
  for (const ch of candidate) {
    if (escape) { escape = false; continue }
    if (ch === '\\') { if (inString) escape = true; continue }
    if (ch === '"') { inString = !inString; continue }
    if (inString) continue
    if (ch === '{' || ch === '[') stack.push(ch)
    else if (ch === '}' || ch === ']') stack.pop()
  }
  let suffix = ''
  if (inString) suffix += '"'
  // Deep-truncation safety: a colon with no value after it means the
  // model was cut mid-pair — a null placeholder keeps it parseable.
  if (/:\s*$/.test(candidate)) candidate += 'null'
  const CLOSER = { '{': '}', '[': ']' }
  while (stack.length) suffix += CLOSER[stack.pop()] || ''
  const closed = candidate + suffix
  try { return { ok: true, value: JSON.parse(closed), repaired: true } } catch {}

  // Last resort: drop a trailing dangling fragment after the last
  // structural closer and try once more (e.g. `{"a":1} {"b":` ).
  const lastBrace = Math.max(candidate.lastIndexOf('}'), candidate.lastIndexOf(']'))
  if (lastBrace > 0) {
    const head = candidate.slice(0, lastBrace + 1)
    try { return { ok: true, value: JSON.parse(head), repaired: true } } catch {}
  }

  return { ok: false, value: null, repaired: false }
}

/**
 * Parse a tool_call's `function.arguments` with repair.
 * Never throws — the caller decides how to surface failure.
 */
function parseToolCallArguments(raw) {
  const r = repairJsonArguments(raw)
  if (r.ok && (typeof r.value !== 'object' || r.value === null || Array.isArray(r.value))) {
    return { ok: false, value: null, repaired: r.repaired }
  }
  return r
}

/**
 * Normalise one assistant message coming back from a provider:
 * guarantees `tool_calls` entries have {id, type:'function',
 * function:{name, arguments:<string>}} and that `arguments` at least
 * parses (or is repaired). Pure — returns a new object.
 */
function normalizeAssistantMessage(message) {
  const out = {
    role: 'assistant',
    content: message?.content ?? '',
    tool_calls: Array.isArray(message?.tool_calls) ? [...message.tool_calls] : [],
  }
  out.tool_calls = out.tool_calls.map((call, i) => {
    const fn = call?.function || {}
    let args = fn.arguments
    // Some providers return a pre-parsed object — stringify it back
    // so every consumer sees ONE shape (the wire format).
    if (args != null && typeof args === 'object') {
      try { args = JSON.stringify(args) } catch { args = '{}' }
    }
    const parsed = parseToolCallArguments(args)
    return {
      id: call?.id || `call_${Date.now().toString(36)}_${i}`,
      type: 'function',
      function: {
        name: String(fn.name || ''),
        arguments: parsed.ok ? JSON.stringify(parsed.value) : String(args ?? '{}'),
      },
      _args_repaired: !!parsed.repaired,
    }
  })
  return out
}

module.exports = { repairJsonArguments, parseToolCallArguments, normalizeAssistantMessage }
