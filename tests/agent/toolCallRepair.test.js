/**
 * KinyaBot Agent V1.1 — Tool-Call JSON Repair Tests
 * Covers the production bugfix for Groq's
 *   400 tool_use_failed "Failed to parse tool call arguments as JSON"
 * and the defensive normalization of 200-response tool_calls.
 * Run: NODE_ENV=test node --test tests/agent/toolCallRepair.test.js
 */
const test = require('node:test')
const assert = require('node:assert')

const {
  repairJsonArguments,
  parseToolCallArguments,
  normalizeAssistantMessage,
} = require('../../services/agent/toolCallRepair')

/* ── repairJsonArguments ─────────────────────────────────────── */

test('valid JSON passes through unrepaired', () => {
  const r = repairJsonArguments('{"path":"src/app.js","content":"hi\\n"}')
  assert.equal(r.ok, true)
  assert.equal(r.repaired, false)
  assert.deepEqual(r.value, { path: 'src/app.js', content: 'hi\n' })
})

test('empty and null inputs yield an empty object', () => {
  assert.equal(repairJsonArguments(null).ok, true)
  assert.deepEqual(repairJsonArguments(null).value, {})
  assert.equal(repairJsonArguments('').ok, true)
  assert.deepEqual(repairJsonArguments('').value, {})
})

test('truncated JSON tail is closed (the exact production failure shape)', () => {
  // e.g. failed_generation: {"name": "git_status", "arguments": {"
  const r = repairJsonArguments('{"path": "src/ap')
  assert.equal(r.ok, true)
  assert.deepEqual(r.value, { path: 'src/ap' })
})

test('unterminated string with trailing colon gets a null placeholder', () => {
  const r = repairJsonArguments('{"path":')
  assert.equal(r.ok, true)
  assert.deepEqual(r.value, { path: null })
})

test('trailing commas are removed', () => {
  const r = repairJsonArguments('{"a": 1, "b": ["x", "y",]}')
  assert.equal(r.ok, true)
  assert.deepEqual(r.value, { a: 1, b: ['x', 'y'] })
})

test('single-quoted strings are normalized', () => {
  const r = repairJsonArguments("{'path': 'src/a.js'}")
  assert.equal(r.ok, true)
  assert.deepEqual(r.value, { path: 'src/a.js' })
})

test('unquoted bare keys are quoted', () => {
  const r = repairJsonArguments('{path: "src/a.js", depth: 3}')
  assert.equal(r.ok, true)
  assert.deepEqual(r.value, { path: 'src/a.js', depth: 3 })
})

test('smart quotes are normalized', () => {
  const r = repairJsonArguments('{\u201Cpath\u201D: \u201Csrc/a.js\u201D}')
  assert.equal(r.ok, true)
  assert.deepEqual(r.value, { path: 'src/a.js' })
})

test('nested truncation is balanced', () => {
  const r = repairJsonArguments('{"filters": {"name": "app", "depth": 2')
  assert.equal(r.ok, true)
  assert.deepEqual(r.value, { filters: { name: 'app', depth: 2 } })
})

test('repair only closes — never invents content', () => {
  const r = repairJsonArguments('{"path": "a.js"')
  assert.deepEqual(r.value, { path: 'a.js' })
  assert.equal('content' in r.value, false)
})

test('unrepairable garbage fails honestly instead of guessing', () => {
  const r = repairJsonArguments('~~~not json at all~~~')
  assert.equal(r.ok, false)
  assert.equal(r.value, null)
})

/* ── parseToolCallArguments ──────────────────────────────────── */

test('parseToolCallArguments rejects non-object JSON values', () => {
  assert.equal(parseToolCallArguments('"just a string"').ok, false)
  assert.equal(parseToolCallArguments('[1,2]').ok, false)
  assert.equal(parseToolCallArguments('42').ok, false)
})

test('parseToolCallArguments accepts pre-parsed objects', () => {
  const r = parseToolCallArguments({ path: 'a.js' })
  assert.equal(r.ok, true)
  assert.deepEqual(r.value, { path: 'a.js' })
})

/* ── normalizeAssistantMessage ───────────────────────────────── */

test('normalization repairs a malformed 200-response tool call', () => {
  const msg = {
    role: 'assistant',
    content: '',
    tool_calls: [
      { id: 'call_1', type: 'function', function: { name: 'read_file', arguments: '{"path": "src/ap' } },
    ],
  }
  const out = normalizeAssistantMessage(msg)
  assert.equal(out.tool_calls.length, 1)
  assert.equal(out.tool_calls[0].function.name, 'read_file')
  assert.deepEqual(JSON.parse(out.tool_calls[0].function.arguments), { path: 'src/ap' })
  assert.equal(out.tool_calls[0]._args_repaired, true)
})

test('normalization stringifies pre-parsed argument objects', () => {
  const msg = {
    role: 'assistant',
    content: 'thinking',
    tool_calls: [
      { id: 'call_2', function: { name: 'list_files', arguments: { path: '.', depth: 2 } } },
    ],
  }
  const out = normalizeAssistantMessage(msg)
  assert.equal(typeof out.tool_calls[0].function.arguments, 'string')
  assert.deepEqual(JSON.parse(out.tool_calls[0].function.arguments), { path: '.', depth: 2 })
})

test('normalization synthesizes missing ids deterministically', () => {
  const out = normalizeAssistantMessage({ tool_calls: [{ function: { name: 'x', arguments: '{}' } }] })
  assert.ok(out.tool_calls[0].id.startsWith('call_'))
})

test('messages without tool calls pass through untouched', () => {
  const out = normalizeAssistantMessage({ role: 'assistant', content: 'final answer' })
  assert.equal(out.content, 'final answer')
  assert.deepEqual(out.tool_calls, [])
})

/* ── Groq retry wrapper (the 400 tool_use_failed path) ────────── */

test('chatCompleteWithTools retries a tool_use_failed 400 and succeeds', async () => {
  // Simulate the Groq client failing once exactly like production, then
  // succeeding. We monkey-patch getClient via the module cache.
  const groqProvider = require('../../services/ai/groqProvider')

  let calls = 0
  const fakeClient = {
    chat: {
      completions: {
        create: async (payload) => {
          calls += 1
          if (calls === 1) {
            const body = { error: { message: 'Failed to parse tool call arguments as JSON', type: 'invalid_request_error', code: 'tool_use_failed', failed_generation: '{"name": "git_status", "arguments": {"' } }
            const err = new Error(JSON.stringify(body))
            err.status = 400
            err.error = body
            throw err
          }
          // Second attempt: valid tool call (as Groq would return).
          return {
            model: payload.model,
            usage: { total_tokens: 42 },
            choices: [{
              finish_reason: 'tool_calls',
              message: { role: 'assistant', content: '', tool_calls: [{ id: 'c1', type: 'function', function: { name: 'read_file', arguments: '{"path":"a.js"}' } }] },
            }],
          }
        },
      },
    },
  }
  groqProvider.setClientForTests(fakeClient)
  // Keep the retry budget explicit in tests.
  process.env.GROQ_TOOL_CALL_RETRIES = '3'

  try {
    const result = await groqProvider.chatCompleteWithTools({
      messages: [{ role: 'user', content: 'list the file' }],
      tools: [{ type: 'function', function: { name: 'read_file', parameters: { type: 'object', properties: {} } } }],
      model: 'test-model',
    })
    assert.equal(calls, 2, 'exactly one retry after the 400')
    assert.equal(result.message.tool_calls[0].function.name, 'read_file')
    assert.deepEqual(JSON.parse(result.message.tool_calls[0].function.arguments), { path: 'a.js' })
    assert.equal(result.tokens, 42)
  } finally {
    groqProvider.setClientForTests(null)
    delete process.env.GROQ_TOOL_CALL_RETRIES
  }
})

test('chatCompleteWithTools gives up after the retry budget and codes the error', async () => {
  const groqProvider = require('../../services/ai/groqProvider')
  let calls = 0
  const fakeClient = {
    chat: {
      completions: {
        create: async () => {
          calls += 1
          const body = { error: { message: 'Failed to parse tool call arguments as JSON', code: 'tool_use_failed' } }
          const err = new Error(JSON.stringify(body))
          err.status = 400
          err.error = body
          throw err
        },
      },
    },
  }
  groqProvider.setClientForTests(fakeClient)
  process.env.GROQ_TOOL_CALL_RETRIES = '2'

  try {
    await assert.rejects(
      () => groqProvider.chatCompleteWithTools({ messages: [{ role: 'user', content: 'x' }], tools: [{ type: 'function', function: { name: 't', parameters: {} } }] }),
      (err) => err.code === 'AI_TOOL_USE_FAILED' && err.userSafe === true // specific, honest code after budget exhaustion
    )
    assert.equal(calls, 2, 'retried exactly the configured number of times')
  } finally {
    groqProvider.setClientForTests(null)
    delete process.env.GROQ_TOOL_CALL_RETRIES
  }
})

test('non-tool-use 400 errors are NOT retried', async () => {
  const groqProvider = require('../../services/ai/groqProvider')
  let calls = 0
  const fakeClient = {
    chat: {
      completions: {
        create: async () => {
          calls += 1
          const err = new Error('model not found')
          err.status = 404
          throw err
        },
      },
    },
  }
  groqProvider.setClientForTests(fakeClient)

  try {
    await assert.rejects(
      () => groqProvider.chatCompleteWithTools({ messages: [{ role: 'user', content: 'x' }] }),
      (err) => err.code === 'AI_MODEL_UNAVAILABLE'
    )
    assert.equal(calls, 1, '404 must fail immediately without retry')
  } finally {
    groqProvider.setClientForTests(null)
  }
})
