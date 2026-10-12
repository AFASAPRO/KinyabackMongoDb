/**
 * KinyaBot Agent V1 — Tool Registry & Permission System (§8, §21)
 * ─────────────────────────────────────────────────────────────
 * Every tool the model can invoke is declared ONCE here with:
 *
 *   • a clear name + description (sent to the model as a function)
 *   • a JSON schema for its arguments (validated before execution)
 *   • the permission it requires (READ/WRITE/EXECUTE/NETWORK/
 *     BROWSER/GIT) — checked against the task's granted set
 *   • its implementation, which receives a ToolContext and MUST
 *     stay inside the workspace sandbox
 *
 * The registry is intentionally declarative so V2/V3 can add
 * browser/web-research tools without touching the worker loop.
 */

const PERMISSIONS = ['READ', 'WRITE', 'EXECUTE', 'NETWORK', 'BROWSER', 'GIT']

const registry = new Map()

/**
 * Register a tool.
 * @param {object} def
 *   name         unique tool name (snake_case)
 *   description  one-paragraph description for the model
 *   parameters   JSON-schema object for arguments
 *   permission   one of PERMISSIONS
 *   risk         'low' | 'medium' | 'high' (terminal tools re-classify
 *                per-command at runtime — this is the default label)
 *   category     grouping label used by the UI/logs
 *   handler      async ({ args, ctx }) => result object
 */
function registerTool(def) {
  if (!def?.name || typeof def.name !== 'string') throw new Error('Tool name required')
  if (!PERMISSIONS.includes(def.permission)) throw new Error(`Unknown permission: ${def.permission}`)
  if (typeof def.handler !== 'function') throw new Error('Tool handler required')
  if (registry.has(def.name)) throw new Error(`Duplicate tool: ${def.name}`)
  registry.set(def.name, {
    name: def.name,
    description: def.description,
    parameters: def.parameters || { type: 'object', properties: {} },
    permission: def.permission,
    risk: def.risk || 'low',
    category: def.category || 'general',
    handler: def.handler,
  })
  return registry.get(def.name)
}

function getTool(name) { return registry.get(name) || null }

function listTools() { return [...registry.values()] }

/** OpenAI/Groq-compatible tool definitions for the model. */
function toModelTools() {
  return listTools().map(t => ({
    type: 'function',
    function: {
      name: t.name,
      description: t.description,
      parameters: t.parameters,
    },
  }))
}

/* ── Argument validation (JSON-schema subset, enough for V1) ── */
function validateArgs(schema, args) {
  if (schema?.type === 'object') {
    if (typeof args !== 'object' || args === null || Array.isArray(args)) {
      const e = new Error('Arguments must be an object'); e.code = 'TOOL_INVALID_ARGS'; throw e
    }
    for (const [key, sub] of Object.entries(schema.properties || {})) {
      const val = args[key]
      if (val === undefined || val === null) {
        if ((schema.required || []).includes(key)) {
          const e = new Error(`Missing required argument: ${key}`); e.code = 'TOOL_INVALID_ARGS'; throw e
        }
        continue
      }
      if (sub.type === 'string' && typeof val !== 'string') {
        const e = new Error(`Argument "${key}" must be a string`); e.code = 'TOOL_INVALID_ARGS'; throw e
      }
      if (sub.type === 'number' && (typeof val !== 'number' || !Number.isFinite(val))) {
        const e = new Error(`Argument "${key}" must be a number`); e.code = 'TOOL_INVALID_ARGS'; throw e
      }
      if (sub.type === 'boolean' && typeof val !== 'boolean') {
        const e = new Error(`Argument "${key}" must be a boolean`); e.code = 'TOOL_INVALID_ARGS'; throw e
      }
      if (sub.type === 'integer' && (!Number.isInteger(val))) {
        const e = new Error(`Argument "${key}" must be an integer`); e.code = 'TOOL_INVALID_ARGS'; throw e
      }
    }
    // Reject unknown keys the schema doesn't know about (strict mode keeps
    // the model honest and surfaces schema drift early).
    const known = new Set(Object.keys(schema.properties || {}))
    for (const key of Object.keys(args)) {
      if (!known.has(key)) {
        const e = new Error(`Unknown argument: ${key}`); e.code = 'TOOL_INVALID_ARGS'; throw e
      }
    }
  }
  return true
}

/**
 * Execute a tool call with full validation.
 * @param {string} name
 * @param {object} args        parsed JSON arguments from the model
 * @param {object} ctx         ToolContext {
 *                               workspace, taskId, permissions,
 *                               limits, emit(type, data), runCommand,
 *                               requireConfirmation(command, meta) }
 */
async function executeTool(name, args, ctx) {
  const tool = getTool(name)
  if (!tool) { const e = new Error(`Unknown tool: ${name}`); e.code = 'TOOL_UNKNOWN'; throw e }
  if (!ctx?.permissions?.[tool.permission]) {
    const e = new Error(`Tool "${name}" requires the ${tool.permission} permission, which this task does not have`)
    e.code = 'TOOL_PERMISSION_DENIED'; e.userSafe = true
    throw e
  }
  validateArgs(tool.parameters, args)
  return tool.handler({ args: args || {}, ctx })
}

module.exports = { registerTool, getTool, listTools, toModelTools, executeTool, validateArgs, PERMISSIONS }
