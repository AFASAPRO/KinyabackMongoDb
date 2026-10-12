/**
 * KinyaBot Agent V1 — AI Provider Abstraction (§19, §20)
 * ─────────────────────────────────────────────────────────────
 * The Agent loop talks to an AgentProvider interface, never to a
 * concrete SDK. V1 ships:
 *
 *   • groq     — production. Wraps services/ai/groqProvider.js
 *                (the sanctioned single Groq integration point)
 *                and its NATIVE structured tool calling.
 *   • scripted — TEST ONLY (AGENT_PROVIDER=scripted). Deterministic
 *                responses used by the automated test suite to
 *                exercise the REAL orchestrator, REAL tools, REAL
 *                sandbox and REAL persistence without network
 *                access. It is refused outside test runs.
 *
 * Future V2+ providers (specialized coding models, other vendors)
 * implement the same two methods and are selected purely through
 * config — no loop changes:
 *
 *   interface AgentProvider {
 *     async plan({ task, detection }) -> { steps: [{ title }] }
 *     async step({ messages, tools, model, maxTokens }) -> {
 *       message: { role, content, tool_calls:[{id,name,arguments}] },
 *       finish_reason, model, tokens
 *     }
 *   }
 */

const agentConfig = require('./config')
const groqProvider = require('../ai/groqProvider')

/* ── Prompt builders (shared by every provider) ─────────────── */

const PLANNER_SYSTEM = `You are KinyaBot Agent — an autonomous software agent. You create SHORT, high-level execution plans for tasks.

Rules:
- Return ONLY a JSON object: {"steps": ["...", "...", ...]}
- 3 to 7 steps maximum. Each step is a short imperative phrase (max 8 words).
- Focus on observable milestones (inspect project, create files, run build, verify result) — NEVER on internal reasoning.
- Include a final verification step (e.g. "Verify the result").
Do not include any other text.`

const AGENT_SYSTEM = `You are KinyaBot Agent — an autonomous execution agent running inside an isolated Linux workspace with real tools.

HOW YOU WORK
- Call tools with structured tool calls. NEVER describe commands in prose instead of calling the tool.
- One tool call at a time when a call depends on previous results; you may batch independent calls when truly independent.
- Observe each tool result before deciding the next action. If a tool fails, read the error, fix the cause (wrong path, syntax error, missing file) and try a DIFFERENT approach rather than repeating the same failing call.
- Prefer SMALL targeted edits (edit_file) over rewriting files (write_file). Preserve existing content and coding conventions.
- Start every project task with detect_project.

RULES
- All paths are RELATIVE to the workspace root. Never touch files outside it.
- You MUST verify your own work: read files back, run build/test commands when they exist, and only claim success for operations that actually succeeded.
- Never fabricate output, file contents or test results. Report what the tools actually returned.
- When the task is fully complete and verified, reply with a final message (no tool call) that: (1) states what was actually done, (2) lists the commands that were run and their outcomes, (3) honestly notes anything that could not be done and why.
- If the task is impossible with the available tools, say so plainly instead of pretending.`

const VERIFICATION_SYSTEM = `You are KinyaBot Agent in VERIFICATION mode. Your ONLY job is to check whether the task was truly completed by re-running real checks (reading files, running commands). 

Rules:
- Use tools to verify: re-read key files, run build/test/preview commands that exist.
- Then reply with EXACTLY one line, either:
  VERIFIED: <one sentence summarizing the real evidence>
  or
  ISSUES: <specific, concrete problems found>`
  .trim()

/* ── Groq provider (production) ─────────────────────────────── */
const groqAgentProvider = {
  name: 'groq',
  requiresNetwork: true,

  async plan({ task, detection }) {
    const detectionBlock = detection
      ? `\nProject detection result:\n${JSON.stringify(detection).slice(0, 2500)}`
      : ''
    const { message } = await groqProvider.chatCompleteWithTools({
      messages: [
        { role: 'system', content: PLANNER_SYSTEM },
        { role: 'user', content: `Task: ${task.prompt}${detectionBlock}\n\nProduce the plan JSON now.` },
      ],
      model: agentConfig.models.planning,
      maxTokens: agentConfig.loop.planningMaxTokens,
      temperature: 0.2,
    })
    return parsePlanJson(message.content)
  },

  /* phase: 'execution' | 'verification' | 'repair' — future model
     routing can pick different models per phase through the same
     interface without touching the worker loop. */
  async step({ messages, tools, maxTokens, task, phase }) {
    return groqProvider.chatCompleteWithTools({
      messages,
      tools,
      toolChoice: 'auto',
      model: phase === 'verification' ? agentConfig.models.agent : agentConfig.models.agent,
      maxTokens: maxTokens || agentConfig.loop.maxTokensPerStep,
      temperature: phase === 'verification' ? Math.max(0, agentConfig.loop.temperature - 0.1) : agentConfig.loop.temperature,
    })
  },
}

/** Tolerant plan-JSON extraction (models sometimes wrap in fences). */
function parsePlanJson(text) {
  const raw = String(text || '').trim()
  const candidates = []
  const fence = raw.match(/```(?:json)?\s*([\s\S]*?)```/i)
  if (fence) candidates.push(fence[1])
  const braces = raw.match(/\{[\s\S]*\}/)
  if (braces) candidates.push(braces[0])
  candidates.push(raw)
  for (const c of candidates) {
    try {
      const parsed = JSON.parse(c)
      if (Array.isArray(parsed.steps)) {
        return { steps: parsed.steps.slice(0, 10).map(s => String(s).slice(0, 120)) }
      }
    } catch {}
  }
  // Honest fallback: single-step plan is better than a fabricated one.
  return { steps: ['Execute the task with tools', 'Verify the result'] }
}

/* ── Scripted provider — TEST ONLY (§37, §38) ──────────────────
   Deterministic scripts keyed by phase. Used exclusively by the
   automated test suite so the full stack (orchestrator, worker,
   sandbox, tools, persistence, events) runs for real without
   network access. Refused unless explicitly selected AND the
   process is a test run.                                        */
const { SCRIPTS, ScriptedRunner } = require('./providers/scriptedProvider')

const scriptedAgentProvider = {
  name: 'scripted',
  requiresNetwork: false,
  _runners: null,

  async plan({ task }) {
    const script = SCRIPTS[task.prompt]
    const steps = script ? script.plan : ['Inspect the workspace', 'Create the requested files', 'Verify the result']
    return { steps }
  },

  async step({ messages, task, phase = 'execution' }) {
    // One runner per (task, phase) — the worker process is
    // single-task, so cursors advance across steps within a phase.
    if (!this._runners || this._runners.taskKey !== task.prompt) {
      this._runners = { taskKey: task.prompt, execution: null, verification: null, repair: null }
    }
    if (!this._runners[phase]) this._runners[phase] = new ScriptedRunner(task.prompt, phase)
    return this._runners[phase].step(messages)
  },
}

/* ── Factory ────────────────────────────────────────────────── */
function getAgentProvider() {
  const name = agentConfig.provider
  if (name === 'groq') return groqAgentProvider
  if (name === 'scripted') {
    if (process.env.NODE_ENV !== 'test' && !process.env.KINYA_ALLOW_SCRIPTED_PROVIDER) {
      throw Object.assign(new Error('The scripted agent provider is TEST-ONLY and cannot run in production'), { code: 'PROVIDER_MISCONFIGURED' })
    }
    return scriptedAgentProvider
  }
  throw Object.assign(new Error(`Unknown agent provider: ${name}`), { code: 'PROVIDER_MISCONFIGURED' })
}

module.exports = {
  getAgentProvider,
  groqAgentProvider,
  scriptedAgentProvider,
  PLANNER_SYSTEM,
  AGENT_SYSTEM,
  VERIFICATION_SYSTEM,
  parsePlanJson,
}
