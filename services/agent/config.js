/**
 * KinyaBot Agent V1 — Centralized Agent configuration
 * ─────────────────────────────────────────────────────────────
 * Single source of truth for every Agent runtime knob, mirroring
 * the pattern of services/ai/config.js. NOTHING in the Agent
 * stack reads process.env directly except this file.
 *
 * All limits are defensive V1 defaults (§12 Sandbox Requirements)
 * and can be tuned through environment variables without code
 * changes. Secrets (JWT / MongoDB / admin) are deliberately NOT
 * referenced here — the Agent Execution Worker never receives them.
 */

function env(name, fallback = null) {
  const v = process.env[name]
  return v === undefined || v === null || String(v).trim() === '' ? fallback : String(v).trim()
}

function num(name, fallback) {
  const v = Number(process.env[name])
  return Number.isFinite(v) && v > 0 ? v : fallback
}

function bool(name, fallback) {
  const v = process.env[name]
  if (v === undefined || v === null || String(v).trim() === '') return fallback
  return ['1', 'true', 'yes', 'on'].includes(String(v).trim().toLowerCase())
}

const agentModel = env('GROQ_AGENT_MODEL', env('GROQ_CHAT_MODEL', env('GROQ_MODEL', 'llama-3.3-70b-versatile')))

const config = {
  /* ── Master switch — lets hosting environments without a suitable
     execution sandbox disable the Agent entirely (§39) while the
     rest of KinyaBot keeps working.                              */
  enabled: bool('AGENT_ENABLED', true),

  /* ── Execution mode (§39 deployment consideration)
     'local'    — worker forked from the API process (dev / single
                  host deployments). The ONLY mode implemented in V1.
     'external' — reserved: worker deployed as a separate service and
                  reached over a transport. The workerBridge interface
                  is transport-agnostic so this can be added without
                  touching the orchestrator or the frontend.          */
  executionMode: env('AGENT_EXECUTION_MODE', 'local'),

  /* ── Model (provider abstraction lives in agentProvider.js) ── */
  provider: env('AGENT_PROVIDER', 'groq'),
  models: {
    agent: agentModel,
    planning: env('GROQ_AGENT_PLANNING_MODEL', agentModel),
  },

  /* ── Loop bounds (§18 failure recovery — never an infinite loop) */
  loop: {
    maxSteps:            num('AGENT_MAX_STEPS', 40),        // hard cap on model iterations
    maxVerificationSteps: num('AGENT_MAX_VERIFICATION_STEPS', 8),
    maxRepairCycles:     num('AGENT_MAX_REPAIR_CYCLES', 1), // verification-failure → fix rounds
    maxToolRetries:      num('AGENT_MAX_TOOL_RETRIES', 2),  // retries per failing tool call
    retryBackoffMs:      num('AGENT_RETRY_BACKOFF_MS', 800),
    planningMaxTokens:   num('AGENT_PLANNING_MAX_TOKENS', 700),
    maxTokensPerStep:    num('AGENT_STEP_MAX_TOKENS', 2048),
    temperature:         num('AGENT_TEMPERATURE', 0.3),
  },

  /* ── Sandbox limits (§12) ────────────────────────────────── */
  limits: {
    taskTimeoutMs:        num('AGENT_TASK_TIMEOUT_MS', 15 * 60 * 1000),  // 15 min per task
    commandTimeoutMs:     num('AGENT_COMMAND_TIMEOUT_MS', 120 * 1000),   // 2 min per command
    commandMaxOutputBytes: num('AGENT_COMMAND_MAX_OUTPUT', 100 * 1024),  // 100 KB captured
    maxConcurrentCommands: num('AGENT_MAX_CONCURRENT_COMMANDS', 2),      // per task
    maxFileReadBytes:     num('AGENT_MAX_FILE_READ', 200 * 1024),        // 200 KB per read_file
    maxFileWriteBytes:    num('AGENT_MAX_FILE_WRITE', 2 * 1024 * 1024),  // 2 MB per write
    maxSearchResults:     num('AGENT_MAX_SEARCH_RESULTS', 200),
    confirmationTimeoutMs: num('AGENT_CONFIRMATION_TIMEOUT_MS', 5 * 60 * 1000), // auto-deny after 5 min
    contextCharBudget:    num('AGENT_CONTEXT_CHAR_BUDGET', 120000),      // rolling context bound
    heartbeatMs:          num('AGENT_HEARTBEAT_MS', 10 * 1000),
    stuckWorkerMs:        num('AGENT_STUCK_WORKER_MS', 90 * 1000),       // watchdog: kill silent workers
  },

  /* ── Orchestration (§29 performance) ─────────────────────── */
  orchestration: {
    maxConcurrentTasks:  num('AGENT_MAX_CONCURRENT_TASKS', 2),   // simultaneously running workers
    maxTasksPerUserPerDay: num('AGENT_TASK_DAILY_LIMIT', 30),
    workspaceIdleCleanupMin: num('AGENT_WORKSPACE_CLEANUP_MIN', 24 * 60), // delete idle workspaces after 24h
  },

  /* ── Workspaces (§11) ──────────────────────────────────────
     Each task gets its own directory; the sandbox refuses every
     path that resolves outside it. Root is RELATIVE to the
     backend directory so it works on any host.                   */
  workspaceRoot: env('AGENT_WORKSPACE_ROOT', 'agent-workspaces'),

  /* ── Preview (§24) ───────────────────────────────────────── */
  preview: {
    enabled: bool('AGENT_PREVIEW_ENABLED', true),
    portProbeTimeoutMs: num('AGENT_PREVIEW_PROBE_MS', 1500),
    tokenTtlMs:         num('AGENT_PREVIEW_TOKEN_TTL', 10 * 60 * 1000),
    // Only local/loopback hosts may be proxied (SSRF guard)
    allowedHosts: ['127.0.0.1', 'localhost', '::1'],
  },

  /* ── Permissions granted to a V1 task (§21).
     NETWORK / BROWSER are architected but intentionally NOT
     granted — tools requiring them are rejected with a clear
     error so future versions can flip them on safely.           */
  defaultPermissions: { READ: true, WRITE: true, EXECUTE: true, GIT: true, NETWORK: false, BROWSER: false },

  /* ── Rate limiting burst guard (mirrors services/rateLimiter) ── */
  rateLimits: {
    create: { limit: num('RL_AGENT_CREATE_LIMIT', 6), windowMs: num('RL_AGENT_CREATE_WINDOW_MS', 10 * 60 * 1000) },
  },
}

module.exports = config
