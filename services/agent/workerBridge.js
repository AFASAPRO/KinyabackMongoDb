/**
 * KinyaBot Agent V1 — Worker Bridge (§11, §35, §39)
 * ─────────────────────────────────────────────────────────────
 * Spawns ONE Execution Worker child process per task and relays
 * its IPC messages to the API side (persistence + Socket.IO +
 * preview registration).
 *
 * SECURITY (§12): the child env is built EXPLICITLY — it receives
 * ONLY what the worker needs (the model key + agent config). It
 * never sees JWT_SECRET, ADMIN_SECRET, MONGODB_URI, SMTP creds or
 * any other production secret.
 *
 * DEPLOYMENT (§39): this module is the "local" transport of a
 * transport-agnostic interface. A future RemoteWorkerTransport
 * implementing the same handle shape ({ send, onMessage, kill })
 * lets the SAME orchestrator talk to workers running on separate
 * sandbox infrastructure without touching routes or frontend.
 */
const { fork } = require('child_process')
const path = require('path')
const net = require('net')

const agentConfig = require('./config')

const WORKER_PATH = path.join(__dirname, 'worker.js')

/** Environment the worker child is allowed to see. */
function buildWorkerEnv() {
  const env = {
    NODE_ENV: process.env.NODE_ENV || 'production',
    PATH: '/usr/local/bin:/usr/bin:/bin:/usr/local/sbin:/usr/sbin:/sbin',
    HOME: '/tmp/kinya-agent-worker',   // scratch for the SDK, not a task workspace
    LANG: 'C.UTF-8',
    // Model access — the ONLY credential the worker receives.
    GROQ_API_KEY: process.env.GROQ_API_KEY || '',
    GROQ_AGENT_MODEL: agentConfig.models.agent,
    GROQ_AGENT_PLANNING_MODEL: agentConfig.models.planning,
    GROQ_CHAT_MODEL: process.env.GROQ_CHAT_MODEL || '',
    GROQ_MODEL: process.env.GROQ_MODEL || '',
    AGENT_PROVIDER: agentConfig.provider,
    AGENT_DEBUG: process.env.AGENT_DEBUG || '',
    AGENT_ENABLED: 'true',
    // Test-only escape hatch for the scripted provider — the provider
    // factory itself refuses it unless this OR NODE_ENV=test is set.
    KINYA_ALLOW_SCRIPTED_PROVIDER: process.env.KINYA_ALLOW_SCRIPTED_PROVIDER || '',
  }
  if (process.env.NODE_ENV === 'test') env.NODE_ENV = 'test'
  return env
}

/**
 * Verify a port is REALLY listening on loopback before it is ever
 * reported as a live preview (§24/§32 — never fake a preview).
 */
function probePort(port, timeoutMs = agentConfig.preview.portProbeTimeoutMs) {
  return new Promise((resolve) => {
    const s = net.Socket()
    let done = false
    const finish = (ok) => {
      if (done) return
      done = true
      s.destroy()
      resolve(ok)
    }
    s.setTimeout(timeoutMs, () => finish(false))
    s.once('connect', () => finish(true))
    s.once('error', () => finish(false))
    try { s.connect(port, '127.0.0.1') } catch { finish(false) }
  })
}

/**
 * Start a worker for one task.
 * @param {object} p { task, limits, onEvent(evt), onConfirmation(req),
 *                     onPortsDetected({ports}), onDone(payload) }
 * @returns handle { send(msg), kill(), pid, lastHeartbeat }
 */
function startWorker({ task, limits, onEvent, onConfirmation, onPortsDetected, onDone }) {
  const child = fork(WORKER_PATH, [], {
    env: buildWorkerEnv(),
    stdio: ['ignore', 'pipe', 'pipe', 'ipc'],
    // cwd stays the backend dir so require() resolution works
  })

  const handle = {
    pid: child.pid,
    killed: false,
    lastHeartbeat: Date.now(),
    _doneSeen: false,
    send(msg) { try { child.send(msg) } catch {} },
    kill() {
      handle.killed = true
      try { child.kill('SIGKILL') } catch {}
    },
  }

  const safeOnDone = (msg) => {
    handle._doneSeen = true
    onDone?.(msg)
  }

  // Worker stdout/err → server log only (never shown to users, §31:
  // bounded + no secrets by construction of the worker env).
  let logBuf = ''
  child.stdout?.setEncoding('utf8')
  child.stdout?.on('data', (d) => { logBuf += d; if (logBuf.length > 4000) logBuf = logBuf.slice(-2000) })
  child.stderr?.setEncoding('utf8')
  child.stderr?.on('data', (d) => { console.error(`[AgentWorker:${task.taskId}]`, String(d).slice(0, 500)) })

  child.on('message', async (msg) => {
    if (!msg || typeof msg !== 'object') return
    if (msg.type === 'event') {
      onEvent?.(msg.event)
      // Preview port detection: verify listening, then surface honestly.
      if (msg.event?.type === 'ports_detected' && Array.isArray(msg.event.data?.ports)) {
        const verified = []
        for (const port of msg.event.data.ports.slice(0, 5)) {
          if (await probePort(port)) verified.push(port)
        }
        if (verified.length) onPortsDetected?.({ ports: verified })
      }
      return
    }
    if (msg.type === 'confirmation_request') { onConfirmation?.(msg); return }
    if (msg.type === 'heartbeat') { handle.lastHeartbeat = Date.now(); return }
    if (msg.type === 'done') { safeOnDone(msg); return }
  })

  child.on('exit', (code, signal) => {
    // A crash WITHOUT a done message must be surfaced honestly.
    if (!handle.killed && !handle._doneSeen) {
      safeOnDone({
        ok: false,
        code: 'WORKER_CRASHED',
        error: `The execution worker terminated unexpectedly (exit ${code}${signal ? ` / ${signal}` : ''}).`,
        stats: {},
      })
    }
  })

  handle.send({ type: 'run', task, limits })
  return handle
}

/** Watchdog: polls a handle and calls onStuck() when it goes silent
 *  (§18 stuck detection). Returns a stop() function. */
function startWatchdog(handle, onStuck, stuckMs = agentConfig.limits.stuckWorkerMs) {
  const timer = setInterval(() => {
    if (handle.killed || handle._doneSeen) { clearInterval(timer); return }
    if (Date.now() - handle.lastHeartbeat > stuckMs) {
      clearInterval(timer)
      onStuck()
    }
  }, Math.max(5000, Math.floor(stuckMs / 3)))
  timer.unref?.()
  return () => clearInterval(timer)
}

module.exports = { startWorker, probePort, buildWorkerEnv, WORKER_PATH, startWatchdog }
