/* Live-trace the orchestrator event flow with timestamps. */
process.env.NODE_ENV = 'test'
process.env.AGENT_PROVIDER = 'scripted'
process.env.GROQ_API_KEY = 'x'
process.env.AGENT_DEBUG = '1'

const mongoose = require('mongoose')

;(async () => {
  const baseUri = process.env.MONGODB_URI
  await mongoose.connect(baseUri, { dbName: 'kinyabot-agent-v1-test' })
  await mongoose.connection.dropDatabase()

  const { User } = require('../models')
  const plansService = require('../services/plans')
  await plansService.ensureSeed()

  const bcrypt = require('bcryptjs')
  const jwt = require('jsonwebtoken')
  const user = await User.create({
    username: 'traceuser', email: 'trace@test.local',
    password_hash: await bcrypt.hash('x', 10), onboarded: true, email_verified: true,
  })
  const token = jwt.sign({ id: user._id.toString(), username: user.username, email: user.email }, 'kinyabot_jwt_secret_change_me', { expiresIn: '1d' })

  // Patch the bridge startWorker to trace ALL IPC traffic
  const bridge = require('../services/agent/workerBridge')
  const origStartWorker = bridge.startWorker
  bridge.startWorker = function ({ task, limits, onEvent, onConfirmation, onPortsDetected, onDone }) {
    return origStartWorker({
      task, limits,
      onEvent: (evt) => { console.log(`[T+${Date.now() % 100000}] EVT ${evt.type} ${JSON.stringify(evt.data).slice(0, 100)}`); onEvent(evt) },
      onConfirmation: (r) => { console.log('[IPC] CONFIRMATION', JSON.stringify(r).slice(0, 120)); onConfirmation(r) },
      onPortsDetected: (r) => { console.log('[IPC] PORTS', JSON.stringify(r)); onPortsDetected(r) },
      onDone: (m) => { console.log(`[T+${Date.now() % 100000}] DONE ok=${m.ok} stats=${JSON.stringify(m.stats)} err=${m.error || ''}`); onDone(m) },
    })
  }

  const orchestrator = require('../services/agent/orchestrator')
  // trace recordEvent
  const events = require('../services/agent/events')

  const taskDoc = await require('../models').AgentTask.create({
    user_id: user._id, task_ref: require('crypto').randomUUID(),
    title: 'trace', prompt: 'Create a simple HTML page about KinyaBot.',
    status: 'queued', permissions: { READ: true, WRITE: true, EXECUTE: true, GIT: true, NETWORK: false, BROWSER: false },
  })
  taskDoc.workspace_id = taskDoc._id.toString()
  await taskDoc.save()

  console.log('=== STARTING TASK', taskDoc._id.toString(), '===')
  const started = orchestrator.startOrQueueTask(taskDoc)
  console.log('startOrQueueTask →', started)

  await new Promise(r => setTimeout(r, 15000))
  const fresh = await require('../models').AgentTask.findById(taskDoc._id)
  console.log('=== FINAL STATUS:', fresh.status, 'error:', fresh.error, 'stats:', JSON.stringify(fresh.stats))
  console.log('=== FILES:', (() => { try { return require('fs').readdirSync(`agent-workspaces/${taskDoc._id.toString()}`).join(',') } catch (e) { return 'ERR ' + e.message } })())

  await mongoose.connection.dropDatabase()
  await mongoose.disconnect()
  process.exit(0)
})().catch(e => { console.error('TRACE ERR', e); process.exit(1) })
