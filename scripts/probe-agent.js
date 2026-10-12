/* Reproduce the integration-environment worker failure in isolation. */
process.env.NODE_ENV = 'test'
process.env.AGENT_PROVIDER = 'scripted'
process.env.GROQ_API_KEY = 'x'

const mongoose = require('mongoose')
const express = require('express')
const http = require('http')
const { Server } = require('socket.io')

;(async () => {
  const baseUri = process.env.MONGODB_URI
  await mongoose.connect(baseUri, { dbName: 'kinyabot-agent-v1-test' })

  const { User, Chat, Message, AgentTask, AgentEvent, PlanConfig } = require('../models')
  const plansService = require('../services/plans')
  await plansService.ensureSeed()

  const bcrypt = require('bcryptjs')
  const jwt = require('jsonwebtoken')
  const user = await User.create({
    username: 'probeuser', email: 'probe@test.local',
    password_hash: await bcrypt.hash('x', 10), onboarded: true, email_verified: true,
  })
  const token = jwt.sign({ id: user._id.toString(), username: user.username, email: user.email }, process.env.JWT_SECRET || 'kinyabot_jwt_secret_change_me', { expiresIn: '1d' })

  const app = express()
  app.use(express.json({ limit: '5mb' }))
  app.use((req, res, next) => { req.app.set('io', io); next() })
  app.use('/api', require('../routes/agent'))
  const server = http.createServer(app)
  const io = new Server(server, { cors: { origin: '*', credentials: false } })
  const orchestrator = require('../services/agent/orchestrator')
  orchestrator.attachAgentIo(io)
  await new Promise(r => server.listen(0, r))
  const port = server.address().port

  // create task via API exactly like the test
  const res = await fetch(`http://127.0.0.1:${port}/api/agent/tasks`, {
    method: 'POST', headers: { 'Content-Type': 'application/json', Authorization: `Bearer ${token}` },
    body: JSON.stringify({ prompt: 'Create a simple HTML page about KinyaBot.' }),
  })
  const json = await res.json()
  console.log('CREATE:', res.status, json.task?.status, json.task?.task_ref)

  // poll
  for (let i = 0; i < 40; i++) {
    await new Promise(r => setTimeout(r, 500))
    const r2 = await fetch(`http://127.0.0.1:${port}/api/agent/tasks/${json.task.task_ref}`, { headers: { Authorization: `Bearer ${token}` } })
    const j2 = await r2.json()
    if (['completed', 'failed', 'cancelled'].includes(j2.task?.status)) {
      console.log('FINAL:', j2.task.status, 'error:', j2.task.error, 'stats:', JSON.stringify(j2.task.stats))
      const logs = await fetch(`http://127.0.0.1:${port}/api/agent/tasks/${json.task.task_ref}/logs`, { headers: { Authorization: `Bearer ${token}` } })
      const lj = await logs.json()
      for (const l of lj.logs.filter(l => l.type === 'task.tool.failed')) console.log('FAILED:', JSON.stringify(l.data).slice(0, 300))
      break
    }
    if (i % 8 === 0) console.log('poll', i, j2.task?.status)
  }

  await mongoose.connection.dropDatabase()
  await mongoose.disconnect()
  server.close()
  process.exit(0)
})().catch(e => { console.error('PROBE ERR', e); process.exit(1) })
