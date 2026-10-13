/**
 * KinyaBot Agent V1 — Agent API (§5–§7, §17, §24, §25, §26)
 * ─────────────────────────────────────────────────────────────
 * Mounted at /api/agent in app.js. Every route is authGuard-
 * protected (same JWT as the rest of KinyaBot) and entitlement
 * is resolved SERVER-SIDE through plansService — never from the
 * request body.
 *
 *   GET  /api/agent/config                     capabilities + entitlement
 *   POST /api/agent/tasks                     create + start a task
 *   GET  /api/agent/tasks                     list the user's tasks
 *   GET  /api/agent/tasks/:idOrRef            task detail (restore §25)
 *   GET  /api/agent/tasks/:idOrRef/events     event timeline / catch-up
 *   POST /api/agent/tasks/:idOrRef/stop       stop / cancel (§17)
 *   POST /api/agent/tasks/:idOrRef/confirm    approve a high-risk command
 *   GET  /api/agent/tasks/:idOrRef/files      workspace file tree
 *   GET  /api/agent/tasks/:idOrRef/file       read one workspace file
 *   POST /api/agent/tasks/:idOrRef/file       user creates a file
 *   PUT  /api/agent/tasks/:idOrRef/file       user edits a file
 *   DELETE /api/agent/tasks/:idOrRef/file     user deletes a file
 *   GET  /api/agent/tasks/:idOrRef/changes    real diff records
 *   GET  /api/agent/tasks/:idOrRef/logs       structured execution logs
 *   GET  /api/agent/tasks/:idOrRef/download   workspace as streamed .zip (V1.1 §8)
 *   GET  /api/agent/tasks/:idOrRef/preview/*  live preview proxy (§24)
 *
 * NO FAKE DATA (§32): everything returned comes from real DB
 * documents, real workspace files, or a real listening port.
 */
const express = require('express')
const mongoose = require('mongoose')
const crypto = require('crypto')
const http = require('http')
const path = require('path')
const fs = require('fs')
const fsp = require('fs').promises

const { AgentTask, AgentEvent, Chat, Message, AgentUpload } = require('../models')
const authGuard = require('../services/authGuard')
const plansService = require('../services/plans')
const usageService = require('../services/usage')
const rateLimiter = require('../services/rateLimiter')
const { logActivity } = require('../services/activity')
const agentConfig = require('../services/agent/config')
const orchestrator = require('../services/agent/orchestrator')
const { listEvents } = require('../services/agent/events')
const { Workspace, buildCommandEnv, signPreviewToken, verifyPreviewToken } = require('../services/agent/sandbox')
const registry = require('../services/agent/tools/registry')
const bridge = require('../services/agent/workerBridge')
const uploadsService = require('../services/agent/uploads')
const { extractZipSafely } = require('../services/agent/zipExtract')
const staticPreview = require('../services/agent/staticPreview')
const appSettings = require('../services/settings')
require('../services/agent/tools/filesystem')
require('../services/agent/tools/terminal')
require('../services/agent/tools/project').registerAll()
require('../services/agent/tools/websearch')   // V1.2 §10 — real web research tool
/* V1.1 (§11): Git tools removed from the Agent-facing registry. Git commands
   remain reachable through run_command with full command-safety classification. */

const router = express.Router()
const userOnly = [authGuard]

const JWT_SECRET = () => process.env.JWT_SECRET || 'kinyabot_jwt_secret_change_me'

/* ── helpers ────────────────────────────────────────────────── */
function fmtTask(doc) {
  if (!doc) return null
  const o = doc.toObject ? doc.toObject({ virtuals: false }) : { ...doc }
  o.id = o._id?.toString()
  delete o._id; delete o.__v
  for (const k of ['user_id', 'conversation_id']) {
    if (o[k] instanceof mongoose.Types.ObjectId) o[k] = o[k]?.toString?.() || null
  }
  return o
}

async function findOwnTask(req, res) {
  const key = String(req.params.idOrRef || '')
  const isObjectId = /^[a-f0-9]{24}$/i.test(key)
  const q = isObjectId
    ? { _id: key, user_id: req.user.id }
    : { task_ref: key, user_id: req.user.id }
  const doc = await AgentTask.findOne(q).catch(() => null)
  if (!doc) {
    res.status(404).json({ error: 'Agent task not found.' })
    return null
  }
  return doc
}

async function agentEntitled(req, res) {
  const { UserPlan } = require('../models')
  const planDoc = await plansService.getUserPlanDoc(req.user.id).catch(() => null)
  const plan = planDoc?.plan || 'free'
  if (!(await plansService.canUseFeature(plan, 'agentAccess'))) {
    res.status(403).json({ error: 'Agent mode is not available on your plan.', code: 'FEATURE_LOCKED', feature: 'agentAccess' })
    return false
  }
  return true
}

/* V1.2 §14.C: effective runtime switches — env boot defaults merged
   with the Superadmin's live settings (admin-settings.json). The
   admin UI can disable the agent / preview / uploads without a
   redeploy; browser-side changes can NEVER bypass these. */
function runtimeAgentEnabled() {
  return agentConfig.enabled && appSettings.get().agent_enabled !== false
}
function runtimePreviewEnabled() {
  return agentConfig.preview.enabled && appSettings.get().agent_preview_enabled !== false
}
function runtimeUploadsEnabled() {
  return agentConfig.uploads.enabled && appSettings.get().agent_uploads_enabled !== false
}
function runtimeDailyLimit() {
  const v = Number(appSettings.get().agent_daily_limit)
  return Number.isFinite(v) && v > 0 ? v : agentConfig.orchestration.maxTasksPerUserPerDay
}
function runtimeWebSearchAllowed() {
  return appSettings.get().agent_websearch_policy !== 'disabled' && appSettings.get().web_search_enabled !== false
}

/* ── GET /config — capability discovery (§39 honest reporting) ── */
router.get('/agent/config', ...userOnly, async (req, res) => {
  const entitled = await agentEntitled(req, res)
  if (!entitled) return
  const planDoc = await plansService.getUserPlanDoc(req.user.id).catch(() => null)
  const plan = planDoc?.plan || 'free'
  res.json({
    enabled: agentConfig.enabled,
    executionMode: agentConfig.executionMode,
    previewEnabled: agentConfig.preview.enabled,
    staticPreviewEnabled: agentConfig.preview.staticEnabled,
    maxConcurrentTasks: agentConfig.orchestration.maxConcurrentTasks,
    runningNow: orchestrator.runningCount(),
    taskTimeoutMs: agentConfig.limits.taskTimeoutMs,
    permissions: agentConfig.defaultPermissions,
    provider: agentConfig.provider,
    model: agentConfig.models.agent,
    /* V1.2 §8 — honest vision capability (never pretend a text-only
       model can inspect reference images). */
    vision: {
      capable: agentConfig.vision.capable,
      model: agentConfig.vision.capable ? agentConfig.models.vision : null,
    },
    /* V1.2 §8/§9 — upload capabilities + limits the UI can rely on */
    uploads: runtimeUploadsEnabled() ? {
      enabled: true,
      imageMaxBytes: agentConfig.uploads.imageMaxBytes,
      zipMaxBytes: agentConfig.uploads.zipMaxBytes,
      maxReferenceImages: agentConfig.uploads.maxReferenceImages,
    } : { enabled: false },
    /* V1.2 §10 — whether THIS user's plan may use web research
       (runtime admin policy applied server-side) */
    webSearch: (await plansService.canUseFeature(plan, 'webSearch')) && runtimeWebSearchAllowed(),
    tools: registry.listTools().map(t => ({ name: t.name, category: t.category, permission: t.permission, risk: t.risk })),
  })
})

/* ── POST /agent/tasks — create + start (§5, §6) ─────────────── */
router.post('/agent/tasks', ...userOnly, async (req, res) => {
  try {
    if (!runtimeAgentEnabled()) {
      return res.status(503).json({ error: 'Agent execution is disabled in this environment.', code: 'AGENT_DISABLED' })
    }
    if (agentConfig.executionMode !== 'local') {
      return res.status(501).json({ error: `Execution mode "${agentConfig.executionMode}" is not implemented yet in this deployment.`, code: 'AGENT_MODE_UNAVAILABLE' })
    }
    const entitled = await agentEntitled(req, res)
    if (!entitled) return

    const prompt = String(req.body?.prompt || '').trim()
    if (!prompt) return res.status(400).json({ error: 'A task prompt is required.' })
    if (prompt.length > 8000) return res.status(400).json({ error: 'The task prompt is too long (max 8000 characters).' })

    // Burst guard (mirrors the chat pipeline's rate limiter usage)
    const rl = rateLimiter.allow(`u_${req.user.id}`, 'agentCreate', { limit: agentConfig.rateLimits.create.limit, windowMs: agentConfig.rateLimits.create.windowMs })
    if (!rl.ok) return rateLimiter.tooMany(res, rl.retryAfterSec)

    // Daily task quota per user (§29 bounded resource usage — runtime limit)
    const dayStart = new Date(); dayStart.setHours(0, 0, 0, 0)
    const todayCount = await AgentTask.countDocuments({ user_id: req.user.id, created_at: { $gte: dayStart } })
    if (todayCount >= runtimeDailyLimit()) {
      return res.status(429).json({ error: `Daily agent task limit reached (${runtimeDailyLimit()}).`, code: 'AGENT_DAILY_LIMIT' })
    }

    // One live task at a time per user keeps workspaces comprehensible.
    const live = await AgentTask.findOne({ user_id: req.user.id, status: { $in: ['queued', 'planning', 'running', 'waiting_for_confirmation'] } })
    if (live) {
      return res.status(409).json({ error: 'You already have a task running. Stop it before starting another.', code: 'AGENT_TASK_ACTIVE', taskRef: live.task_ref })
    }

    /* Conversation linkage (§26): reuse /c/{conversationId} when the
       client passes one it owns; otherwise create a fresh 'agent'
       conversation so the task shows in history like any chat.    */
    let chatDoc = null
    const requestedConversation = String(req.body?.conversationId || '').trim()
    if (requestedConversation) {
      chatDoc = await Chat.findOne({
        user_id: req.user.id,
        $or: [{ conversation_id: requestedConversation }, ...(mongoose.isValidObjectId(requestedConversation) ? [{ _id: requestedConversation }] : [])],
      }).catch(() => null)
      if (!chatDoc) return res.status(404).json({ error: 'Conversation not found.' })
      if (chatDoc.mode !== 'agent') chatDoc.mode = 'agent'
      await chatDoc.save()
    } else {
      chatDoc = await Chat.create({
        user_id: req.user.id,
        title: prompt.slice(0, 60),
        mode: 'agent',
        conversation_id: crypto.randomUUID(),
      })
    }

    /* ── V1.2 §8: reference images (ownership + vision capability) ── */
    let referenceImages = []
    const requestedImageIds = Array.isArray(req.body?.referenceImageIds)
      ? req.body.referenceImageIds.map(String).slice(0, agentConfig.uploads.maxReferenceImages)
      : []
    if (requestedImageIds.length) {
      if (!runtimeUploadsEnabled()) {
        return res.status(501).json({ error: 'Agent uploads are disabled in this environment.', code: 'UPLOADS_DISABLED' })
      }
      if (!agentConfig.vision.capable) {
        return res.status(501).json({
          error: `Reference images need a vision-capable model. This deployment's agent model (${agentConfig.models.agent}) is text-only and no vision model is configured (set GROQ_AGENT_VISION_MODEL).`,
          code: 'VISION_UNAVAILABLE',
        })
      }
      for (const id of requestedImageIds) {
        if (!mongoose.isValidObjectId(id)) {
          return res.status(400).json({ error: 'Invalid reference image id.' })
        }
        const got = await uploadsService.getOwnUpload(req.user.id, id)
        if (!got || got.doc.kind !== 'reference_image') {
          return res.status(404).json({ error: 'Reference image not found. Upload it again.', code: 'UPLOAD_NOT_FOUND' })
        }
        referenceImages.push({
          upload_id: got.doc._id,
          storage_path: got.doc.storage_path,
          mime_type: got.doc.mime_type,
          original_name: got.doc.original_name,
        })
      }
    }

    /* ── V1.2 §9: existing-project ZIP — validated + extracted into
       the task's ISOLATED workspace BEFORE the worker starts. The
       user's original archive is never touched; extraction never
       executes anything; secrets are skipped and reported.      ── */
    let sourceUpload = null
    const requestedZipId = String(req.body?.projectZipId || '').trim()
    if (requestedZipId) {
      if (!runtimeUploadsEnabled()) {
        return res.status(501).json({ error: 'Agent uploads are disabled in this environment.', code: 'UPLOADS_DISABLED' })
      }
      if (!mongoose.isValidObjectId(requestedZipId)) {
        return res.status(400).json({ error: 'Invalid project archive id.' })
      }
      const got = await uploadsService.getOwnUpload(req.user.id, requestedZipId)
      if (!got || got.doc.kind !== 'project_zip') {
        return res.status(404).json({ error: 'Project archive not found. Upload it again.', code: 'UPLOAD_NOT_FOUND' })
      }
      // Extraction happens AFTER the task id exists (below): the
      // workspace is agent-workspaces/{taskId}, and extracting before
      // the worker starts means the agent's very first detect_project
      // sees the uploaded project.
      sourceUpload = { upload: got }
    }

    /* ── V1.2 §10: server-resolved entitlements for this task ── */
    const planDoc = await plansService.getUserPlanDoc(req.user.id).catch(() => null)
    const plan = planDoc?.plan || 'free'
    const entitlements = {
      webSearch: await plansService.canUseFeature(plan, 'webSearch') && runtimeWebSearchAllowed(),
      webSearchEnabled: runtimeWebSearchAllowed(),
    }

    const taskDoc = await AgentTask.create({
      user_id: req.user.id,
      conversation_id: chatDoc._id,
      task_ref: crypto.randomUUID(),
      title: prompt.slice(0, 120),
      prompt,
      status: 'queued',
      workspace_id: null,
      permissions: { ...agentConfig.defaultPermissions },
      reference_images: referenceImages,
      entitlements,
    })
    taskDoc.workspace_id = taskDoc._id.toString()
    await taskDoc.save()

    /* V1.2 §9 continued: extract the uploaded project INTO the task
       workspace (after the id exists). Failures are honest and abort
       the task BEFORE any execution begins. */
    if (sourceUpload?.upload) {
      const ws = new Workspace(taskDoc._id.toString())
      try {
        const summary = await extractZipSafely({
          zipPath: sourceUpload.upload.abs,
          destDir: ws.root,
          limits: agentConfig.uploads.extract,
        })
        taskDoc.source_upload = {
          upload_id: sourceUpload.upload.doc._id,
          name: sourceUpload.upload.doc.original_name,
          files: summary.files,
          bytes: summary.bytes,
          root_dir: summary.rootDir,
          skipped: summary.skipped,
        }
        await taskDoc.save()
        await AgentUpload.updateOne({ _id: sourceUpload.upload.doc._id }, { $set: { used: true, task_id: taskDoc._id } })
        await recordUploadEvent(taskDoc, 'task_upload_extracted', {
          name: sourceUpload.upload.doc.original_name,
          files: summary.files,
          bytes: summary.bytes,
          skippedSecrets: (summary.skipped?.secrets || []).length,
          skippedSymlinks: (summary.skipped?.symlinks || []).length,
        })
      } catch (extrErr) {
        await AgentTask.deleteOne({ _id: taskDoc._id }).catch(() => {})
        return res.status(extrErr?.userSafe ? 400 : 500).json({
          error: extrErr?.userSafe ? extrErr.message : 'The project archive could not be extracted.',
          code: extrErr?.code || 'ZIP_EXTRACT_FAILED',
        })
      }
    }
    // Mark reference images as consumed by this task too.
    if (referenceImages.length) {
      await AgentUpload.updateMany(
        { _id: { $in: referenceImages.map(r => r.upload_id) } },
        { $set: { used: true, task_id: taskDoc._id } }
      ).catch(() => {})
    }

    // The user's prompt becomes a normal Message in the conversation.
    await Message.create({
      chat_id: chatDoc._id,
      role: 'user',
      content: prompt,
      agent_task_id: taskDoc._id.toString(),
      message_type: 'text',
    })

    const started = orchestrator.startOrQueueTask(taskDoc)
    logActivity('agent_task_started', { username: req.user.username, user_id: req.user.id, meta: { taskId: taskDoc._id.toString(), queued: started === 'queued' } })

    res.status(201).json({
      task: fmtTask(taskDoc),
      conversationId: chatDoc.conversation_id,
      queued: started === 'queued',
    })
  } catch (err) {
    console.error('[Agent] create task failed:', err)
    res.status(500).json({ error: 'The agent task could not be created.' })
  }
})

/* Helper: persist + broadcast an upload lifecycle event honestly. */
async function recordUploadEvent(taskDoc, type, data) {
  try {
    const { recordEvent } = require('../services/agent/events')
    await recordEvent({ taskId: taskDoc._id.toString(), userId: taskDoc.user_id.toString(), type, data }, null)
  } catch {}
}

/* ── V1.2 §8: reference-image upload ─────────────────────────── */
router.post('/agent/uploads/reference-image', ...userOnly, async (req, res) => {
  try {
    if (!runtimeAgentEnabled()) return res.status(503).json({ error: 'Agent execution is disabled in this environment.', code: 'AGENT_DISABLED' })
    if (!runtimeUploadsEnabled()) return res.status(501).json({ error: 'Agent uploads are disabled in this environment.', code: 'UPLOADS_DISABLED' })
    if (!agentConfig.vision.capable) {
      return res.status(501).json({
        error: `Reference images need a vision-capable model. Configure GROQ_AGENT_VISION_MODEL to enable them.`,
        code: 'VISION_UNAVAILABLE',
      })
    }
    const entitled = await agentEntitled(req, res)
    if (!entitled) return
    uploadsService.buildMulter().single('file')(req, res, async (err) => {
      if (err) {
        const code = err?.code === 'LIMIT_FILE_SIZE' ? 'UPLOAD_TOO_LARGE' : 'UPLOAD_FAILED'
        return res.status(400).json({ error: code === 'UPLOAD_TOO_LARGE' ? `That image is larger than the ${Math.round(agentConfig.uploads.imageMaxBytes / 1048576)} MB limit.` : 'The image could not be uploaded.', code })
      }
      if (!req.file) return res.status(400).json({ error: 'An image file is required.' })
      try {
        const doc = await uploadsService.persistUpload({ req, file: req.file, kind: 'reference_image' })
        res.status(201).json({ upload: { id: doc._id.toString(), kind: doc.kind, name: doc.original_name, size: doc.size_bytes, mime: doc.mime_type } })
      } catch (perr) {
        res.status(perr?.status || 400).json({ error: perr?.userSafe ? perr.message : 'The image could not be validated.', code: perr?.code })
      }
    })
  } catch {
    res.status(500).json({ error: 'The upload could not be processed.' })
  }
})

/* ── V1.2 §9: existing-project ZIP upload ───────────────────── */
router.post('/agent/uploads/project-zip', ...userOnly, async (req, res) => {
  try {
    if (!runtimeAgentEnabled()) return res.status(503).json({ error: 'Agent execution is disabled in this environment.', code: 'AGENT_DISABLED' })
    if (!runtimeUploadsEnabled()) return res.status(501).json({ error: 'Agent uploads are disabled in this environment.', code: 'UPLOADS_DISABLED' })
    const entitled = await agentEntitled(req, res)
    if (!entitled) return
    uploadsService.buildMulter().single('file')(req, res, async (err) => {
      if (err) {
        const code = err?.code === 'LIMIT_FILE_SIZE' ? 'UPLOAD_TOO_LARGE' : 'UPLOAD_FAILED'
        return res.status(400).json({ error: code === 'UPLOAD_TOO_LARGE' ? `That archive is larger than the ${Math.round(agentConfig.uploads.zipMaxBytes / 1048576)} MB limit.` : 'The archive could not be uploaded.', code })
      }
      if (!req.file) return res.status(400).json({ error: 'A .zip file is required.' })
      try {
        const doc = await uploadsService.persistUpload({ req, file: req.file, kind: 'project_zip' })
        res.status(201).json({ upload: { id: doc._id.toString(), kind: doc.kind, name: doc.original_name, size: doc.size_bytes, mime: doc.mime_type } })
      } catch (perr) {
        res.status(perr?.status || 400).json({ error: perr?.userSafe ? perr.message : 'The archive could not be validated.', code: perr?.code })
      }
    })
  } catch {
    res.status(500).json({ error: 'The upload could not be processed.' })
  }
})

/* ── GET /agent/tasks — list ─────────────────────────────────── */
router.get('/agent/tasks', ...userOnly, async (req, res) => {
  try {
    const limit = Math.min(50, Math.max(1, Number(req.query.limit) || 20))
    const status = req.query.status
    const q = { user_id: req.user.id }
    if (status) q.status = String(status)
    const docs = await AgentTask.find(q).sort({ created_at: -1 }).limit(limit).lean()
    res.json({ tasks: docs.map(d => ({ ...fmtTask(d) })) })
  } catch {
    res.status(500).json({ error: 'Tasks could not be loaded.' })
  }
})

/* ── GET /agent/tasks/:idOrRef — detail (§25 restore) ────────── */
router.get('/agent/tasks/:idOrRef', ...userOnly, async (req, res) => {
  try {
    const doc = await findOwnTask(req, res)
    if (!doc) return
    const events = await listEvents(doc._id.toString(), { after: 0, limit: 120 })
    const chat = doc.conversation_id ? await Chat.findById(doc.conversation_id).catch(() => null) : null
    res.json({
      task: fmtTask(doc),
      events,
      conversationId: chat?.conversation_id || null,
      running: orchestrator.isTaskRunning(doc._id.toString()),
    })
  } catch {
    res.status(500).json({ error: 'The task could not be loaded.' })
  }
})

/* ── GET /agent/tasks/:idOrRef/events — catch-up (§30) ───────── */
router.get('/agent/tasks/:idOrRef/events', ...userOnly, async (req, res) => {
  try {
    const doc = await findOwnTask(req, res)
    if (!doc) return
    const after = Number(req.query.after) || 0
    const events = await listEvents(doc._id.toString(), { after, limit: Number(req.query.limit) || 500 })
    res.json({ events, running: orchestrator.isTaskRunning(doc._id.toString()), status: doc.status })
  } catch {
    res.status(500).json({ error: 'Events could not be loaded.' })
  }
})

/* ── POST /agent/tasks/:idOrRef/stop — §17 task controls ─────── */
router.post('/agent/tasks/:idOrRef/stop', ...userOnly, async (req, res) => {
  try {
    const doc = await findOwnTask(req, res)
    if (!doc) return
    const result = await orchestrator.cancelTask(doc._id.toString(), String(req.body?.reason || 'Task stopped by the user'))
    logActivity('agent_task_stopped', { username: req.user.username, user_id: req.user.id, meta: { taskId: doc._id.toString() } })
    res.json(result)
  } catch (err) {
    res.status(500).json({ error: 'The task could not be stopped.' })
  }
})

/* ── POST /agent/tasks/:idOrRef/confirm — §13 confirmation ───── */
router.post('/agent/tasks/:idOrRef/confirm', ...userOnly, async (req, res) => {
  try {
    const doc = await findOwnTask(req, res)
    if (!doc) return
    const confirmationId = String(req.body?.confirmationId || '')
    const approved = req.body?.approved === true
    if (!confirmationId) return res.status(400).json({ error: 'confirmationId is required.' })
    const result = await orchestrator.resolveConfirmation(doc._id.toString(), confirmationId, approved)
    if (!result.ok) return res.status(result.error === 'Task is not running' ? 409 : 404).json({ error: result.error })
    logActivity('agent_confirmation', { username: req.user.username, user_id: req.user.id, meta: { taskId: doc._id.toString(), approved, confirmationId } })
    res.json({ ok: true })
  } catch {
    res.status(500).json({ error: 'The confirmation could not be delivered.' })
  }
})

/* ── Workspace files (§6 Files tab) ──────────────────────────── */
async function requireWorkspace(req, res, doc) {
  const ws = new Workspace(doc._id.toString())
  const exists = await ws.exists('.').catch(() => false)
  if (!exists) {
    res.status(410).json({ error: 'This task has no workspace on disk anymore (idle workspaces are cleaned up automatically).', code: 'WORKSPACE_GONE' })
    return null
  }
  return ws
}

router.get('/agent/tasks/:idOrRef/files', ...userOnly, async (req, res) => {
  try {
    const doc = await findOwnTask(req, res)
    if (!doc) return
    const ws = await requireWorkspace(req, res, doc)
    if (!ws) return
    const result = await registry.executeTool('list_files', { path: '.', depth: Number(req.query.depth) || 4 }, {
      workspace: ws, taskId: doc._id.toString(), permissions: { READ: true }, limits: agentConfig.limits,
      emit: () => {}, runCommand: () => { throw new Error('not available') }, requireConfirmation: async () => false,
    })
    res.json({ entries: result.entries, count: result.count })
  } catch (err) {
    if (err.code === 'SANDBOX_VIOLATION') return res.status(400).json({ error: err.message })
    res.status(500).json({ error: 'The file tree could not be loaded.' })
  }
})

router.get('/agent/tasks/:idOrRef/file', ...userOnly, async (req, res) => {
  try {
    const doc = await findOwnTask(req, res)
    if (!doc) return
    const ws = await requireWorkspace(req, res, doc)
    if (!ws) return
    const result = await registry.executeTool('read_file', { path: String(req.query.path || '') }, {
      workspace: ws, taskId: doc._id.toString(), permissions: { READ: true }, limits: agentConfig.limits,
      emit: () => {}, runCommand: () => { throw new Error('not available') }, requireConfirmation: async () => false,
    })
    res.json(result)
  } catch (err) {
    if (err.code === 'SANDBOX_VIOLATION') return res.status(400).json({ error: err.message })
    if (err.code === 'TOOL_BINARY_FILE') return res.status(415).json({ error: err.message })
    if (err.code === 'TOOL_TARGET_MISSING') return res.status(404).json({ error: 'File not found.' })
    res.status(500).json({ error: 'The file could not be read.' })
  }
})

/* User-side file operations (§6 Files tab requires create/edit/delete). */
router.post('/agent/tasks/:idOrRef/file', ...userOnly, async (req, res) => {
  try {
    const doc = await findOwnTask(req, res)
    if (!doc) return
    const ws = await requireWorkspace(req, res, doc)
    if (!ws) return
    const result = await registry.executeTool('create_file', { path: String(req.body?.path || ''), content: String(req.body?.content ?? '') }, {
      workspace: ws, taskId: doc._id.toString(), permissions: { WRITE: true }, limits: agentConfig.limits,
      emit: () => {}, runCommand: () => { throw new Error('not available') }, requireConfirmation: async () => false,
    })
    res.status(201).json(result)
  } catch (err) {
    if (err.code === 'SANDBOX_VIOLATION' || err.code === 'TOOL_ALREADY_EXISTS' || err.code === 'SANDBOX_LIMIT') return res.status(400).json({ error: err.message })
    res.status(500).json({ error: 'The file could not be created.' })
  }
})

router.put('/agent/tasks/:idOrRef/file', ...userOnly, async (req, res) => {
  try {
    const doc = await findOwnTask(req, res)
    if (!doc) return
    const ws = await requireWorkspace(req, res, doc)
    if (!ws) return
    const result = await registry.executeTool('write_file', { path: String(req.body?.path || ''), content: String(req.body?.content ?? '') }, {
      workspace: ws, taskId: doc._id.toString(), permissions: { WRITE: true }, limits: agentConfig.limits,
      emit: () => {}, runCommand: () => { throw new Error('not available') }, requireConfirmation: async () => false,
    })
    res.json(result)
  } catch (err) {
    if (err.code === 'SANDBOX_VIOLATION' || err.code === 'SANDBOX_LIMIT') return res.status(400).json({ error: err.message })
    res.status(500).json({ error: 'The file could not be saved.' })
  }
})

router.delete('/agent/tasks/:idOrRef/file', ...userOnly, async (req, res) => {
  try {
    const doc = await findOwnTask(req, res)
    if (!doc) return
    const ws = await requireWorkspace(req, res, doc)
    if (!ws) return
    const result = await registry.executeTool('delete_file', { path: String(req.query.path || '') }, {
      workspace: ws, taskId: doc._id.toString(), permissions: { WRITE: true }, limits: agentConfig.limits,
      emit: () => {}, runCommand: () => { throw new Error('not available') }, requireConfirmation: async () => false,
    })
    res.json(result)
  } catch (err) {
    if (err.code === 'SANDBOX_VIOLATION' || err.code === 'TOOL_DIR_NOT_EMPTY') return res.status(400).json({ error: err.message })
    if (err.code === 'TOOL_TARGET_MISSING') return res.status(404).json({ error: 'File not found.' })
    res.status(500).json({ error: 'The file could not be deleted.' })
  }
})

/* ── Changes (§6 Changes tab) — real diff records from events ── */
router.get('/agent/tasks/:idOrRef/changes', ...userOnly, async (req, res) => {
  try {
    const doc = await findOwnTask(req, res)
    if (!doc) return
    const events = await AgentEvent.find({ task_id: doc._id, type: 'task.file.changed' }).sort({ seq: 1 }).lean()
    const changes = events.map(e => ({
      at: e.created_at,
      path: e.data?.path,
      action: e.data?.action,
      added: e.data?.change?.added ?? 0,
      removed: e.data?.change?.removed ?? 0,
      hunks: e.data?.change?.hunks ?? [],
    }))
    res.json({ changes })
  } catch {
    res.status(500).json({ error: 'Changes could not be loaded.' })
  }
})

/* ── Logs (§6 Logs tab) — structured execution events ────────── */
router.get('/agent/tasks/:idOrRef/logs', ...userOnly, async (req, res) => {
  try {
    const doc = await findOwnTask(req, res)
    if (!doc) return
    const skipTerminalNoise = req.query.full !== '1'
    const filter = { task_id: doc._id }
    if (skipTerminalNoise) filter.type = { $nin: ['task.terminal.output'] }
    const events = await AgentEvent.find(filter).sort({ seq: 1 }).limit(1000).lean()
    res.json({
      logs: events.map(e => ({ at: e.created_at, type: e.type, data: e.data, seq: e.seq })),
    })
  } catch {
    res.status(500).json({ error: 'Logs could not be loaded.' })
  }
})

/* ── DOWNLOAD PROJECT AS ZIP (§8 V1.1) ──────────────────────────
   GET /api/agent/tasks/:idOrRef/download

   Streams the REAL workspace of the task as a .zip archive:

   Security & integrity:
   • authGuard + findOwnTask → ownership enforced (404 for others)
   • walk starts at the workspace root and only follows entries whose
     resolved path stays INSIDE it (path-traversal proof)
   • symbolic links are skipped entirely (no escape via symlink)
   • secrets & junk excluded: .env*, node_modules, .git, .tmp,
     caches, log files, OS droppings
   • hard caps: file count + total bytes (413 beyond) — no zip bombs
   • STREAMED with archiver straight to the response — the archive
     is never buffered in memory and no temp file is created, so
     there is nothing to clean up on failure
   • filename derived from the task title (slugified) + task ref    */
const ZIP_EXCLUDED_DIRS = new Set([
  'node_modules', '.git', '.tmp', '.cache', '__pycache__', '.venv',
  'venv', '.idea', '.vscode-server', '.npm', '.yarn', '.DS_Store',
])
const ZIP_EXCLUDED_FILEPatterns = [
  /^\.env(\..*)?$/i,       // .env, .env.local, .env.production …
  /^\.port$/i,             // agent-internal dev-server bookkeeping
  /\.log$/i,               // stray log files
  /\.pid$/i,
  /^\.DS_Store$/i,
  /^npm-debug\.log$/i,
  /^yarn-error\.log$/i,
]
const ZIP_MAX_FILES = 12000
const ZIP_MAX_BYTES = 200 * 1024 * 1024 // 200 MB

function zipExcluded(name) {
  if (ZIP_EXCLUDED_DIRS.has(name)) return true
  return ZIP_EXCLUDED_FILEPatterns.some(re => re.test(name))
}

function taskSlug(title) {
  return String(title || 'agent-project')
    .toLowerCase()
    .replace(/[^a-z0-9]+/g, '-')
    .replace(/^-+|-+$/g, '')
    .slice(0, 48) || 'agent-project'
}

/** Recursively collect safe entries (relative paths) under root. */
async function collectZipEntries(rootPath) {
  const entries = []
  let totalBytes = 0
  // Compare against the REAL path of the root so a symlinked base dir
  // (e.g. /tmp → /private/tmp) never yields false containment failures.
  const root = await fsp.realpath(rootPath).catch(() => rootPath)

  async function walk(relDir) {
    const absDir = relDir ? path.join(root, relDir) : root
    let dirents
    try { dirents = await fsp.readdir(absDir, { withFileTypes: true }) }
    catch { return }
    for (const d of dirents) {
      if (entries.length >= ZIP_MAX_FILES) return
      const rel = relDir ? `${relDir}/${d.name}` : d.name
      if (zipExcluded(d.name)) continue
      // Symlinks are NEVER followed or packed (§8 symlink attacks).
      if (d.isSymbolicLink()) continue
      const abs = path.join(root, rel)
      // Defense-in-depth: resolved path must remain inside the root.
      const resolved = await fsp.realpath(abs).catch(() => null)
      if (!resolved || !resolved.startsWith(root + path.sep) && resolved !== root) continue
      if (d.isDirectory()) {
        await walk(rel)
      } else if (d.isFile()) {
        const st = await fsp.stat(abs).catch(() => null)
        if (!st || !st.isFile()) continue
        if (st.size > 64 * 1024 * 1024) continue // skip absurd single files
        totalBytes += st.size
        if (totalBytes > ZIP_MAX_BYTES) {
          const e = new Error('The workspace is too large to package (over 200 MB).')
          e.code = 'ZIP_TOO_LARGE'; throw e
        }
        entries.push({ rel, abs, size: st.size })
      }
    }
  }

  await walk('')
  return entries
}

router.get('/agent/tasks/:idOrRef/download', ...userOnly, async (req, res) => {
  let doc = null
  try {
    doc = await findOwnTask(req, res)
    if (!doc) return
    const ws = await requireWorkspace(req, res, doc)
    if (!ws) return

    const entries = await collectZipEntries(ws.root)
    if (!entries.length) {
      return res.status(409).json({ error: 'The workspace is empty — there is nothing to download yet.', code: 'ZIP_EMPTY' })
    }

    const filename = `${taskSlug(doc.title)}-${doc.task_ref.slice(0, 8)}.zip`
    res.setHeader('Content-Type', 'application/zip')
    res.setHeader('Content-Disposition', `attachment; filename="${filename}"`)
    res.setHeader('X-Archive-Files', String(entries.length))
    res.setHeader('Cache-Control', 'no-store')

    /* Stream: archiver → response. Nothing is buffered in memory and
       no temporary archive file is ever written (§8 cleanup by
       construction). A client disconnect aborts the stream safely. */
    const archiver = require('archiver')
    const archive = archiver('zip', { zlib: { level: 6 } })
    archive.on('warning', (err) => console.warn('[Agent] zip warning:', err?.message || err))
    archive.on('error', (err) => {
      console.error('[Agent] zip stream failed:', err?.message || err)
      if (!res.headersSent) res.status(500).json({ error: 'The archive could not be created.' })
      else res.end()
    })
    req.on('close', () => { if (!res.writableEnded) archive.abort?.() })
    archive.pipe(res)

    for (const e of entries) {
      // entry name is the SAFE relative path (already verified inside root)
      archive.append(require('fs').createReadStream(e.abs), { name: e.rel })
    }
    await archive.finalize()

    logActivity('agent_task_downloaded', {
      username: req.user.username, user_id: req.user.id,
      meta: { taskId: doc._id.toString(), files: entries.length },
    })
  } catch (err) {
    if (err?.code === 'ZIP_TOO_LARGE') {
      return res.status(413).json({ error: err.message })
    }
    if (res.headersSent) { try { res.end() } catch {} return }
    console.error('[Agent] download failed:', err)
    res.status(500).json({ error: 'The project archive could not be created.' })
  }
})


/* ── V1.2 §3.B: preview auth for SUBRESOURCES ─────────────────
   Relative asset URLs (css/style.css, app.js, images/…) resolve
   against the preview URL WITHOUT the ?pt= query string, so every
   subresource request used to arrive unauthenticated → 401 → the
   exact “unstyled HTML / JavaScript not executing” symptom from the
   V1.2 spec. Fix: the token response ALSO sets a path-scoped,
   HttpOnly, SameSite=Lax cookie covering exactly this task's preview
   routes; browsers attach it to every subresource automatically. */
const PREVIEW_COOKIE = 'kb_ag_pt'

function previewCookiePath(taskRef) {
  return `/api/agent/tasks/${taskRef}/preview`
}

function setPreviewCookie(res, taskRef, token) {
  const ttlSec = Math.floor(agentConfig.preview.tokenTtlMs / 1000)
  res.setHeader('Set-Cookie',
    `${PREVIEW_COOKIE}=${encodeURIComponent(token)}; Path=${previewCookiePath(taskRef)}; HttpOnly; SameSite=Lax; Max-Age=${ttlSec}`)
}

function readPreviewCookie(req) {
  const raw = req.headers?.cookie
  if (!raw) return null
  for (const part of raw.split(';')) {
    const eq = part.indexOf('=')
    if (eq === -1) continue
    if (part.slice(0, eq).trim() === PREVIEW_COOKIE) {
      try { return decodeURIComponent(part.slice(eq + 1).trim()) } catch { return null }
    }
  }
  return null
}

/* ── Preview token (§24) — iframe-friendly auth ──────────────── */
router.get('/agent/tasks/:idOrRef/preview-token', ...userOnly, async (req, res) => {
  try {
    const doc = await findOwnTask(req, res)
    if (!doc) return
    if (!runtimePreviewEnabled()) return res.status(501).json({ error: 'Preview is disabled in this environment.', code: 'PREVIEW_DISABLED' })

    /* §32 honest check: a preview is servable ONLY while the task
       runs OR its dev server was deliberately kept alive after
       completion — and ONLY if the port is REALLY still listening,
       probed live. Never hand out a token for a dead preview.
       The DEV flow takes precedence whenever a port is registered. */
    if (doc.preview?.port) {
      const live = orchestrator.isTaskRunning(doc._id.toString()) || doc.preview.kept_alive === true
      if (!live) return res.status(409).json({ error: 'The task is not running, so its preview is offline.', code: 'PREVIEW_NOT_RUNNING' })
      if (!(await bridge.probePort(doc.preview.port))) {
        return res.status(409).json({ error: 'The preview server is no longer responding on its port.', code: 'PREVIEW_DEAD' })
      }
      const token = signPreviewToken(JWT_SECRET(), doc._id.toString(), req.user.id)
      await patchPreviewMode(doc, 'dev', null)
      setPreviewCookie(res, doc.task_ref, token)
      return res.json({ token, url: `/api/agent/tasks/${doc.task_ref}/preview/?pt=${encodeURIComponent(token)}`, port: doc.preview.port, mode: 'dev' })
    }

    /* V1.2 (§3.E): STATIC preview — workspace files served directly
       by this API process. No port, no process; the preview lives as
       long as the workspace does. ENGAGES ONLY when the task's static
       preview is actually registered (finalize sets it on success) —
       a stopped/cancelled task stays honestly offline (§11).
       The root is re-detected live so later edits are honored.  */
    const staticRegistered = doc.preview?.mode === 'static' || (doc.status === 'completed' && doc.preview?.kept_alive === true)
    if (staticRegistered && agentConfig.preview.staticEnabled) {
      const ws = new Workspace(doc._id.toString())
      const root = doc.preview?.root || await staticPreview.detectProjectRoot(ws.root)
      if (root) {
        const token = signPreviewToken(JWT_SECRET(), doc._id.toString(), req.user.id)
        await patchPreviewMode(doc, 'static', root)
        setPreviewCookie(res, doc.task_ref, token)
        return res.json({
          token,
          url: `/api/agent/tasks/${doc.task_ref}/preview/?pt=${encodeURIComponent(token)}`,
          mode: 'static', root,
        })
      }
    }

    return res.status(409).json({ error: 'No preview server is currently running for this task.', code: 'NO_PREVIEW' })
  } catch {
    res.status(500).json({ error: 'The preview token could not be issued.' })
  }
})

/** Keep the persisted preview mode/root in sync with what we just
 *  issued a token for (restore-after-refresh reads it honestly). */
async function patchPreviewMode(doc, mode, root) {
  const patch = {}
  if (doc.preview?.mode !== mode) patch['preview.mode'] = mode
  if (mode === 'static' && doc.preview?.root !== root) patch['preview.root'] = root
  if (mode === 'static') {
    patch['preview.kept_alive'] = true   // static preview persists with the workspace
    if (!doc.preview?.started_at) patch['preview.started_at'] = new Date()
  }
  if (Object.keys(patch).length) {
    await require('mongoose').model('AgentTask').updateOne({ _id: doc._id }, { $set: patch }).catch(() => {})
  }
}

/* ── Preview proxy (§24) — REAL port proxying, honest failures ──
   V1.2 (§3): two serving modes share this route + auth:
     • static — workspace files served directly (correct MIME types,
       relative asset resolution, no process required)
     • dev    — proxied to the task's real dev server on loopback  */
router.all('/agent/tasks/:idOrRef/preview/*', async (req, res) => {
  // Auth via signed preview token: ?pt= (iframe document), the
  // x-preview-token header, or the path-scoped preview cookie set by
  // the token route — WITHOUT the cookie every css/js/img subresource
  // would arrive unauthenticated (V1.2 §3.B root-cause fix).
  const token = String(req.query.pt || req.headers['x-preview-token'] || readPreviewCookie(req) || '')
  const verified = verifyPreviewToken(JWT_SECRET(), token)
  if (!verified) {
    res.removeHeader?.('Set-Cookie')
    return res.status(401).send(previewErrorPage('Preview unavailable', 'This preview link is invalid or has expired. Reopen the Agent workspace to get a fresh link.'))
  }
  // A valid ?pt= on the document request refreshes the cookie so the
  // subresources keep working even after an iframe reload.
  if (req.query.pt) {
    const doc0 = await AgentTask.findById(verified.taskId, { task_ref: 1 }).catch(() => null)
    if (doc0?.task_ref) setPreviewCookie(res, doc0.task_ref, String(req.query.pt))
  }
  const doc = await AgentTask.findById(verified.taskId).catch(() => null)
  if (!doc || String(doc.user_id) !== String(verified.userId)) {
    return res.status(404).send(previewErrorPage('Preview unavailable', 'The task no longer exists.'))
  }
  if (!agentConfig.preview.enabled || !runtimePreviewEnabled()) {
    return res.status(501).send(previewErrorPage('Preview unavailable in this environment', 'Agent preview is disabled by configuration.'))
  }

  /* ── DEV mode: proxy to the task's real dev server on loopback.
     Takes precedence whenever a port is registered (framework flow,
     §3.F unchanged from V1). Falls through to static when no port. */
  if (doc.preview?.port) {
    if (!orchestrator.isTaskRunning(doc._id.toString()) && doc.preview.kept_alive !== true) {
      return res.status(409).send(previewErrorPage('Preview unavailable', 'The task is not running, so its preview is offline.'))
    }
    const port = Number(doc.preview.port)
    if (!agentConfig.preview.allowedHosts.includes('127.0.0.1')) {
      return res.status(500).send(previewErrorPage('Preview unavailable', 'The preview host is not configured.'))
    }
    const subPath = req.params[0] || ''
    const targetPath = `/${subPath}${req.url.includes('?') ? '?' + req.url.split('?').slice(1).filter(q => !q.startsWith('pt=')).join('&') : ''}`
    const proxyReq = http.request({
      host: '127.0.0.1', port, path: targetPath, method: req.method,
      headers: { ...req.headers, host: `127.0.0.1:${port}` },
    }, (proxyRes) => {
      res.writeHead(proxyRes.statusCode || 502, proxyRes.headers)
      proxyRes.pipe(res)
    })
    proxyReq.on('error', (err) => {
      console.error(`[Agent] preview proxy error (${doc.task_ref} → 127.0.0.1:${port}):`, err?.code || '', err?.message || '')
      res.writeHead(502).end(previewErrorPage('Preview unavailable', 'The preview server stopped responding. It may have crashed — check the Terminal tab.'))
    })
    return req.pipe(proxyReq)
  }

  /* ── STATIC mode (§3.E): serve the workspace project directly —
     correct MIME types, relative asset resolution, no process needed.
     Only when the static preview is REGISTERED for this task; a
     stopped or cancelled task never re-engages it (§11 honest
     offline state). */
  if (agentConfig.preview.staticEnabled
      && (doc.preview?.mode === 'static' || (doc.status === 'completed' && doc.preview?.kept_alive === true))) {
    const ws = new Workspace(doc._id.toString())
    const root = doc.preview?.root || await staticPreview.detectProjectRoot(ws.root).catch(() => null)
    if (root) {
      // Keep the persisted mode/root honest (survives refresh).
      if (doc.preview?.mode !== 'static' || doc.preview?.root !== root) {
        await patchPreviewMode(doc, 'static', root)
      }
      return staticPreview.serveStatic(req, res, ws.root, root)
    }
  }

  return res.status(409).send(previewErrorPage('Preview unavailable', 'No preview server is running for this task. The Agent must start one (for example a dev server) first.'))
})

/* Small, honest error page for the preview iframe (§32). */
function previewErrorPage(title, message) {
  return `<!DOCTYPE html><html><head><meta charset="utf-8"><title>${title}</title>
<style>body{font-family:system-ui,sans-serif;background:#070A12;color:#CBD5E1;display:grid;place-items:center;min-height:100vh;margin:0}
.box{max-width:420px;padding:32px;text-align:center;border:1px solid #1F2937;border-radius:12px;background:#0B1020}
h1{color:#F8FAFC;font-size:18px;margin:0 0 8px}p{font-size:14px;line-height:1.5;margin:0}</style></head>
<body><div class="box"><h1>${title}</h1><p>${message}</p></div></body></html>`
}

module.exports = router
