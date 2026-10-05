/**
 * KinyaBot — Audit Trail service
 * ─────────────────────────────────────────────────────────────────
 * Writes one immutable AuditLog row per administrative mutation and
 * mirrors it to the Superadmin realtime feed. Historical audit rows
 * are NEVER updated or deleted by any endpoint.
 */
const { AuditLog } = require('../models')
const { logActivity } = require('./activity')

/**
 * @param {object} admin   decoded admin token payload ({ id, username })
 * @param {string} action  namespaced action, e.g. 'user.ban', 'settings.update'
 * @param {object} opts    { resourceType, resourceId, resourceLabel, meta, result, ip, req }
 */
async function writeAudit(admin, action, opts = {}) {
  const {
    resourceType = null, resourceId = null, resourceLabel = null,
    meta = null, result = 'success', ip = null, req = null,
  } = opts
  try {
    const doc = await AuditLog.create({
      actor_id: admin?.id || null,
      actor_username: admin?.username || null,
      action,
      resource_type: resourceType,
      resource_id: resourceId != null ? String(resourceId) : null,
      resource_label: resourceLabel,
      result,
      meta,
      ip: ip || req?.ip || null,
    })
    const row = { id: doc._id.toString(), action, actor_username: doc.actor_username, resource_type: resourceType, resource_label: resourceLabel, result, created_at: doc.created_at }
    // Mirror to the live audit feed (best-effort)
    try { logActivity(`audit:${action}`, { username: admin?.username || null, meta: { resource: resourceLabel || resourceId } }) } catch {}
    return row
  } catch (err) {
    console.error('[Audit] write failed:', err.message)
    return null
  }
}

/** Wrap a mutating handler so success AND failure are both audited. */
function withAudit(action, resourceType, handler) {
  return async (req, res) => {
    try {
      await handler(req, res)
    } catch (err) {
      await writeAudit(req.admin, action, { resourceType, result: 'failure', meta: { error: err?.message || String(err) }, req })
      throw err
    }
  }
}

module.exports = { writeAudit, withAudit }
