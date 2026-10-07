/**
 * KinyaBot — Shared auth middleware
 * ─────────────────────────────────────────────────────────────────
 * Single implementation of the user-session guard used by both the
 * core app routes (app.js) and modular routers (routes/*.js).
 * Verifies the user JWT and attaches the decoded payload to req.user.
 */
const jwt = require('jsonwebtoken')

const JWT_SECRET = process.env.JWT_SECRET || 'kinyabot_jwt_secret_change_me'

function authGuard(req, res, next) {
  const h = req.headers.authorization
  if (!h?.startsWith('Bearer ')) return res.status(401).json({ error: 'Unauthorized' })
  try { req.user = jwt.verify(h.slice(7), JWT_SECRET); next() }
  catch { res.status(401).json({ error: 'Session expired. Please log in again.' }) }
}

module.exports = authGuard
