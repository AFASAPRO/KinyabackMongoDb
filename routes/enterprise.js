/**
 * KinyaBot — Enterprise Requests API (public, from the landing page)
 * ═══════════════════════════════════════════════════════════════
 *   POST /api/enterprise-requests
 *
 * A visitor WITHOUT a KinyaBot account submits the Enterprise popup
 * on the marketing site. The row is stored for the superadmin
 * (Superadmin → Enterprise Requests) and every admin is notified.
 *
 * Security:
 *   • Public endpoint — rate-limited per IP, strictly validated.
 *   • No secrets returned; responses are minimal by design.
 */
const express = require('express')
const { EnterpriseRequest } = require('../models')
const rateLimiter = require('../services/rateLimiter')
const { notifyAdmins } = require('../services/notify')

const router = express.Router()

router.post('/enterprise-requests', async (req, res) => {
  /* Rate limit per IP: 5 submissions per hour is generous for humans */
  const rl = rateLimiter.allow(`ip:${req.ip}`, 'enterprise_request', { limit: 5, windowMs: 3600 * 1000 })
  if (!rl.ok) return res.status(429).json({ error: 'Too many requests. Please try again later.' })

  const b = req.body || {}
  const errors = {}

  const fullName = String(b.full_name || b.name || '').trim()
  if (fullName.length < 2 || fullName.length > 120) errors.full_name = 'Please enter your full name.'

  const company = String(b.company || '').trim()
  if (!company || company.length > 160) errors.company = 'Please enter your company or organization.'

  const email = String(b.email || '').trim().toLowerCase()
  if (!/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(email) || email.length > 200) errors.email = 'Please enter a valid work email.'

  const phone = String(b.phone || '').trim()
  const digits = phone.replace(/[^\d]/g, '')
  if (digits.length < 7 || digits.length > 15) errors.phone = 'Please enter a valid phone number.'

  const teamSize = String(b.team_size || b.teamSize || '').trim().slice(0, 40)
  if (!teamSize) errors.team_size = 'Please select your team size.'

  const message = String(b.message || '').trim().slice(0, 1000)
  const source = String(b.source || 'landing_pricing').trim().slice(0, 60) || 'landing_pricing'

  if (Object.keys(errors).length) {
    return res.status(400).json({ error: 'Please fix the highlighted fields.', fields: errors })
  }

  try {
    const doc = await EnterpriseRequest.create({
      full_name: fullName, company, email, phone, team_size: teamSize, message, source,
    })
    notifyAdmins({
      title: 'New Enterprise plan request',
      message: `${fullName} (${company}, ${teamSize}) requested the Enterprise plan — check Enterprise Requests for contact details.`,
      type: 'info', category: 'user', link: '/admin/enterprise-requests',
    }).catch(() => {})
    res.status(201).json({ ok: true, id: doc._id.toString() })
  } catch (err) {
    console.error('[EnterpriseRequest]', err)
    res.status(500).json({ error: 'Could not submit your request. Please try again.' })
  }
})

module.exports = router
