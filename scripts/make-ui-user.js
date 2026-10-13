/** Prepare a verified browser-test user + login token bootstrap. */
const mongoose = require('mongoose')
const bcrypt = require('bcryptjs')

async function main() {
  const baseUri = process.env.MONGODB_URI || require('dotenv').config().parsed.MONGODB_URI
  // V1.1: DB name is parameterised so the same helper serves any stack
  // (e2e-stack-v11 uses kinyabot-agent-v11-e2e via UI_USER_DB).
  const dbName = process.env.UI_USER_DB || 'kinyabot-agent-v1-smoke'
  await mongoose.connect(`${baseUri}/${dbName}`)
  const { User } = require('../models')
  await User.deleteOne({ username: 'uibot' })
  await User.create({
    username: 'uibot', email: 'uibot@test.local',
    password_hash: await bcrypt.hash('ui-password-1', 10),
    onboarded: true, email_verified: true,
  })
  console.log('✓ uibot user ready (ui-password-1)')
  await mongoose.disconnect()
  process.exit(0)
}
main().catch(e => { console.error(e); process.exit(1) })
