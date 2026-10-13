// In-memory MongoDB launcher for the V1.1 E2E stack.
const { MongoMemoryServer } = require('mongodb-memory-server')
const fs = require('fs')
const path = require('path')
;(async () => {
  const m = await MongoMemoryServer.create({ instance: { ip: '127.0.0.1' } })
  fs.writeFileSync(path.join(__dirname, '.e2e11-logs', 'mongo.uri'), m.getUri())
  console.log('memongo ready:', m.getUri())
  setInterval(() => {}, 60000) // keep alive
})().catch(e => { console.error('memongo failed:', e); process.exit(1) })
