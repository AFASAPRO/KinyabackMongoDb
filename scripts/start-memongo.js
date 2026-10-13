/* Start the in-memory MongoDB and keep it alive until killed. */
const { MongoMemoryServer } = require('mongodb-memory-server')
const fs = require('fs')
;(async () => {
  const m = await MongoMemoryServer.create({ instance: { ip: '127.0.0.1' } })
  fs.writeFileSync(__dirname + '/.mongo-uri', m.getUri())
  console.log('ready:', m.getUri())
  setInterval(() => {}, 60000)
})().catch(e => { console.error(e); process.exit(1) })
