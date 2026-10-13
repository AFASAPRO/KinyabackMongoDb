#!/bin/bash
# KinyaBot Agent V1.1 — full test suite with an in-memory MongoDB
# No external database needed: starts mongodb-memory-server, exports
# MONGODB_URI, runs every agent test file, then stops the database.
set -u
cd "$(dirname "$0")/.."

export NODE_ENV=test
export AGENT_PROVIDER=scripted
export KINYA_ALLOW_SCRIPTED_PROVIDER=1
export GROQ_API_KEY=sk-test-placeholder
export JWT_SECRET=kinyabot_jwt_secret_change_me
export AGENT_TEST_DB=kinyabot-agent-v11-test
export MONGO_MEM_PORT="${MONGO_MEM_PORT:-27000}"

node - > scripts/.mongo-log 2>&1 <<'EOF' &
const { MongoMemoryServer } = require('mongodb-memory-server')
const fs = require('fs')
;(async () => {
  const m = await MongoMemoryServer.create({ port: Number(process.env.MONGO_MEM_PORT) || 27000, instance: { ip: '127.0.0.1' } })
  fs.writeFileSync('scripts/.mongo-uri', m.getUri())
  console.log('memongo ready:', m.getUri())
  // keep alive until this shell's parent kills the process group
  setInterval(() => {}, 60000)
})().catch(e => { console.error('memongo failed:', e); process.exit(1) })
EOF
MEMONGO_PID=$!

# Wait for the URI file (max 120s — first run downloads the binary).
for i in $(seq 1 120); do
  if [ -s scripts/.mongo-uri ]; then break; fi
  sleep 1
done
if [ ! -s scripts/.mongo-uri ]; then
  echo "ERROR: in-memory MongoDB did not start"; cat scripts/.mongo-log 2>/dev/null
  kill $MEMONGO_PID 2>/dev/null; exit 1
fi
export MONGODB_URI="$(head -n1 scripts/.mongo-uri | tr -d '[:space:]')"
echo "── in-memory MongoDB: $MONGODB_URI"

# Wait for the server to accept connections.
for i in $(seq 1 30); do
  if node -e "require('mongoose').connect(process.env.MONGODB_URI).then(()=>process.exit(0)).catch(()=>process.exit(1))" 2>/dev/null; then break; fi
  sleep 1
done

echo "── running agent test suite (V1.1) …"
node --test tests/agent/tools.test.js \
          tests/agent/commandSafety.test.js \
          tests/agent/toolCallRepair.test.js \
          tests/agent/security.test.js \
          tests/agent/zipDownload.test.js \
          tests/agent/integration.test.js
STATUS=$?

# Cleanup: the forked memory server + any stray worker processes.
kill $MEMONGO_PID 2>/dev/null
pkill -f "mongodb-memory-server" 2>/dev/null
rm -f scripts/.mongo-uri scripts/.mongo-err.log
exit $STATUS
