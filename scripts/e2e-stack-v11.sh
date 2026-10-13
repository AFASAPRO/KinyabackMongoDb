#!/bin/bash
# KinyaBot Agent V1.1 — local E2E stack (in-memory MongoDB + scripted provider)
# Usage: bash scripts/e2e-stack-v11.sh start | stop
set -u
BASE="$(cd "$(dirname "$0")/.." && pwd)"
FRONTEND="$BASE/../frontend"
LOGS="$BASE/scripts/.e2e11-logs"
mkdir -p "$LOGS"

case "${1:-start}" in
start)
  cd "$BASE"
  # 1) in-memory MongoDB (stays up until stop).
  #    Clear any stale URI first — a leftover mongo.uri from a previous
  #    run would make the wait-loop exit immediately with the OLD port.
  rm -f "$LOGS/mongo.uri"
  nohup node scripts/.memongo-v11.cjs > "$LOGS/mongo.log" 2>&1 &
  echo $! > "$LOGS/mongo.pid"
  for i in $(seq 1 90); do [ -s "$LOGS/mongo.uri" ] && break; sleep 1; done
  MONGO_URI="$(head -n1 "$LOGS/mongo.uri" | tr -d '[:space:]' | sed 's:/*$::')"
  if [ -z "$MONGO_URI" ]; then echo "ERROR: memongo failed"; cat "$LOGS/mongo.log"; exit 1; fi
  echo "memongo: $MONGO_URI"

  # 2) backend (real app.js, scripted provider for offline E2E)
  MONGODB_URI="$MONGO_URI/kinyabot-agent-v11-e2e" \
  PORT=5000 JWT_SECRET=kinyabot_jwt_secret_change_me \
  AGENT_PROVIDER=scripted KINYA_ALLOW_SCRIPTED_PROVIDER=1 \
  GROQ_API_KEY=sk-test-placeholder \
  nohup node app.js > "$LOGS/backend.log" 2>&1 &
  echo $! > "$LOGS/backend.pid"

  # 3) frontend dev server
  cd "$FRONTEND"
  nohup npx vite --port 5173 --strictPort > "$LOGS/frontend.log" 2>&1 &
  echo $! > "$LOGS/frontend.pid"

  # 4) wait for both to accept connections
  for i in $(seq 1 60); do
    BE_OK=$(curl -s -o /dev/null -w '%{http_code}' http://127.0.0.1:5000/api/health 2>/dev/null || echo 000)
    FE_OK=$(curl -s -o /dev/null -w '%{http_code}' http://127.0.0.1:5173/ 2>/dev/null || echo 000)
    [ "$BE_OK" != "000" ] && [ "$FE_OK" != "000" ] && break
    sleep 1
  done
  echo "started: backend($(cat "$LOGS/backend.pid")) frontend($(cat "$LOGS/frontend.pid"))"
  echo "backend health: $BE_OK · frontend: $FE_OK"
  ;;
stop)
  for f in backend frontend mongo; do
    if [ -f "$LOGS/$f.pid" ]; then
      kill "$(cat "$LOGS/$f.pid")" 2>/dev/null
      rm -f "$LOGS/$f.pid"
    fi
  done
  pkill -f "services/agent/worker.js" 2>/dev/null
  pkill -f "memongo-v11" 2>/dev/null
  pkill -f "http.server" 2>/dev/null
  rm -rf "$LOGS/mongo.uri"
  echo "stopped"
  ;;
esac
