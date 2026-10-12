#!/bin/bash
# KinyaBot Agent V1 — local E2E stack launcher (backend + vite dev server)
# Usage: bash scripts/e2e-stack.sh start | stop
set -u
BASE="$(cd "$(dirname "$0")/.." && pwd)"
FRONTEND="$BASE/../frontend"
LOGS="$BASE/scripts/.e2e-logs"
mkdir -p "$LOGS"

case "${1:-start}" in
start)
  cd "$BASE"
  MONGODB_URI="$(grep '^MONGODB_URI' .env | cut -d= -f2-)/kinyabot-agent-v1-smoke" \
  PORT=5000 JWT_SECRET=kinyabot_jwt_secret_change_me \
  AGENT_PROVIDER=scripted KINYA_ALLOW_SCRIPTED_PROVIDER=1 \
  GROQ_API_KEY=sk-test-placeholder \
  nohup node app.js > "$LOGS/backend.log" 2>&1 &
  echo $! > "$LOGS/backend.pid"

  cd "$FRONTEND"
  nohup npx vite --port 5173 --strictPort > "$LOGS/frontend.log" 2>&1 &
  echo $! > "$LOGS/frontend.pid"
  echo "started: backend($(cat "$LOGS/backend.pid")) frontend($(cat "$LOGS/frontend.pid"))"
  ;;
stop)
  for f in backend frontend; do
    if [ -f "$LOGS/$f.pid" ]; then
      kill "$(cat "$LOGS/$f.pid")" 2>/dev/null
      rm -f "$LOGS/$f.pid"
    fi
  done
  # also reap any agent workers / preview servers from the smoke run
  pkill -f "services/agent/worker.js" 2>/dev/null
  pkill -f "http.server" 2>/dev/null
  echo "stopped"
  ;;
esac
