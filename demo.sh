#!/usr/bin/env bash
# One-file live demo runner: backend + frontend (live mode) + real engine replay feed.
# Run:   ./demo.sh
# Stop:  Ctrl-C (cleans up all three processes)

set -euo pipefail
cd "$(dirname "${BASH_SOURCE[0]}")"

API_PORT=8000
WEB_PORT=5173
API_BASE="http://localhost:${API_PORT}"
LOG_DIR="demo-logs"
REPLAY_LIMIT="${REPLAY_LIMIT:-40}"
REPLAY_DELAY="${REPLAY_DELAY:-1.5}"

mkdir -p "$LOG_DIR"
: > "$LOG_DIR/backend.log"
: > "$LOG_DIR/frontend.log"
: > "$LOG_DIR/replay.log"

PIDS=()
cleanup() {
  echo
  echo "stopping demo..."
  for pid in "${PIDS[@]}"; do
    kill "$pid" >/dev/null 2>&1 || true
  done
  wait >/dev/null 2>&1 || true
  echo "stopped."
}
trap cleanup EXIT INT TERM

if [[ ! -x .venv/bin/uvicorn ]]; then
  echo "missing .venv (run 'make setup' first)"; exit 1
fi
if [[ ! -d frontend/node_modules ]]; then
  echo "missing frontend/node_modules (run 'make setup' first)"; exit 1
fi
if [[ ! -f engine/model/isoforest.joblib ]]; then
  echo "missing trained model at engine/model/ (run '.venv/bin/python -m engine.train' first)"; exit 1
fi

echo "== 1/3 backend  -> ${API_BASE}"
.venv/bin/uvicorn orchestrator.main:app --port "$API_PORT" >"$LOG_DIR/backend.log" 2>&1 &
PIDS+=($!)

echo "waiting for backend health..."
for _ in $(seq 1 30); do
  if curl -sf "${API_BASE}/health" >/dev/null 2>&1; then break; fi
  sleep 0.5
done
if ! curl -sf "${API_BASE}/health" >/dev/null 2>&1; then
  echo "backend did not come up — check $LOG_DIR/backend.log"; exit 1
fi
echo "backend is up."

echo "== 2/3 frontend (live mode) -> http://localhost:${WEB_PORT}"
( cd frontend && VITE_DATA_SOURCE=live VITE_API_BASE="$API_BASE" npm run dev -- --port "$WEB_PORT" ) \
  >"$LOG_DIR/frontend.log" 2>&1 &
PIDS+=($!)

echo "waiting for frontend..."
for _ in $(seq 1 40); do
  if curl -sf "http://localhost:${WEB_PORT}" >/dev/null 2>&1; then break; fi
  sleep 0.5
done
echo "frontend is up."

echo "== 3/3 engine replay -> streaming ${REPLAY_LIMIT} real scored flows into the feed"
.venv/bin/python -m engine.replay --limit "$REPLAY_LIMIT" --delay "$REPLAY_DELAY" \
  >"$LOG_DIR/replay.log" 2>&1 &
PIDS+=($!)

cat <<EOF

demo running:
  dashboard -> http://localhost:${WEB_PORT}
  backend   -> ${API_BASE}
  logs      -> ${LOG_DIR}/{backend,frontend,replay}.log

feed is streaming now. Ctrl-C to stop everything.
EOF

wait
