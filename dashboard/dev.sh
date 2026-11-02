#!/usr/bin/env bash
# Build the frontend and serve the whole dashboard from the backend on :8000.
# For hot-reload development, run the backend and `npm run dev` separately:
#   cd dashboard/backend && uvicorn app:app --reload --port 8000
#   cd dashboard/frontend && npm run dev      # UI on :5173, proxies /api -> :8000
set -euo pipefail
DASH="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
ROOT="$(cd "$DASH/.." && pwd)"
PORT="${PORT:-8000}"

echo "==> building frontend"
cd "$DASH/frontend"
[ -d node_modules ] || npm install
npm run build

echo "==> serving on http://localhost:$PORT (runs from ${PREDIQL_RUNS_ROOT:-$ROOT/runs})"
cd "$DASH/backend"
exec "$ROOT/.venv/bin/uvicorn" app:app --host 0.0.0.0 --port "$PORT"
