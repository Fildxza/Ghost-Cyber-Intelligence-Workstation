#!/usr/bin/env bash
# Fidx-Ghost one-click launcher (Linux / WSL2). Usage: ./start.sh [--no-browser]
set -euo pipefail
cd "$(dirname "$0")"
export PYTHONPATH="$PWD/backend${PYTHONPATH:+:$PYTHONPATH}" PYTHONUTF8=1
PORT="${GHOST_PORT:-8787}"
if ! python3 -c "import flask, httpx, cryptography, click" 2>/dev/null; then
  echo "[setup] Installing Python dependencies..."
  python3 -m pip install -r backend/requirements.txt || sudo apt-get install -y python3-flask python3-httpx python3-cryptography python3-click
fi
if [ ! -f frontend/dist/index.html ]; then
  echo "[setup] Building the web UI (first run, needs Node 20+)..."
  (cd frontend && npm install --no-audit --no-fund && npm run build)
fi
if [ "${1:-}" != "--no-browser" ]; then
  (sleep 2; (command -v xdg-open >/dev/null && xdg-open "http://127.0.0.1:$PORT") || (command -v wslview >/dev/null && wslview "http://127.0.0.1:$PORT") || true) &
fi
echo "[run] Fidx-Ghost on http://127.0.0.1:$PORT  (Ctrl+C to stop)"
exec python3 -m ghost serve --port "$PORT"
