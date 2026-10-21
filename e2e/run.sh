#!/usr/bin/env bash
# Runs the full browser journey against a throw-away server + data dir.
# Prereqs: python deps installed, `npm run build` done in frontend/, a Chromium-based browser installed.
# Works on Linux, WSL2 and Windows Git-Bash.
set -euo pipefail
ROOT="$(cd "$(dirname "$0")/.." && pwd)"
TMP="$(mktemp -d)"; PORT="${PORT:-8788}"
PY="$(command -v python3 || command -v python)"
if command -v cygpath >/dev/null 2>&1; then  # Git-Bash: hand native Windows paths to python/node
  TMP="$(cygpath -m "$TMP")"; ROOT_NATIVE="$(cygpath -m "$ROOT")"
else
  ROOT_NATIVE="$ROOT"
fi
export GHOST_DATA_DIR="$TMP/data" PYTHONPATH="$ROOT_NATIVE/backend" PYTHONUTF8=1
mkdir -p "$GHOST_DATA_DIR"
(cd "$ROOT/backend/tests" && "$PY" -c "import sys; from helpers import classic_pcap; sys.stdout.buffer.write(classic_pcap())" > "$TMP/capture.pcap")
"$PY" -m ghost serve --port "$PORT" > "$TMP/server.log" 2>&1 &
SERVER=$!; trap 'kill $SERVER 2>/dev/null || true' EXIT
for _ in $(seq 1 40); do curl -sf "http://127.0.0.1:$PORT/api/health" >/dev/null && break; sleep 0.5; done
node "$ROOT/e2e/journey.mjs" "http://127.0.0.1:$PORT" "$ROOT_NATIVE/e2e/out" "$TMP/capture.pcap"
