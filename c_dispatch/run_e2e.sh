#!/usr/bin/env bash
# c_dispatch/run_e2e.sh
# ═══════════════════════════════════════════════════════════════════
# End-to-End Benchmark Pipeline
#
# 1. Kill any lingering server on port 4444
# 2. Build all targets
# 3. Start the dispatch server
# 4. Run the end-to-end benchmark client
# 5. Stop the server
# 6. Print summary
#
# Usage:
#   ./run_e2e.sh                        # default: 1000 runs, sha256
#   ./run_e2e.sh --runs 100             # fewer iterations (faster)
#   ./run_e2e.sh --kdf blake3           # use BLAKE3 KDF
#   ./run_e2e.sh --runs 100 --kdf blake3
# ═══════════════════════════════════════════════════════════════════

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
cd "$SCRIPT_DIR"

# ─── Parse args (pass through to bench_e2e) ─────────────────────
BENCH_ARGS="$*"

echo ""
echo "═══════════════════════════════════════════════════════"
echo "  Adaptive Dispatch Runtime — E2E Pipeline"
echo "═══════════════════════════════════════════════════════"
echo ""

# ─── Step 1: Kill any lingering server ───────────────────────────
echo "[1/5] Killing any lingering server on port 4444..."
PID=$(lsof -ti tcp:4444 2>/dev/null || true)
if [ -n "$PID" ]; then
    kill -9 $PID 2>/dev/null || true
fi
sleep 1

# ─── Step 2: Build ───────────────────────────────────────────────
echo "[2/5] Building all targets..."
make -j"$(nproc)" 2>&1
echo ""

# ─── Step 3: Start dispatch server ──────────────────────────────
echo "[3/5] Starting dispatch server..."
./server > server.log 2>&1 &
SERVER_PID=$!
echo "  Server PID: $SERVER_PID"
sleep 2

# Verify server is listening
if ! kill -0 "$SERVER_PID" 2>/dev/null; then
    echo "[!] Server failed to start. Check server.log"
    cat server.log
    exit 1
fi
echo "  Server is listening on port 4444"
echo ""

# ─── Step 4: Run E2E benchmark ──────────────────────────────────
echo "[4/5] Running end-to-end benchmark..."
echo ""
# shellcheck disable=SC2086
./bench_e2e $BENCH_ARGS 2>&1 | tee e2e_output.log

# ─── Step 5: Stop server ────────────────────────────────────────
echo "[5/5] Stopping server (PID $SERVER_PID)..."
kill "$SERVER_PID" 2>/dev/null || true
wait "$SERVER_PID" 2>/dev/null || true

echo ""
echo "═══════════════════════════════════════════════════════"
echo "  Pipeline complete."
echo ""
echo "  Artifacts:"
echo "    host_profile.json          — Boot-time hardware profile"
echo "    e2e_benchmark_results.json — Benchmark statistics"
echo "    e2e_output.log             — Full console output"
echo "    server.log                 — Server log"
echo "═══════════════════════════════════════════════════════"
