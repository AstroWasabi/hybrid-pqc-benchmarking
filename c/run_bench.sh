#!/bin/bash
# run_bench.sh — Full C benchmarking pipeline (non-interactive)
set -e
cd /home/sudoroot/Desktop/research/c

LOG_BASE=/tmp/bench_baselines_output.txt
LOG_HYBRID=/tmp/bench_hybrid_output.txt

echo "[1/4] Killing any lingering server processes..."
kill $(lsof -ti tcp:4444) 2>/dev/null || true
sleep 1

echo "[2/4] Starting server..."
./server > server.log 2>&1 &
SERVER_PID=$!
echo "Server PID: $SERVER_PID"
sleep 2

echo "[3/4] Running bench_baselines..."
./bench_baselines 2>&1 | tee "$LOG_BASE"

echo "[4/4] Running bench_hybrid..."
./bench_hybrid 2>&1 | tee "$LOG_HYBRID"

echo ""
echo "=== DONE. Stopping server (PID $SERVER_PID)..."
kill "$SERVER_PID" 2>/dev/null || true

echo ""
echo "====== BASELINES SUMMARY ======"
tail -20 "$LOG_BASE"
echo ""
echo "====== HYBRID SUMMARY ======"
tail -30 "$LOG_HYBRID"
