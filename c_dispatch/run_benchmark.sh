#!/usr/bin/env bash
# c_dispatch/run_benchmark.sh
# ═══════════════════════════════════════════════════════════════════
# Convenience runner for the Adaptive Dispatch Runtime benchmark.
#
# Usage:
#   ./run_benchmark.sh              # build + run
#   ./run_benchmark.sh --clean      # clean + build + run
#   ./run_benchmark.sh --build-only # build only, don't run
# ═══════════════════════════════════════════════════════════════════

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
cd "$SCRIPT_DIR"

# ─── Parse arguments ─────────────────────────────────────────────
CLEAN=0
BUILD_ONLY=0
for arg in "$@"; do
    case "$arg" in
        --clean)      CLEAN=1 ;;
        --build-only) BUILD_ONLY=1 ;;
        --help|-h)
            echo "Usage: $0 [--clean] [--build-only]"
            exit 0
            ;;
    esac
done

# ─── Clean if requested ─────────────────────────────────────────
if [ "$CLEAN" -eq 1 ]; then
    echo "[*] Cleaning build artefacts..."
    make clean
    echo ""
fi

# ─── Build ───────────────────────────────────────────────────────
echo "[*] Building Adaptive Dispatch Runtime..."
echo ""
make -j"$(nproc)" 2>&1
echo ""

if [ "$BUILD_ONLY" -eq 1 ]; then
    echo "[✔] Build complete. Run ./benchmark_suite to execute."
    exit 0
fi

# ─── Run ─────────────────────────────────────────────────────────
echo "[*] Running benchmark suite..."
echo ""
./benchmark_suite 2>&1 | tee benchmark_output.log

echo ""
echo "[✔] Output saved to: benchmark_output.log"
echo "[✔] Host profile:    host_profile.json"
echo "[✔] Results JSON:    benchmark_results.json"
