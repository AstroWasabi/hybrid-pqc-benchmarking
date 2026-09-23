#!/usr/bin/env bash
# c/setup_ec2.sh
# One-click environment bootstrap for running Native C PQC benchmarks on AWS EC2 (Ubuntu/Debian).

set -e

echo "=== [1/4] Installing system build dependencies ==="
sudo apt-get update -y
sudo apt-get install -y build-essential cmake ninja-build libssl-dev git pkg-config

echo "=== [2/4] Cloning and building liboqs ==="
if [ ! -f /usr/local/include/oqs/oqs.h ]; then
    TMP_DIR=$(mktemp -d)
    git clone --depth=1 --branch main https://github.com/open-quantum-safe/liboqs.git "$TMP_DIR/liboqs"
    cd "$TMP_DIR/liboqs"
    cmake -GNinja -B build \
        -DBUILD_SHARED_LIBS=ON \
        -DCMAKE_INSTALL_PREFIX=/usr/local \
        -DCMAKE_BUILD_TYPE=Release
    ninja -C build
    sudo ninja -C build install
    sudo ldconfig
    rm -rf "$TMP_DIR"
    echo "[✔] liboqs installed to /usr/local"
else
    echo "[✔] liboqs already installed at /usr/local"
fi

echo "=== [3/4] Building Native C Benchmarking Suite ==="
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
cd "$SCRIPT_DIR"
make clean
make -j"$(nproc)"

echo "=== [4/4] Verifying Build Artifacts ==="
ls -lh server bench_baselines bench_hybrid

echo ""
echo "=================================================================="
echo "✔ Setup Complete! To run the benchmarks on this EC2 instance:"
echo "  1. Start the server:     ./server --port 4444 &"
echo "  2. Run baseline tests:   ./bench_baselines --runs 20"
echo "  3. Run hybrid benchmark: ./bench_hybrid --runs 20"
echo "=================================================================="
