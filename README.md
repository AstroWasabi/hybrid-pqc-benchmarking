# Hybrid Post-Quantum Cryptography Benchmarking & Adaptive Execution Engine

[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)
[![C Standard](https://img.shields.io/badge/C-C11-blue.svg)](https://en.wikipedia.org/wiki/C11_(C_standard_revision))
[![TLS 1.3](https://img.shields.io/badge/TLS%201.3-RFC%209954-green.svg)](https://datatracker.ietf.org/doc/rfc9954/)
[![NIST PQC](https://img.shields.io/badge/NIST-FIPS%20203%20%2F%20ML--KEM-purple.svg)](https://csrc.nist.gov/pubs/fips/203/final)

An adaptive, telemetry-aware cryptographic execution framework for **Hybrid Post-Quantum Key Exchange** in TLS 1.3 network protocols, built upon **liboqs** and **OpenSSL**.

---

## Architecture Overview

```
                          ┌────────────────────────┐
                          │   TLS 1.3 Handshake    │
                          │      Client/Server     │
                          └───────────┬────────────┘
                                      │
                         [ Boot Telemetry Profiler ]
                         (Cores, Hypervisor, DMI)
                                      │
                                      ▼
                        ┌───────────────────────────┐
                        │    adaptive_dispatch()    │
                        └──────┬─────────────┬──────┘
                               │             │
              ┌────────────────┘             └────────────────┐
              ▼                                               ▼
   [ ROUTE_SEQUENTIAL ]                             [ ROUTE_PARALLEL ]
   • Calling thread execution                       • Core-pinned persistent worker pool
   • 0 Context switches                             • Main Thread: Core 0 (ECDH)
   • L1/L2 Cache locality preserved                 • Worker Thread: Core 1 (ML-KEM)
   • For: Single-core, low-vCPU VMs, light suites   • For: Bare-metal, multi-core, heavy suites
              │                                               │
              └────────────────┬──────────────────────────────┘
                               ▼
                   ┌────────────────────────┐
                   │ HKDF Shared Secret     │
                   │ Combined Key Material  │
                   └────────────────────────┘
```

---

## Key Features

1. **RFC 9954 Compliant Key Exchange:** Concatenation and HKDF derivation of classical curves (`X25519`, `SecP256r1`, `SecP384r1`) with NIST PQC finalists (`ML-KEM-768`, `ML-KEM-1024`, `FrodoKEM-1344`, `BIKE-L5`).
2. **Phase 1 Hardware Profiler (`telemetry.c`):** Zero-allocation boot-time host detection querying core topology and hypervisor fingerprints (`KVM`, `QEMU`, `VMware`, `AWS Nitro`).
3. **Phase 3 Pinned Execution Engine (`engine.c`):** High-efficiency persistent worker pool with `pthread_cond_t` instant wake-ups and strict CPU core pinning (`sched_setaffinity`).
4. **Phase 4 Adaptive Router (`dispatcher.c`):** Dynamic routing selecting between sequential and parallel crypto pathways based on hardware telemetry and cryptographic algorithm weight.
5. **Phase 5 Network Protocol (`client.c`, `server.c`):** Full end-to-end TLS 1.3 socket layer with wire-level hybrid handshake framing.
6. **Micro-Architectural Telemetry:** Detailed logging of CPU cycles, IPC, L1/L2 cache misses, context switches, and predictive model drift ($\Delta$).

---

## Supported Hybrid Cipher Suites

| Suite ID | Classical Algorithm | Post-Quantum Algorithm | Security Level | Primary Use-Case |
| :--- | :--- | :--- | :---: | :--- |
| `0x0001` | **X25519** | **ML-KEM-768** | NIST Level 1/3 | Ultra-fast general web traffic |
| `0x0002` | **SecP256r1** | **ML-KEM-768** | NIST Level 1/3 | Enterprise / FIPS web compliance |
| `0x0003` | **SecP384r1** | **ML-KEM-1024** | NIST Level 5 | CNSA 2.0 High-security government grade |
| `0x0004` | **SecP384r1** | **FrodoKEM-1344** | NIST Level 5 | Unstructured lattice / Conservative security |
| `0x0005` | **SecP384r1** | **BIKE-L5** | NIST Level 5 | Code-based alternative PQC security |

---

## Empirical Benchmark Results

Evaluated over $N=1,000$ handshakes (omitting cold-start iteration 0):

| Cipher Suite | Mode | Mean (ms) | $p50$ (ms) | $p95$ (ms) | $p99$ (ms) | Speedup / Behavior |
| :--- | :--- | :---: | :---: | :---: | :---: | :--- |
| **X25519 + ML-KEM-768** | Strict Sequential<br>**Adaptive Switch**<br>Strict Parallel | 0.226<br>**0.221**<br>0.191 | 0.219<br>**0.219**<br>0.189 | 0.231<br>**0.226**<br>0.196 | 0.336<br>**0.232**<br>0.201 | **Sequential Selected** — lowest $p99$ variance. |
| **SecP256r1 + ML-KEM-768** | Strict Sequential<br>**Adaptive Switch**<br>Strict Parallel | 0.297<br>**0.280**<br>0.268 | 0.293<br>**0.266**<br>0.265 | 0.305<br>**0.281**<br>0.274 | 0.420<br>**0.451**<br>0.307 | **Parallel Selected** on $\ge 3$ cores. |
| **SecP384r1 + ML-KEM-1024** | Strict Sequential<br>**Adaptive Switch**<br>Strict Parallel | 1.757<br>**1.715**<br>1.716 | 1.748<br>**1.705**<br>1.706 | 1.774<br>**1.733**<br>1.735 | 1.948<br>**1.866**<br>1.899 | Overhead amortized across heavy primitives. |
| **SecP384r1 + FrodoKEM-1344** | Strict Sequential<br>**Adaptive Switch**<br>Strict Parallel | 5.998<br>**4.447**<br>4.448 | 5.972<br>**4.432**<br>4.428 | 6.112<br>**4.523**<br>4.526 | 6.572<br>**4.803**<br>4.914 | **25.8% Latency Reduction** under Parallel. |
| **SecP384r1 + BIKE-L5** | Strict Sequential<br>**Adaptive Switch**<br>Strict Parallel | 4.315<br>**2.595**<br>2.613 | 4.220<br>**2.584**<br>2.585 | 4.829<br>**2.624**<br>2.716 | 6.923<br>**2.867**<br>3.148 | **39.8% Latency Reduction** & slashed tail spikes. |

---

## Directory Structure

```
├── c_dispatch/                     # Native C Adaptive Dispatch Framework
│   ├── include/
│   │   ├── algo_config.h           # Cipher suite definitions & wire mappings
│   │   ├── dispatcher.h            # Adaptive routing API & decisions
│   │   ├── engine.h                # Sequential vs. Parallel execution engine
│   │   ├── telemetry.h             # Boot-time hardware profiler
│   │   └── wire_proto.h            # TLS 1.3 socket protocol packet formats
│   ├── src/
│   │   ├── algo_config.c           # Algorithm registration
│   │   ├── dispatcher.c            # Telemetry-driven routing logic
│   │   ├── engine.c                # pthread worker pool & core pinning
│   │   └── telemetry.c             # DMI & CPU core topology inspector
│   ├── bench_e2e.c                 # Full client/server end-to-end benchmark
│   ├── bench_level5_demo.c         # NIST Level 5 (Frodo/BIKE/ML-KEM) demo
│   ├── benchmark_suite.c           # Latency & percentile evaluation suite
│   ├── client.c / server.c         # Standalone socket client/server binaries
│   ├── Makefile                    # Build recipes (liboqs & OpenSSL linked)
│   └── run_benchmark.sh            # Benchmark orchestration script
├── core/                           # Python baseline framework
├── config/                         # Python algorithm parameters
├── telemetry/                      # Hardware perf counters & cost model
├── generate_conference_plots.py    # Publication plot generation scripts
├── DEFENSE_REPORT.md               # Thesis defense report & committee Q&A
└── README.md
```

---

## Prerequisites & Installation

### 1. System Dependencies
* GCC / Clang with C11 support
* OpenSSL (>= 3.0) development headers (`libssl-dev`, `libcrypto`)
* CMake (>= 3.20)
* Python 3.9+ (with `matplotlib`, `numpy`)

### 2. Build and Install liboqs
```bash
git clone --depth=1 https://github.com/open-quantum-safe/liboqs
cmake -S liboqs -B liboqs/build -DBUILD_SHARED_LIBS=ON -DOQS_BUILD_ONLY_LIB=ON
cmake --build liboqs/build --parallel 8
sudo cmake --build liboqs/build --target install
sudo ldconfig
```

---

## Building & Running the C Dispatch Engine

```bash
cd c_dispatch

# Build all binaries
make all

# Run the comprehensive benchmark suite (1,000 iterations per mode)
./benchmark_suite

# Run the Level 5 High-Security primitives demonstration
./bench_level5_demo

# Run full End-to-End Client/Server TLS 1.3 Handshake test
./run_e2e.sh
```

---

## Thesis Defense Documentation

For in-depth explanations regarding single-core execution, jitter isolation, virtualization effects, and instability criteria, refer to:
* **[DEFENSE_REPORT.md](file:///home/sudoroot/Desktop/research/DEFENSE_REPORT.md)**

---

## License

This project is licensed under the MIT License.
