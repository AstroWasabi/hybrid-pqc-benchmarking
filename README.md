# Hybrid Post-Quantum Cryptographic (PQC) Benchmarking Framework

A comprehensive benchmarking framework for evaluating **Hybrid Classical & Post-Quantum Key Encapsulation Mechanisms (KEM)** over TCP sockets. 

The framework evaluates combinations of classical elliptic curves (`X25519`, `SecP256r1`, `SecP384r1`), NIST post-quantum standardized algorithms (`ML-KEM-768`, `ML-KEM-1024`), and high-speed key derivation functions (`HKDF-SHA256` and SIMD `BLAKE3`).

It contains both a **Python reference implementation** and a multi-threaded **Native C high-performance suite** capable of POSIX parallel cryptographic execution and Linux kernel hardware telemetry (`perf_event_open`).

---

## Supported Algorithm Combinations

| ID | Hybrid / Baseline Profile | Classical Component | Post-Quantum Component | Target Security Level |
|:--:|:-------------------------|:-------------------:|:----------------------:|:---------------------:|
| 1  | Hybrid                   | X25519              | ML-KEM-768             | NIST Level 3          |
| 2  | Hybrid                   | SecP256r1           | ML-KEM-768             | NIST Level 3          |
| 3  | Hybrid                   | SecP384r1           | ML-KEM-1024            | NIST Level 5          |
| 4  | Pure Classical           | X25519              | —                      | Classical 128-bit     |
| 5  | Pure Classical           | SecP256r1           | —                      | Classical 128-bit     |
| 8  | Pure Classical           | SecP384r1           | —                      | Classical 192-bit     |
| 6  | Pure Quantum             | —                   | ML-KEM-768             | NIST Level 3          |
| 7  | Pure Quantum             | —                   | ML-KEM-1024            | NIST Level 5          |

---

## Prerequisites & Dependencies

The suite requires standard C/C++ compilation tools and OpenSSL:
* **git**, **cmake**, **ninja-build**, **gcc / clang**
* **libssl-dev** (OpenSSL 3.0+)
* **liboqs** (Open Quantum Safe C library)
* **python3** & **pip** *(optional, for Python baseline and plotting)*

---

## Quick Start: VM Deployment (AWS EC2 or Local KVM)

### 1. Clone the Repository
```bash
git clone https://github.com/AstroWasabi/hybrid-pqc-benchmarking.git
cd hybrid-pqc-benchmarking
