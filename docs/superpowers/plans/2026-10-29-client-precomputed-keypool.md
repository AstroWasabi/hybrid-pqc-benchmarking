# Client-Side Pre-Computed Key Pool Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Implement a thread-safe, bounded, background-replenished pre-computed key pool on the client side to eliminate the client-side TLS initialization bottleneck (TCP-to-TLS latency) identified in recent post-quantum TLS 1.3 literature (Gómez-Cambronero et al., 2026).

**Architecture:**
- **`key_pool.h` / `key_pool.c`**: Manages circular FIFO queues of pre-generated classical ephemeral keypairs (`X25519`, `SecP256r1`, `SecP384r1`) with pre-exported public key buffers.
- **Background Worker**: Asynchronously monitors watermarks and replenishes consumed key slots during network idle intervals without blocking the connection critical path.
- **Client Integration (`client.c`)**: Allows `execute_dispatch_handshake()` to pop ready-to-use key material in $O(1)$ time (< 2 µs) instead of computing expensive curve scalar multiplications inline.
- **Benchmarking (`bench_keypool.c` / `bench_e2e.c`)**: Quantifies the exact microsecond savings in `ClientHello` construction and end-to-end handshake time across all hybrid cipher suites.

---

### File Structure & Changes

| File | Status | Description |
| :--- | :--- | :--- |
| `c_dispatch/include/key_pool.h` | **New** | Public API and struct definitions for the client key pool |
| `c_dispatch/src/key_pool.c` | **New** | Background replenishment worker and ring buffer logic |
| `c_dispatch/test_key_pool.c` | **New** | Standalone test verifying concurrency, replenishment, and cryptographic validity |
| `c_dispatch/include/algo_config.h` | **Modify** | Add pool-related telemetry/config if needed |
| `c_dispatch/client.c` | **Modify** | Integrate `key_pool_pop()` in `execute_dispatch_handshake()` |
| `c_dispatch/bench_e2e.c` | **Modify** | Support `--precompute` CLI toggle and timing breakdown |
| `c_dispatch/Makefile` | **Modify** | Add `src/key_pool.c` to objects and compile test targets |

---

### Task 1: Core Key Pool Data Structures & API Design

- [ ] Create `c_dispatch/include/key_pool.h` defining:
  - `KeySlot`: Container holding `EVP_PKEY *c_priv`, `uint8_t pub_buf[MAX_PUB_KEY_BYTES]`, `size_t pub_len`, `int curve_id`.
  - `KeyRing`: Fixed-capacity array, `head`, `tail`, `count`, `pthread_mutex_t`, and `pthread_cond_t refill_cond`.
  - Public functions:
    - `int key_pool_init(size_t capacity_per_curve);`
    - `int key_pool_pop(int curve_id, EVP_PKEY **out_priv, uint8_t *out_pub, size_t *out_pub_len);`
    - `void key_pool_stats(int curve_id, size_t *available, size_t *capacity);`
    - `void key_pool_destroy(void);`

---

### Task 2: Background Replenishment Worker Implementation

- [ ] Create `c_dispatch/src/key_pool.c`:
  - Implement per-curve ring buffers for `CURVE_X25519`, `CURVE_SECP256R1`, and `CURVE_SECP384R1`.
  - Implement worker thread loop:
    - Sleeps on condition variable `refill_cond`.
    - When awoken or triggered by low-water mark (e.g. `count < capacity / 2`), generates keypairs using `crypto_generate_keypair()`.
    - Pre-exports the raw/DER public key so that wire serialization is zero-cost during the handshake.
  - Implement `key_pool_pop()`:
    - Lock ring mutex.
    - If empty, fallback gracefully to synchronous `crypto_generate_keypair()`.
    - If available, pop key slot, copy pre-exported public key, transfer `EVP_PKEY*` ownership, zeroize slot, update count, and signal `refill_cond` if below watermark.
    - Unlock ring mutex.
  - Implement `key_pool_destroy()`:
    - Signal shutdown, join worker thread, securely cleanse and free all remaining `EVP_PKEY` instances.

---

### Task 3: Unit & Concurrency Test Suite

- [ ] Create `c_dispatch/test_key_pool.c`:
  - Test 1: Initialize pool, verify pool reaches full capacity across all curves.
  - Test 2: Rapid concurrent pops (burst consumption) to verify thread safety and lock contention.
  - Test 3: Cryptographic validity test — perform ECDH derivation against a mock peer public key using popped keys to prove mathematical correctness.
  - Test 4: Timing microbenchmark — measure elapsed time of `key_pool_pop()` vs. on-demand `crypto_generate_keypair()`.

---

### Task 4: Client Handshake Integration

- [ ] Update `c_dispatch/client.c`:
  - Add global flag `int g_use_precomputed_pool`.
  - In `execute_dispatch_handshake()`:
    - Record nanosecond timestamp before and after `ClientHello` construction (`t_ch_prep`).
    - Use `key_pool_pop()` when enabled, or standard generation when disabled.
  - Call `key_pool_init()` / `key_pool_destroy()` in client lifecycle.

---

### Task 5: End-to-End Benchmark & Comparative Analysis

- [ ] Update `c_dispatch/bench_e2e.c` and `c_dispatch/Makefile`:
  - Add `src/key_pool.c` to `Makefile`.
  - Add CLI option `--precompute` in `bench_e2e.c`.
  - Output comparative markdown table comparing:
    1. Standard On-Demand Keygen (Baseline)
    2. Pre-computed Key Pool (Optimized)
  - Display latency metrics: `ClientHello Construction (ms)`, `In-Flight Handshake (ms)`, `Total E2E (ms)`, and $p50/p95/p99$ tail spreads.
