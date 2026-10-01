# c_dispatch/Makefile
# ═══════════════════════════════════════════════════════════════════
# Build system for the Adaptive Dispatch Runtime
# TLS 1.3 Hybrid PQC — Micro-Architectural Variance Analysis
# ═══════════════════════════════════════════════════════════════════
#
# Targets:
#   all              — build all executables (default)
#   server           — dispatch-integrated TCP server
#   bench_e2e        — end-to-end network benchmark client
#   benchmark_suite  — local (no-network) benchmark harness
#   clean            — remove build artefacts
#
# Dependencies:
#   - OpenSSL 3.x    (libssl, libcrypto)
#   - liboqs         (ML-KEM-768, ML-KEM-1024)
#   - pthreads       (worker pool, affinity)
#   - BLAKE3         (vendored from ../c/blake3/)
#   - cJSON          (vendored from ../c/cjson/)

# ─── liboqs detection ───────────────────────────────────────────
LIBOQS_DIR ?= $(wildcard /home/sudoroot/_oqs)
ifeq ($(LIBOQS_DIR),)
  LIBOQS_DIR := $(wildcard /usr/local)
endif
ifeq ($(LIBOQS_DIR),)
  LIBOQS_DIR := /usr
endif

LIBOQS_LIB_DIR := $(wildcard $(LIBOQS_DIR)/lib64)
ifeq ($(LIBOQS_LIB_DIR),)
  LIBOQS_LIB_DIR := $(LIBOQS_DIR)/lib
endif

# ─── Vendored library directories ──────────────────────────────
BLAKE3_DIR := ../c/blake3
CJSON_DIR  := ../c/cjson

# ─── Compiler / Flags ───────────────────────────────────────────
CC      := gcc
CFLAGS  := -Wall -Wextra -O3 -std=c11 -pthread \
           -D_GNU_SOURCE \
           -I./include \
           -I$(BLAKE3_DIR) \
           -I$(CJSON_DIR) \
           -I$(LIBOQS_DIR)/include

LDFLAGS := -L$(LIBOQS_LIB_DIR) \
           -Wl,-rpath,$(LIBOQS_LIB_DIR) \
           -loqs -lssl -lcrypto -lpthread -lm

.DEFAULT_GOAL := all

# ─── BLAKE3 objects ─────────────────────────────────────────────
BLAKE3_CORE_SRCS := $(BLAKE3_DIR)/blake3.c \
                    $(BLAKE3_DIR)/blake3_dispatch.c \
                    $(BLAKE3_DIR)/blake3_portable.c

BLAKE3_CORE_OBJS := $(BLAKE3_CORE_SRCS:.c=.o)

$(BLAKE3_DIR)/blake3_sse2.o: $(BLAKE3_DIR)/blake3_sse2.c
	$(CC) $(CFLAGS) -msse2 -c $< -o $@

$(BLAKE3_DIR)/blake3_sse41.o: $(BLAKE3_DIR)/blake3_sse41.c
	$(CC) $(CFLAGS) -msse4.1 -c $< -o $@

$(BLAKE3_DIR)/blake3_avx2.o: $(BLAKE3_DIR)/blake3_avx2.c
	$(CC) $(CFLAGS) -mavx2 -c $< -o $@

$(BLAKE3_DIR)/blake3_avx512.o: $(BLAKE3_DIR)/blake3_avx512.c
	$(CC) $(CFLAGS) -mavx512f -mavx512vl -c $< -o $@

BLAKE3_SIMD_OBJS := $(BLAKE3_DIR)/blake3_sse2.o \
                    $(BLAKE3_DIR)/blake3_sse41.o \
                    $(BLAKE3_DIR)/blake3_avx2.o \
                    $(BLAKE3_DIR)/blake3_avx512.o

BLAKE3_OBJS := $(BLAKE3_CORE_OBJS) $(BLAKE3_SIMD_OBJS)

# ─── cJSON ──────────────────────────────────────────────────────
CJSON_SRCS := $(CJSON_DIR)/cJSON.c
CJSON_OBJS := $(CJSON_SRCS:.c=.o)

# ─── Dispatch runtime core ─────────────────────────────────────
DISPATCH_SRCS := src/telemetry.c \
                 src/engine.c \
                 src/dispatcher.c \
                 src/crypto_engine.c \
                 src/network_utils.c

DISPATCH_OBJS := $(DISPATCH_SRCS:.c=.o)

# ─── All common objects ────────────────────────────────────────
ALL_COMMON := $(DISPATCH_OBJS) $(BLAKE3_OBJS) $(CJSON_OBJS)

# ─── Generic compile rule ──────────────────────────────────────
%.o: %.c
	$(CC) $(CFLAGS) -c $< -o $@

# ─── Targets ───────────────────────────────────────────────────
.PHONY: all clean

all: server bench_e2e benchmark_suite bench_level5 bench_level5_demo bench_prims
	@echo ""
	@echo "═══════════════════════════════════════════════════════"
	@echo "  Build complete:"
	@echo "    ./server           — Adaptive Dispatch TLS Server"
	@echo "    ./bench_e2e        — End-to-End Network Benchmark"
	@echo "    ./benchmark_suite  — Local (no-network) Benchmark"
	@echo "    ./bench_level5     — NIST Level 5 Benchmark"
	@echo "    ./bench_level5_demo — Level 5 Demo Benchmark"
	@echo "    ./bench_prims      — Cryptographic Primitives Benchmark"
	@echo "═══════════════════════════════════════════════════════"

server: server.o $(ALL_COMMON)
	$(CC) -o $@ $^ $(LDFLAGS)

bench_e2e: bench_e2e.o client.o $(ALL_COMMON)
	$(CC) -o $@ $^ $(LDFLAGS)

benchmark_suite: benchmark_suite.o $(ALL_COMMON)
	$(CC) -o $@ $^ $(LDFLAGS)

bench_level5: bench_level5.o $(ALL_COMMON)
	$(CC) -o $@ $^ $(LDFLAGS)

bench_level5_demo: bench_level5_demo.o $(ALL_COMMON)
	$(CC) -o $@ $^ $(LDFLAGS)

bench_prims: bench_prims.o
	$(CC) -o $@ $^ $(LDFLAGS)

clean:
	rm -f server bench_e2e benchmark_suite bench_level5 bench_level5_demo bench_prims
	rm -f *.o src/*.o $(BLAKE3_DIR)/*.o $(CJSON_DIR)/*.o
	rm -f host_profile.json benchmark_results.json e2e_benchmark_results.json
	rm -f benchmark_output.log e2e_output.log server.log
	@echo "Cleaned."
