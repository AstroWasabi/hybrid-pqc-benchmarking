# c/Makefile
# Build system for the Native C PQC benchmarking framework.
#
# Targets:
#   all             — build all executables
#   server          — multi-threaded TCP handshake server
#   bench_baselines — baseline benchmark runner
#   bench_hybrid    — hybrid benchmark runner
#   clean           — remove all build artefacts

# Detect or configure liboqs installation path
# Can be overridden via: make LIBOQS_DIR=/path/to/liboqs
LIBOQS_DIR ?= $(wildcard /home/sudoroot/_oqs)
ifeq ($(LIBOQS_DIR),)
  LIBOQS_DIR := $(wildcard /usr/local)
endif
ifeq ($(LIBOQS_DIR),)
  LIBOQS_DIR := /usr
endif

# Detect lib64 vs lib directory
LIBOQS_LIB_DIR := $(wildcard $(LIBOQS_DIR)/lib64)
ifeq ($(LIBOQS_LIB_DIR),)
  LIBOQS_LIB_DIR := $(LIBOQS_DIR)/lib
endif

CC      := gcc
CFLAGS  := -Wall -Wextra -O3 -std=c11 -pthread \
           -I./include \
           -I./cjson \
           -I./blake3 \
           -I$(LIBOQS_DIR)/include

LDFLAGS := -L$(LIBOQS_LIB_DIR) \
           -Wl,-rpath,$(LIBOQS_LIB_DIR) \
           -loqs -lssl -lcrypto -lpthread -lm

.DEFAULT_GOAL := all

# --------------------------------------------------------------------------
# BLAKE3: core + portable (no special flags)
# The SIMD C files each need their own -m<feature> flag.
# The assembly backends are also used for the full dispatch table.
# --------------------------------------------------------------------------
BLAKE3_CORE_SRCS := blake3/blake3.c \
                    blake3/blake3_dispatch.c \
                    blake3/blake3_portable.c

BLAKE3_CORE_OBJS := $(BLAKE3_CORE_SRCS:.c=.o)

blake3/blake3_sse2.o:    blake3/blake3_sse2.c
	$(CC) $(CFLAGS) -msse2 -c $< -o $@

blake3/blake3_sse41.o:   blake3/blake3_sse41.c
	$(CC) $(CFLAGS) -msse4.1 -c $< -o $@

blake3/blake3_avx2.o:    blake3/blake3_avx2.c
	$(CC) $(CFLAGS) -mavx2 -c $< -o $@

blake3/blake3_avx512.o:  blake3/blake3_avx512.c
	$(CC) $(CFLAGS) -mavx512f -mavx512vl -c $< -o $@

BLAKE3_SIMD_OBJS := blake3/blake3_sse2.o \
                    blake3/blake3_sse41.o \
                    blake3/blake3_avx2.o \
                    blake3/blake3_avx512.o

BLAKE3_OBJS := $(BLAKE3_CORE_OBJS) $(BLAKE3_SIMD_OBJS)

# --------------------------------------------------------------------------
# cJSON
# --------------------------------------------------------------------------
CJSON_SRCS  := cjson/cJSON.c
CJSON_OBJS  := $(CJSON_SRCS:.c=.o)

# --------------------------------------------------------------------------
# Core library
# --------------------------------------------------------------------------
LIB_SRCS    := src/crypto_engine.c \
               src/network_utils.c \
               src/metrics.c \
               src/hw_telemetry.c
LIB_OBJS    := $(LIB_SRCS:.c=.o)

# client.c provides execute_handshake() — shared by both bench targets
CLIENT_SRC  := client.c
CLIENT_OBJ  := client.o

# --------------------------------------------------------------------------
# Generic compile rule
# --------------------------------------------------------------------------
%.o: %.c
	$(CC) $(CFLAGS) -c $< -o $@

# --------------------------------------------------------------------------
# Targets
# --------------------------------------------------------------------------
.PHONY: all clean

ALL_COMMON_OBJS := $(LIB_OBJS) $(BLAKE3_OBJS) $(CJSON_OBJS)

all: server bench_baselines bench_hybrid

server: server.o $(ALL_COMMON_OBJS)
	$(CC) -o $@ $^ $(LDFLAGS)

bench_baselines: bench_baselines.o $(CLIENT_OBJ) $(ALL_COMMON_OBJS)
	$(CC) -o $@ $^ $(LDFLAGS)

bench_hybrid: bench_hybrid.o $(CLIENT_OBJ) $(ALL_COMMON_OBJS)
	$(CC) -o $@ $^ $(LDFLAGS)

clean:
	rm -f server bench_baselines bench_hybrid \
	      *.o src/*.o blake3/*.o cjson/*.o
