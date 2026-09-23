/* c/include/hw_telemetry.h
 * Hardware Performance Counters & OS Telemetry Profiler
 * Utilises Linux perf_event_open subsystem for user-space thread
 * instrumentation.
 *
 * Metrics:
 *   - CPU Cycles
 *   - Instructions
 *   - IPC (Instructions Per Cycle)
 *   - L1 Cache Misses (L1 Data Read Misses)
 *   - L2 / LLC Cache Misses
 *   - Context Switches
 *   - CPU Migrations
 *   - Page Faults
 */

#ifndef HW_TELEMETRY_H
#define HW_TELEMETRY_H

#include <stddef.h>
#include <stdint.h>

typedef struct {
  uint64_t cpu_cycles;
  uint64_t instructions;
  double ipc;
  uint64_t l1_cache_misses;
  uint64_t l2_cache_misses;
  uint64_t context_switches;
  uint64_t cpu_migrations;
  uint64_t page_faults;
} HWTelemetryResult;

typedef struct {
  int fd_cycles;
  int fd_instructions;
  int fd_l1_miss;
  int fd_l2_miss;
  int fd_context_switches;
  int fd_cpu_migrations;
  int fd_page_faults;
  int is_active;
} HWTelemetrySession;

/* Initialize hardware counter file descriptors for calling thread/process */
int hw_telemetry_init(HWTelemetrySession *sess);

/* Reset and enable counters */
void hw_telemetry_start(HWTelemetrySession *sess);

/* Disable counters, read values into result, calculate IPC */
void hw_telemetry_stop(HWTelemetrySession *sess, HWTelemetryResult *res);

/* Close all open perf event descriptors */
void hw_telemetry_cleanup(HWTelemetrySession *sess);

#endif /* HW_TELEMETRY_H */
