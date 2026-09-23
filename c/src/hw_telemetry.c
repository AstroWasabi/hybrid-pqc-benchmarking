/* c/src/hw_telemetry.c
 * Implementation of zero-overhead PMU and OS counter collection via
 * perf_event_open.
 */

#define _GNU_SOURCE
#include "../include/hw_telemetry.h"

#include <errno.h>
#include <linux/perf_event.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/ioctl.h>
#include <sys/syscall.h>
#include <unistd.h>

static inline int perf_event_open_sys(struct perf_event_attr *hw_event,
                                      pid_t pid, int cpu, int group_fd,
                                      unsigned long flags) {
  return (int)syscall(__NR_perf_event_open, hw_event, pid, cpu, group_fd,
                      flags);
}

static int open_single_counter(uint32_t type, uint64_t config) {
  struct perf_event_attr pe;
  memset(&pe, 0, sizeof(pe));
  pe.type = type;
  pe.size = sizeof(pe);
  pe.config = config;
  pe.disabled = 1;
  pe.exclude_kernel = 1;
  pe.exclude_hv = 1;

  /* Measure calling thread (pid = 0) on any CPU (cpu = -1) */
  return perf_event_open_sys(&pe, 0, -1, -1, 0);
}

int hw_telemetry_init(HWTelemetrySession *sess) {
  if (!sess)
    return -1;
  memset(sess, 0, sizeof(*sess));

  sess->fd_cycles =
      open_single_counter(PERF_TYPE_HARDWARE, PERF_COUNT_HW_CPU_CYCLES);
  sess->fd_instructions =
      open_single_counter(PERF_TYPE_HARDWARE, PERF_COUNT_HW_INSTRUCTIONS);

  /* L1 Data Cache Read Misses */
  sess->fd_l1_miss = open_single_counter(
      PERF_TYPE_HW_CACHE, PERF_COUNT_HW_CACHE_L1D |
                              (PERF_COUNT_HW_CACHE_OP_READ << 8) |
                              (PERF_COUNT_HW_CACHE_RESULT_MISS << 16));

  /* L2 / Last-Level Cache Read Misses (fallback to general CACHE_MISSES if
   * needed) */
  sess->fd_l2_miss = open_single_counter(
      PERF_TYPE_HW_CACHE, PERF_COUNT_HW_CACHE_LL |
                              (PERF_COUNT_HW_CACHE_OP_READ << 8) |
                              (PERF_COUNT_HW_CACHE_RESULT_MISS << 16));
  if (sess->fd_l2_miss < 0) {
    sess->fd_l2_miss =
        open_single_counter(PERF_TYPE_HARDWARE, PERF_COUNT_HW_CACHE_MISSES);
  }

  /* Software OS events */
  sess->fd_context_switches =
      open_single_counter(PERF_TYPE_SOFTWARE, PERF_COUNT_SW_CONTEXT_SWITCHES);
  sess->fd_cpu_migrations =
      open_single_counter(PERF_TYPE_SOFTWARE, PERF_COUNT_SW_CPU_MIGRATIONS);
  sess->fd_page_faults =
      open_single_counter(PERF_TYPE_SOFTWARE, PERF_COUNT_SW_PAGE_FAULTS);

  sess->is_active = 1;
  return 0;
}

void hw_telemetry_start(HWTelemetrySession *sess) {
  if (!sess || !sess->is_active)
    return;

  if (sess->fd_cycles >= 0) {
    ioctl(sess->fd_cycles, PERF_EVENT_IOC_RESET, 0);
    ioctl(sess->fd_cycles, PERF_EVENT_IOC_ENABLE, 0);
  }
  if (sess->fd_instructions >= 0) {
    ioctl(sess->fd_instructions, PERF_EVENT_IOC_RESET, 0);
    ioctl(sess->fd_instructions, PERF_EVENT_IOC_ENABLE, 0);
  }
  if (sess->fd_l1_miss >= 0) {
    ioctl(sess->fd_l1_miss, PERF_EVENT_IOC_RESET, 0);
    ioctl(sess->fd_l1_miss, PERF_EVENT_IOC_ENABLE, 0);
  }
  if (sess->fd_l2_miss >= 0) {
    ioctl(sess->fd_l2_miss, PERF_EVENT_IOC_RESET, 0);
    ioctl(sess->fd_l2_miss, PERF_EVENT_IOC_ENABLE, 0);
  }
  if (sess->fd_context_switches >= 0) {
    ioctl(sess->fd_context_switches, PERF_EVENT_IOC_RESET, 0);
    ioctl(sess->fd_context_switches, PERF_EVENT_IOC_ENABLE, 0);
  }
  if (sess->fd_cpu_migrations >= 0) {
    ioctl(sess->fd_cpu_migrations, PERF_EVENT_IOC_RESET, 0);
    ioctl(sess->fd_cpu_migrations, PERF_EVENT_IOC_ENABLE, 0);
  }
  if (sess->fd_page_faults >= 0) {
    ioctl(sess->fd_page_faults, PERF_EVENT_IOC_RESET, 0);
    ioctl(sess->fd_page_faults, PERF_EVENT_IOC_ENABLE, 0);
  }
}

void hw_telemetry_stop(HWTelemetrySession *sess, HWTelemetryResult *res) {
  if (!sess || !res)
    return;
  memset(res, 0, sizeof(*res));

  if (sess->fd_cycles >= 0) {
    ioctl(sess->fd_cycles, PERF_EVENT_IOC_DISABLE, 0);
    read(sess->fd_cycles, &res->cpu_cycles, sizeof(res->cpu_cycles));
  }
  if (sess->fd_instructions >= 0) {
    ioctl(sess->fd_instructions, PERF_EVENT_IOC_DISABLE, 0);
    read(sess->fd_instructions, &res->instructions, sizeof(res->instructions));
  }
  if (sess->fd_l1_miss >= 0) {
    ioctl(sess->fd_l1_miss, PERF_EVENT_IOC_DISABLE, 0);
    read(sess->fd_l1_miss, &res->l1_cache_misses, sizeof(res->l1_cache_misses));
  }
  if (sess->fd_l2_miss >= 0) {
    ioctl(sess->fd_l2_miss, PERF_EVENT_IOC_DISABLE, 0);
    read(sess->fd_l2_miss, &res->l2_cache_misses, sizeof(res->l2_cache_misses));
  }
  if (sess->fd_context_switches >= 0) {
    ioctl(sess->fd_context_switches, PERF_EVENT_IOC_DISABLE, 0);
    read(sess->fd_context_switches, &res->context_switches,
         sizeof(res->context_switches));
  }
  if (sess->fd_cpu_migrations >= 0) {
    ioctl(sess->fd_cpu_migrations, PERF_EVENT_IOC_DISABLE, 0);
    read(sess->fd_cpu_migrations, &res->cpu_migrations,
         sizeof(res->cpu_migrations));
  }
  if (sess->fd_page_faults >= 0) {
    ioctl(sess->fd_page_faults, PERF_EVENT_IOC_DISABLE, 0);
    read(sess->fd_page_faults, &res->page_faults, sizeof(res->page_faults));
  }

  res->ipc = (res->cpu_cycles > 0)
                 ? ((double)res->instructions / (double)res->cpu_cycles)
                 : 0.0;
}

void hw_telemetry_cleanup(HWTelemetrySession *sess) {
  if (!sess)
    return;
  if (sess->fd_cycles >= 0)
    close(sess->fd_cycles);
  if (sess->fd_instructions >= 0)
    close(sess->fd_instructions);
  if (sess->fd_l1_miss >= 0)
    close(sess->fd_l1_miss);
  if (sess->fd_l2_miss >= 0)
    close(sess->fd_l2_miss);
  if (sess->fd_context_switches >= 0)
    close(sess->fd_context_switches);
  if (sess->fd_cpu_migrations >= 0)
    close(sess->fd_cpu_migrations);
  if (sess->fd_page_faults >= 0)
    close(sess->fd_page_faults);
  memset(sess, 0, sizeof(*sess));
}
