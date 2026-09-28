/* c_dispatch/include/telemetry.h
 * Phase 1: Boot-Time Hardware Profiler
 *
 * Detects hypervisor presence, logical CPU core count, and exports
 * the host profile to JSON via fprintf (zero external dependencies).
 * The global HostProfile struct provides zero-allocation access
 * during TLS 1.3 handshakes.
 */

#ifndef TELEMETRY_H
#define TELEMETRY_H

#include <stdint.h>

/* -----------------------------------------------------------------------
 * Host Profile — singleton, populated once at boot
 * ----------------------------------------------------------------------- */

typedef struct {
    char     hostname[256];       /* System hostname                       */
    char     sys_vendor[256];     /* DMI sys_vendor string                 */
    int      is_virtualized;      /* 1 = hypervisor detected, 0 = bare-metal */
    int      logical_cores;       /* sysconf(_SC_NPROCESSORS_ONLN)         */
    char     boot_timestamp[64];  /* ISO 8601 init timestamp               */
} HostProfile;

/* -----------------------------------------------------------------------
 * Public API
 * ----------------------------------------------------------------------- */

/**
 * Initialize the global host profile (idempotent — runs exactly once).
 * Reads /sys/class/dmi/id/sys_vendor for hypervisor detection,
 * falls back to /proc/cpuinfo 'hypervisor' flag if DMI unavailable.
 *
 * @returns  0 on success
 */
int host_profile_init(void);

/**
 * Return a const pointer to the global HostProfile.
 * Valid only after host_profile_init() has been called.
 * Zero-allocation: returns address of static storage.
 */
const HostProfile *get_host_profile(void);

/**
 * Export the current host profile to a JSON file using fprintf.
 * No cJSON or external JSON library dependency.
 *
 * @param filepath  Output path (e.g. "host_profile.json")
 * @returns         0 on success, -1 on failure
 */
int host_profile_export_json(const char *filepath);

#endif /* TELEMETRY_H */
