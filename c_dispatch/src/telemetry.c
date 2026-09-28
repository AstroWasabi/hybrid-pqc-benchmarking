/* c_dispatch/src/telemetry.c
 * Phase 1: Boot-Time Hardware Profiler
 *
 * Runs exactly once at application startup.
 * Detects hypervisor via /sys/class/dmi/id/sys_vendor (DMI) with fallback
 * to /proc/cpuinfo 'hypervisor' flag.  Counts logical cores via sysconf.
 * Exports state to host_profile.json using plain fprintf (no cJSON).
 */

#include "../include/telemetry.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <strings.h>
#include <unistd.h>
#include <time.h>

/* -----------------------------------------------------------------------
 * Singleton storage
 * ----------------------------------------------------------------------- */

static HostProfile g_host_profile;
static int         g_initialized = 0;

/* -----------------------------------------------------------------------
 * Known hypervisor vendor strings
 * Matched case-insensitively against /sys/class/dmi/id/sys_vendor
 * ----------------------------------------------------------------------- */

static const char *VM_VENDORS[] = {
    "QEMU",
    "Amazon EC2",
    "Microsoft Corporation",
    "VMware",
    "Xen",
    "Google",
    "KVM",
    "innotek GmbH",          /* VirtualBox */
    "Parallels",
    "DigitalOcean",
    "Alibaba Cloud",
    "Hetzner",
    NULL
};

/* -----------------------------------------------------------------------
 * Hypervisor detection
 * ----------------------------------------------------------------------- */

static int detect_hypervisor(char *vendor_buf, size_t buf_len)
{
    /*
     * Primary: read the DMI sys_vendor string.
     * This is the canonical way to detect virtualisation on Linux
     * without requiring root-only CPUID leaf 0x40000000 decoding.
     */
    FILE *fp = fopen("/sys/class/dmi/id/sys_vendor", "r");
    if (fp) {
        if (fgets(vendor_buf, (int)buf_len, fp)) {
            /* Strip trailing newline */
            size_t len = strlen(vendor_buf);
            if (len > 0 && vendor_buf[len - 1] == '\n')
                vendor_buf[len - 1] = '\0';
        } else {
            snprintf(vendor_buf, buf_len, "Unknown");
        }
        fclose(fp);

        /* Match against known hypervisor vendors */
        for (int i = 0; VM_VENDORS[i] != NULL; i++) {
            if (strcasestr(vendor_buf, VM_VENDORS[i]))
                return 1;
        }
        return 0;
    }

    /*
     * Fallback: scan /proc/cpuinfo for the 'hypervisor' CPU flag.
     * This flag is set by the hypervisor itself via CPUID and is
     * readable without elevated privileges.
     */
    fp = fopen("/proc/cpuinfo", "r");
    if (fp) {
        char line[512];
        while (fgets(line, sizeof(line), fp)) {
            if (strstr(line, "flags") && strstr(line, "hypervisor")) {
                fclose(fp);
                snprintf(vendor_buf, buf_len,
                         "Unknown Hypervisor (cpuinfo flag)");
                return 1;
            }
        }
        fclose(fp);
    }

    snprintf(vendor_buf, buf_len, "Bare Metal (DMI unavailable)");
    return 0;
}

/* -----------------------------------------------------------------------
 * Public API
 * ----------------------------------------------------------------------- */

int host_profile_init(void)
{
    if (g_initialized)
        return 0;   /* Idempotent — run exactly once */

    memset(&g_host_profile, 0, sizeof(g_host_profile));

    /* ── Hostname ── */
    if (gethostname(g_host_profile.hostname,
                    sizeof(g_host_profile.hostname)) != 0)
        snprintf(g_host_profile.hostname,
                 sizeof(g_host_profile.hostname), "unknown");

    /* ── Hypervisor Detection ── */
    g_host_profile.is_virtualized = detect_hypervisor(
        g_host_profile.sys_vendor, sizeof(g_host_profile.sys_vendor));

    /* ── Logical CPU Core Count ── */
    g_host_profile.logical_cores = (int)sysconf(_SC_NPROCESSORS_ONLN);
    if (g_host_profile.logical_cores < 1)
        g_host_profile.logical_cores = 1;

    /* ── Boot Timestamp (ISO 8601) ── */
    time_t now = time(NULL);
    struct tm *tm_info = localtime(&now);
    strftime(g_host_profile.boot_timestamp,
             sizeof(g_host_profile.boot_timestamp),
             "%Y-%m-%dT%H:%M:%S%z", tm_info);

    g_initialized = 1;
    return 0;
}

const HostProfile *get_host_profile(void)
{
    return &g_host_profile;
}

int host_profile_export_json(const char *filepath)
{
    if (!g_initialized)
        return -1;

    FILE *fp = fopen(filepath, "w");
    if (!fp) {
        perror("host_profile_export_json: fopen");
        return -1;
    }

    /*
     * Hand-formatted JSON via fprintf — no external JSON library.
     * All string values are assumed safe (no user-controlled escaping needed).
     */
    fprintf(fp, "{\n");
    fprintf(fp, "  \"hostname\": \"%s\",\n",
            g_host_profile.hostname);
    fprintf(fp, "  \"sys_vendor\": \"%s\",\n",
            g_host_profile.sys_vendor);
    fprintf(fp, "  \"is_virtualized\": %s,\n",
            g_host_profile.is_virtualized ? "true" : "false");
    fprintf(fp, "  \"logical_cores\": %d,\n",
            g_host_profile.logical_cores);
    fprintf(fp, "  \"boot_timestamp\": \"%s\"\n",
            g_host_profile.boot_timestamp);
    fprintf(fp, "}\n");

    fclose(fp);
    return 0;
}
