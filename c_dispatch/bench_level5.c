#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <unistd.h>
#include <oqs/oqs.h>
#include <openssl/evp.h>
#include <openssl/ec.h>
#include <openssl/obj_mac.h>
#include "include/engine.h"
#include "include/dispatcher.h"
#include "include/telemetry.h"

static double ts_diff_ms(struct timespec a, struct timespec b) {
    return (b.tv_sec - a.tv_sec) * 1000.0 + (b.tv_nsec - a.tv_nsec) / 1000000.0;
}

static int cmp_double(const void *a, const void *b) {
    double da = *(const double *)a, db = *(const double *)b;
    return (da > db) - (da < db);
}

int main() {
    boot_hardware_profiler("host_profile.json");
    engine_init();

    printf("\n═══════════════════════════════════════════════════════════════\n");
    printf("  High-Security Level 5 Hybrid Benchmark: Sequential vs Parallel\n");
    printf("═══════════════════════════════════════════════════════════════\n");

    const AlgoCombo level5_combos[] = {
        {
            .combo_id        = 101,
            .profile         = PROFILE_HYBRID,
            .classical_curve = CURVE_P384,
            .pqc_name        = "ML-KEM-1024",
            .display_name    = "Hybrid: SecP384r1 + ML-KEM-1024 (NIST Level 5)"
        },
        {
            .combo_id        = 102,
            .profile         = PROFILE_HYBRID,
            .classical_curve = CURVE_P521,
            .pqc_name        = "ML-KEM-1024",
            .display_name    = "Hybrid: SecP521r1 + ML-KEM-1024 (NIST Level 5)"
        },
        {
            .combo_id        = 103,
            .profile         = PROFILE_HYBRID,
            .classical_curve = CURVE_P521,
            .pqc_name        = "FrodoKEM-1344-AES",
            .display_name    = "Hybrid: SecP521r1 + FrodoKEM-1344-AES (Conservative L5)"
        }
    };

    int n_combos = sizeof(level5_combos) / sizeof(level5_combos[0]);
    int runs = 500;
    double *times = malloc(runs * sizeof(double));

    for (int c = 0; c < n_combos; c++) {
        const AlgoCombo *combo = &level5_combos[c];
        printf("\n─── %s ───\n", combo->display_name);

        for (int m = 0; m < 3; m++) {
            const char *mode_name = (m == 0) ? "Strict_Sequential" :
                                    (m == 1) ? "Strict_Parallel"   : "Adaptive_Switch";

            double sum = 0.0;
            for (int r = 0; r < runs; r++) {
                SharedCryptoResult res;
                struct timespec t0, t1;
                clock_gettime(CLOCK_MONOTONIC, &t0);

                if (m == 0) {
                    execute_sequential(combo, &res);
                } else if (m == 1) {
                    execute_parallel(combo, &res);
                } else {
                    dispatch_execute(combo, &res);
                }

                clock_gettime(CLOCK_MONOTONIC, &t1);
                times[r] = ts_diff_ms(t0, t1);
                sum += times[r];
                crypto_result_free(&res);
            }

            qsort(times, runs, sizeof(double), cmp_double);
            double mean = sum / runs;
            double p50  = times[runs / 2];
            double p95  = times[(int)(runs * 0.95)];
            double p99  = times[(int)(runs * 0.99)];

            printf("  [%-17s] Mean: %6.3f ms | p50: %6.3f ms | p95: %6.3f ms | p99: %6.3f ms\n",
                   mode_name, mean, p50, p95, p99);
        }
    }

    free(times);
    engine_shutdown();
    return 0;
}
