#ifndef _GNU_SOURCE
#define _GNU_SOURCE
#endif

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
#include "include/algo_config.h"

static double ts_diff_ms(struct timespec a, struct timespec b) {
    return (b.tv_sec - a.tv_sec) * 1000.0 + (b.tv_nsec - a.tv_nsec) / 1000000.0;
}

static int cmp_double(const void *a, const void *b) {
    double da = *(const double *)a, db = *(const double *)b;
    return (da > db) - (da < db);
}

int main(void) {
    host_profile_init();
    host_profile_export_json("host_profile.json");
    if (engine_init() != 0) {
        fprintf(stderr, "Failed to initialize crypto engine\n");
        return 1;
    }

    printf("\n═══════════════════════════════════════════════════════════════\n");
    printf("  High-Security Level 5 Hybrid Benchmark: Sequential vs Parallel\n");
    printf("═══════════════════════════════════════════════════════════════\n");

    const AlgoCombo level5_combos[] = {
        {
            .id              = 101,
            .label           = "Hybrid: SecP384r1 + ML-KEM-1024 (NIST Level 5)",
            .profile         = PROFILE_HYBRID,
            .classical_curve = CURVE_P384,
            .pqc_alg         = PQC_MLKEM_1024,
            .pqc_name        = OQS_MLKEM_1024_NAME,
            .info            = "L5-P384-MLKEM1024"
        },
        {
            .id              = 102,
            .label           = "Hybrid: SecP384r1 + FrodoKEM-1344-AES (Conservative L5)",
            .profile         = PROFILE_HYBRID,
            .classical_curve = CURVE_P384,
            .pqc_alg         = PQC_FRODOKEM_1344,
            .pqc_name        = OQS_FRODOKEM_1344_NAME,
            .info            = "L5-P384-Frodo1344"
        },
        {
            .id              = 103,
            .label           = "Hybrid: SecP384r1 + BIKE-L5 (Code-Based L5)",
            .profile         = PROFILE_HYBRID,
            .classical_curve = CURVE_P384,
            .pqc_alg         = PQC_BIKE_L5,
            .pqc_name        = OQS_BIKE_L5_NAME,
            .info            = "L5-P384-BIKEL5"
        }
    };

    int n_combos = sizeof(level5_combos) / sizeof(level5_combos[0]);
    int runs = 500;
    double *times = malloc(runs * sizeof(double));
    if (!times) {
        fprintf(stderr, "Failed to allocate memory for benchmark times\n");
        engine_shutdown();
        return 1;
    }

    for (int c = 0; c < n_combos; c++) {
        const AlgoCombo *combo = &level5_combos[c];
        printf("\n─── %s ───\n", combo->label);

        for (int m = 0; m < 3; m++) {
            const char *mode_name = (m == 0) ? "Strict_Sequential" :
                                    (m == 1) ? "Strict_Parallel"   : "Adaptive_Switch";

            double sum = 0.0;
            for (int r = 0; r < runs; r++) {
                SharedCryptoResult res;
                struct timespec t0, t1;
                clock_gettime(CLOCK_MONOTONIC, &t0);

                if (m == 0) {
                    execute_sequential(combo, ROLE_SERVER, &res);
                } else if (m == 1) {
                    execute_parallel_optimized(combo, ROLE_SERVER, &res);
                } else {
                    dispatch_execute(combo, ROLE_SERVER, &res);
                }

                clock_gettime(CLOCK_MONOTONIC, &t1);
                times[r] = ts_diff_ms(t0, t1);
                sum += times[r];
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
