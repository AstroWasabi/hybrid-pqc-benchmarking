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

typedef struct {
    double mean;
    double p50;
    double p95;
    double p99;
} Stats;

static Stats compute_stats(double *times, int count) {
    qsort(times, count, sizeof(double), cmp_double);
    double sum = 0.0;
    for (int i = 0; i < count; i++) sum += times[i];
    return (Stats){
        .mean = sum / count,
        .p50  = times[count / 2],
        .p95  = times[(int)(count * 0.95)],
        .p99  = times[(int)(count * 0.99)]
    };
}

int main(void)
{
    host_profile_init();
    host_profile_export_json("host_profile.json");
    if (engine_init() != 0) {
        fprintf(stderr, "Failed to initialize crypto engine\n");
        return 1;
    }

    printf("\n═══════════════════════════════════════════════════════════════════════════════\n");
    printf("   Adaptive Dispatch Runtime — High-Security & Mixed-Workload Benchmark\n");
    printf("═══════════════════════════════════════════════════════════════════════════════\n");

    /* Define security tiers from fast (Level 1) to ultra-heavy (Level 5) */
    const AlgoCombo suites[] = {
        {
            .id              = 1,
            .label           = "Tier 1: X25519 + ML-KEM-768 (Lightweight L1)",
            .profile         = PROFILE_HYBRID,
            .classical_curve = CURVE_X25519,
            .pqc_alg         = PQC_MLKEM_768,
            .pqc_name        = "ML-KEM-768",
            .info            = "Tier1-L1"
        },
        {
            .id              = 2,
            .label           = "Tier 2: SecP256r1 + ML-KEM-768 (Standard L3)",
            .profile         = PROFILE_HYBRID,
            .classical_curve = CURVE_P256,
            .pqc_alg         = PQC_MLKEM_768,
            .pqc_name        = "ML-KEM-768",
            .info            = "Tier2-L3"
        },
        {
            .id              = 3,
            .label           = "Tier 3: SecP384r1 + ML-KEM-1024 (CNSA 2.0 L5)",
            .profile         = PROFILE_HYBRID,
            .classical_curve = CURVE_P384,
            .pqc_alg         = PQC_MLKEM_1024,
            .pqc_name        = "ML-KEM-1024",
            .info            = "Tier3-L5"
        },
        {
            .id              = 4,
            .label           = "Tier 4: SecP384r1 + FrodoKEM-1344-AES (Conservative L5)",
            .profile         = PROFILE_HYBRID,
            .classical_curve = CURVE_P384,
            .pqc_alg         = 99,
            .pqc_name        = "FrodoKEM-1344-AES",
            .info            = "Tier4-Frodo"
        },
        {
            .id              = 5,
            .label           = "Tier 5: SecP384r1 + BIKE-L5 (Code-Based L5)",
            .profile         = PROFILE_HYBRID,
            .classical_curve = CURVE_P384,
            .pqc_alg         = 98,
            .pqc_name        = "BIKE-L5",
            .info            = "Tier5-BIKE"
        }
    };

    int n_suites = sizeof(suites) / sizeof(suites[0]);
    int iters = 200;
    double *times = malloc(iters * sizeof(double));

    printf("\n### Section 1: Per-Suite Latency Profile (Sequential vs Parallel vs Adaptive)\n\n");

    for (int s = 0; s < n_suites; s++) {
        const AlgoCombo *combo = &suites[s];
        DispatchRoute chosen_route = adaptive_dispatch(combo);

        printf("─── %s ───\n", combo->label);
        printf("  [Adaptive Router Decision: %s]\n", route_name(chosen_route));

        for (int mode = 0; mode < 3; mode++) {
            const char *mode_name = (mode == 0) ? "Strict_Sequential" :
                                    (mode == 1) ? "Strict_Parallel"   : "Adaptive_Switch";

            for (int i = 0; i < iters; i++) {
                SharedCryptoResult res;
                struct timespec t0, t1;
                clock_gettime(CLOCK_MONOTONIC, &t0);

                if (mode == 0)
                    execute_sequential(combo, ROLE_SERVER, &res);
                else if (mode == 1)
                    execute_parallel_optimized(combo, ROLE_SERVER, &res);
                else
                    dispatch_execute(combo, ROLE_SERVER, &res);

                clock_gettime(CLOCK_MONOTONIC, &t1);
                times[i] = ts_diff_ms(t0, t1);
            }

            Stats st = compute_stats(times, iters);
            printf("  %-18s | Mean: %6.3f ms | p50: %6.3f ms | p95: %6.3f ms | p99: %6.3f ms\n",
                   mode_name, st.mean, st.p50, st.p95, st.p99);
        }
        printf("\n");
    }

    /* ═══════════════════════════════════════════════════════════════════
     * Section 2: Simulated Real-World Mixed-Traffic Gateway
     * 1000 incoming handshakes:
     *   40% Tier 1 (X25519 + ML-KEM-768)
     *   30% Tier 2 (P256 + ML-KEM-768)
     *   20% Tier 3 (P384 + ML-KEM-1024)
     *   10% Tier 4 (P384 + FrodoKEM-1344)
     * ═══════════════════════════════════════════════════════════════════ */

    printf("═══════════════════════════════════════════════════════════════════════════════\n");
    printf("   Section 2: Realistic Mixed-Traffic Gateway Simulation (1,000 Handshakes)\n");
    printf("   Distribution: 40%% Tier 1 (Fast), 30%% Tier 2, 20%% Tier 3, 10%% Tier 4 (Heavy)\n");
    printf("═══════════════════════════════════════════════════════════════════════════════\n\n");

    int mixed_total = 1000;
    int *workload = malloc(mixed_total * sizeof(int));
    srand(42);
    for (int i = 0; i < mixed_total; i++) {
        int r = rand() % 100;
        if (r < 40)      workload[i] = 0; /* Tier 1 */
        else if (r < 70) workload[i] = 1; /* Tier 2 */
        else if (r < 90) workload[i] = 2; /* Tier 3 */
        else             workload[i] = 3; /* Tier 4 */
    }

    double *mixed_times = malloc(mixed_total * sizeof(double));

    for (int mode = 0; mode < 3; mode++) {
        const char *policy_label = (mode == 0) ? "Policy A: Always Sequential (Traditional TLS)" :
                                   (mode == 1) ? "Policy B: Always Parallel   (Naive Multi-thread)" :
                                                 "Policy C: Adaptive Switch   (Dynamic Runtime)";

        struct timespec w0, w1;
        clock_gettime(CLOCK_MONOTONIC, &w0);

        for (int i = 0; i < mixed_total; i++) {
            const AlgoCombo *combo = &suites[workload[i]];
            SharedCryptoResult res;
            struct timespec t0, t1;
            clock_gettime(CLOCK_MONOTONIC, &t0);

            if (mode == 0)
                execute_sequential(combo, ROLE_SERVER, &res);
            else if (mode == 1)
                execute_parallel_optimized(combo, ROLE_SERVER, &res);
            else
                dispatch_execute(combo, ROLE_SERVER, &res);

            clock_gettime(CLOCK_MONOTONIC, &t1);
            mixed_times[i] = ts_diff_ms(t0, t1);
        }

        clock_gettime(CLOCK_MONOTONIC, &w1);
        double total_wall_ms = ts_diff_ms(w0, w1);
        Stats st = compute_stats(mixed_times, mixed_total);

        printf("%s\n", policy_label);
        printf("  Total Gateway Time: %8.2f ms\n", total_wall_ms);
        printf("  Mean Handshake Latency: %6.3f ms\n", st.mean);
        printf("  p50: %6.3f ms | p95: %6.3f ms | p99: %6.3f ms\n\n", st.p50, st.p95, st.p99);
    }

    free(times);
    free(workload);
    free(mixed_times);
    engine_shutdown();
    return 0;
}
