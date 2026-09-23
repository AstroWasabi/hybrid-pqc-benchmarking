/* c/bench_baselines.c
 * Baseline benchmarking for pure-classical and pure-quantum algorithm profiles.
 * Mirrors bench_baselines.py exactly:
 *   - 1,000 runs per profile
 *   - Discards iteration 0 (cold-start)
 *   - Computes steady-state cost & jitter table
 *   - Outputs baseline_matrix_weights.json (same schema as Python)
 *
 * Usage: ./bench_baselines [--host <ip>] [--runs <N>]
 */

#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <math.h>

#include "include/algo_config.h"
#include "include/metrics.h"
#include "cjson/cJSON.h"

/* External from client.c (shared translation unit via linker) */
double execute_handshake(const char *host, const AlgoCombo *combo,
                         const char *kdf_type);

/* -----------------------------------------------------------------------
 * Defaults
 * ----------------------------------------------------------------------- */
static const char *g_host     = "127.0.0.1";
static int         g_num_runs = 1000;

/* -----------------------------------------------------------------------
 * Parse simple CLI arguments
 * ----------------------------------------------------------------------- */
static void parse_args(int argc, char *argv[])
{
    for (int i = 1; i < argc; i++) {
        if (strcmp(argv[i], "--host") == 0 && i + 1 < argc)
            g_host = argv[++i];
        else if (strcmp(argv[i], "--runs") == 0 && i + 1 < argc)
            g_num_runs = atoi(argv[++i]);
    }
}

/* -----------------------------------------------------------------------
 * Main
 * ----------------------------------------------------------------------- */
int main(int argc, char *argv[])
{
    parse_args(argc, argv);

    printf("=== Native C Control Baselines Pipeline (%d runs per profile) ===\n",
           g_num_runs);
    printf("[*] Server: %s:%d\n\n", g_host, 4444);

    /* Training data: will become baseline_matrix_weights.json */
    cJSON *weights_json = cJSON_CreateObject();

    /* Table rows for summary print */
    typedef struct { char algo_key[64]; char label[128]; double stable_cost; double sd; } Row;
    Row rows[NUM_ALGO_COMBOS];
    int num_rows = 0;

    double *run_buf = malloc(sizeof(double) * (size_t)g_num_runs);
    if (!run_buf) { fprintf(stderr, "OOM\n"); return 1; }

    for (int ci = 0; ci < NUM_ALGO_COMBOS; ci++) {
        const AlgoCombo *combo = &ALGORITHM_COMBOS[ci];

        /* Only process pure_classical and pure_quantum profiles */
        if (combo->profile != PROFILE_PURE_CLASSICAL &&
            combo->profile != PROFILE_PURE_QUANTUM) continue;

        printf("[*] Profiling baseline: %s...\n", combo->label);

        int ok_runs = 0;
        for (int r = 0; r < g_num_runs; r++) {
            double ms = execute_handshake(g_host, combo, "sha256");
            if (ms < 0.0) {
                fprintf(stderr, " [!] Handshake failed on run %d — aborting profile.\n", r);
                goto next_combo;
            }
            run_buf[r] = ms;
            ok_runs++;
        }

        {
            double stable = metrics_stable_cost(run_buf, ok_runs);
            double sd     = metrics_stddev(run_buf + 1, ok_runs - 1);

            printf("    -> Complete. Steady-State Cost: %.3f ms | Max Jitter: %.3f ms\n",
                   stable, sd);

            /* Build JSON weight entry */
            const char *algo_key = (combo->profile == PROFILE_PURE_CLASSICAL)
                ? curve_name_str(combo->classical_curve)
                : combo->pqc_name;

            cJSON *entry = cJSON_CreateObject();
            cJSON_AddStringToObject(entry, "label",          combo->label);
            cJSON_AddStringToObject(entry, "profile",
                (combo->profile == PROFILE_PURE_CLASSICAL) ? "pure_classical" : "pure_quantum");
            cJSON_AddNumberToObject(entry, "stable_cost_ms", stable);
            cJSON_AddItemToObject(weights_json, algo_key, entry);

            /* Save for table print */
            strncpy(rows[num_rows].algo_key, algo_key, 63);
            strncpy(rows[num_rows].label,    combo->label, 127);
            rows[num_rows].stable_cost = stable;
            rows[num_rows].sd          = sd;
            num_rows++;
        }

    next_combo:;
    }

    free(run_buf);

    /* ---- Save baseline_matrix_weights.json ---- */
    {
        FILE *fp = fopen("baseline_matrix_weights.json", "w");
        if (!fp) { perror("fopen baseline_matrix_weights.json"); return 1; }
        char *json_str = cJSON_Print(weights_json);
        fputs(json_str, fp);
        fclose(fp);
        free(json_str);
        printf("\n[✔] Baseline weights written to: baseline_matrix_weights.json\n");
    }

    cJSON_Delete(weights_json);

    /* ---- Summary table (matches Python format) ---- */
    printf("\n%s\n", "=======================================================");
    printf("%-25s | %-16s | %-10s\n", "Algorithm Baseline", "Stable Cost (ms)", "Jitter (ms)");
    printf("%s\n", "-------------------------------------------------------");
    for (int i = 0; i < num_rows; i++) {
        printf("%-25s | %-16.3f | %-10.3f\n",
               rows[i].algo_key, rows[i].stable_cost, rows[i].sd);
    }
    printf("%s\n", "=======================================================");

    return 0;
}
