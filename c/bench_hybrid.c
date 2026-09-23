/* c/bench_hybrid.c
 * Hybrid algorithm benchmarking runner.
 * Mirrors bench_hybrid.py exactly:
 *   - Loads baseline_matrix_weights.json
 *   - 1,000 runs per hybrid profile × 2 KDF engines (SHA-256, BLAKE3)
 *   - Computes empirical avg, SD jitter, and predictive model drift
 *   - Prints formatted summary tables
 *
 * Usage: ./bench_hybrid [--host <ip>] [--runs <N>]
 */

#define _GNU_SOURCE
#include <math.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "cjson/cJSON.h"
#include "include/algo_config.h"
#include "include/hw_telemetry.h"
#include "include/metrics.h"

/* External from client.c */
double execute_handshake_with_telemetry(const char *host,
                                        const AlgoCombo *combo,
                                        const char *kdf_type,
                                        HWTelemetrySession *telem_sess,
                                        HWTelemetryResult *telem_res);
double execute_handshake(const char *host, const AlgoCombo *combo,
                         const char *kdf_type);

/* -----------------------------------------------------------------------
 * Defaults
 * ----------------------------------------------------------------------- */
static const char *g_host = "127.0.0.1";
static int g_num_runs = 1000;

/* -----------------------------------------------------------------------
 * Predictive cost model — mirrors PredictiveCostModel in
 * telemetry/cost_model.py
 * ----------------------------------------------------------------------- */
typedef struct {
  double x25519_cost;
  double p256_cost;
  double p384_cost;
  double mlkem768_cost;
  double mlkem1024_cost;
  double sha256_kdf_cost;
  double blake3_kdf_cost;
} CostModel;

static double get_classical_cost(const CostModel *m, int curve) {
  switch (curve) {
  case CURVE_X25519:
    return m->x25519_cost;
  case CURVE_P256:
    return m->p256_cost;
  case CURVE_P384:
    return m->p384_cost;
  default:
    return 0.0;
  }
}

static double get_pqc_cost(const CostModel *m, int pqc) {
  switch (pqc) {
  case PQC_MLKEM_768:
    return m->mlkem768_cost;
  case PQC_MLKEM_1024:
    return m->mlkem1024_cost;
  default:
    return 0.0;
  }
}

static double get_kdf_cost(const CostModel *m, const char *kdf) {
  if (strcmp(kdf, "blake3") == 0)
    return m->blake3_kdf_cost;
  return m->sha256_kdf_cost;
}

/* Calibrate KDF micro-costs using CLOCK_MONOTONIC */
#include "include/crypto_engine.h"
#include <time.h>

static void calibrate_kdf(CostModel *m, int iters) {
  uint8_t ikm[64] = {0};
  uint8_t out[32] = {0};
  const uint8_t *info = (const uint8_t *)"Calibration-Info-Label-v1";
  size_t info_len = strlen("Calibration-Info-Label-v1");
  const uint8_t *salt = (const uint8_t *)"Calibration-Salt-v1";
  size_t salt_len = strlen("Calibration-Salt-v1");

  struct timespec t0, t1;

  /* SHA-256 HKDF */
  clock_gettime(CLOCK_MONOTONIC, &t0);
  for (int i = 0; i < iters; i++)
    crypto_hkdf_sha256(ikm, 64, salt, salt_len, info, info_len, out);
  clock_gettime(CLOCK_MONOTONIC, &t1);
  m->sha256_kdf_cost =
      ((t1.tv_sec - t0.tv_sec) * 1e3 + (t1.tv_nsec - t0.tv_nsec) / 1e6) / iters;

  /* BLAKE3 */
  clock_gettime(CLOCK_MONOTONIC, &t0);
  for (int i = 0; i < iters; i++)
    crypto_blake3_kdf(ikm, 64, info, info_len, out);
  clock_gettime(CLOCK_MONOTONIC, &t1);
  m->blake3_kdf_cost =
      ((t1.tv_sec - t0.tv_sec) * 1e3 + (t1.tv_nsec - t0.tv_nsec) / 1e6) / iters;

  printf("[Cost Model] Calibrated KDF -> SHA-256: %.5f ms | BLAKE3: %.5f ms\n",
         m->sha256_kdf_cost, m->blake3_kdf_cost);
}

/* -----------------------------------------------------------------------
 * Load trained baseline weights from JSON file
 * ----------------------------------------------------------------------- */
static int load_weights(const char *filename, CostModel *model) {
  FILE *fp = fopen(filename, "r");
  if (!fp) {
    fprintf(stderr, "[!] baseline_matrix_weights.json not found.\n");
    fprintf(stderr, "    Run './bench_baselines' first to generate it.\n");
    return -1;
  }

  fseek(fp, 0, SEEK_END);
  long sz = ftell(fp);
  rewind(fp);
  char *buf = malloc((size_t)sz + 1);
  fread(buf, 1, (size_t)sz, fp);
  buf[sz] = '\0';
  fclose(fp);

  cJSON *root = cJSON_Parse(buf);
  free(buf);
  if (!root) {
    fprintf(stderr, "[!] Failed to parse weights JSON.\n");
    return -1;
  }

  /* Extract known keys */
  cJSON *item;
  if ((item = cJSON_GetObjectItem(root, "X25519")))
    model->x25519_cost =
        cJSON_GetObjectItem(item, "stable_cost_ms")->valuedouble;
  if ((item = cJSON_GetObjectItem(root, "P256")))
    model->p256_cost = cJSON_GetObjectItem(item, "stable_cost_ms")->valuedouble;
  if ((item = cJSON_GetObjectItem(root, "P384")))
    model->p384_cost = cJSON_GetObjectItem(item, "stable_cost_ms")->valuedouble;
  if ((item = cJSON_GetObjectItem(root, "ML-KEM-768")))
    model->mlkem768_cost =
        cJSON_GetObjectItem(item, "stable_cost_ms")->valuedouble;
  if ((item = cJSON_GetObjectItem(root, "ML-KEM-1024")))
    model->mlkem1024_cost =
        cJSON_GetObjectItem(item, "stable_cost_ms")->valuedouble;

  cJSON_Delete(root);
  return 0;
}

/* -----------------------------------------------------------------------
 * Run a single KDF track for all hybrid combos (Timing + HW Telemetry)
 * ----------------------------------------------------------------------- */
static void run_hybrid_track(const AlgoCombo **hybrids, int n_hybrids,
                             const char *kdf_name, const CostModel *model,
                             double *run_buf, cJSON *telemetry_json) {
  printf("\n==================================================================="
         "=======================================");
  printf("\n--- Hybrid Execution Phase: %s ---\n", kdf_name);
  printf("====================================================================="
         "=====================================\n");

  /* Table row storage for timing */
  typedef struct {
    char label[128];
    char kdf[16];
    double emp_avg;
    double seq_pred;
    double par_pred;
    double sd;
    double drift;
  } SummaryRow;

  /* Table row storage for hardware & OS telemetry */
  typedef struct {
    char label[128];
    char kdf[16];
    uint64_t cycles;
    uint64_t instructions;
    double ipc;
    uint64_t l1_miss;
    uint64_t l2_miss;
    uint64_t ctx_sw;
    uint64_t migrations;
    uint64_t page_faults;
  } TelemetryRow;

  SummaryRow rows[16];
  TelemetryRow telem_rows[16];
  int num_rows = 0;

  HWTelemetrySession telem_sess;
  int telem_ok = (hw_telemetry_init(&telem_sess) == 0);

  for (int ci = 0; ci < n_hybrids; ci++) {
    const AlgoCombo *combo = hybrids[ci];
    printf("[*] Benchmarking: %s via %s...\n", combo->label, kdf_name);

    uint64_t tot_cycles = 0;
    uint64_t tot_instr = 0;
    uint64_t tot_l1 = 0;
    uint64_t tot_l2 = 0;
    uint64_t tot_csw = 0;
    uint64_t tot_mig = 0;
    uint64_t tot_pgf = 0;
    int telem_samples = 0;

    int ok = 0;
    for (int r = 0; r < g_num_runs; r++) {
      HWTelemetryResult tr = {0};
      double ms = execute_handshake_with_telemetry(
          g_host, combo, kdf_name, telem_ok ? &telem_sess : NULL,
          telem_ok ? &tr : NULL);
      if (ms < 0.0) {
        fprintf(stderr, " [!] Handshake failed on run %d.\n", r);
        break;
      }
      run_buf[r] = ms;
      ok++;

      /* Exclude warm-up run 0 from telemetry statistics */
      if (r > 0 && telem_ok) {
        tot_cycles += tr.cpu_cycles;
        tot_instr += tr.instructions;
        tot_l1 += tr.l1_cache_misses;
        tot_l2 += tr.l2_cache_misses;
        tot_csw += tr.context_switches;
        tot_mig += tr.cpu_migrations;
        tot_pgf += tr.page_faults;
        telem_samples++;
      }
    }

    if (ok < 2)
      continue;

    /* Steady-state statistics (skip iteration 0) */
    double emp_avg = metrics_mean(run_buf + 1, ok - 1);
    double sd = metrics_stddev(run_buf + 1, ok - 1);

    /* Average hardware telemetry */
    uint64_t avg_cycles = telem_samples ? (tot_cycles / telem_samples) : 0;
    uint64_t avg_instr = telem_samples ? (tot_instr / telem_samples) : 0;
    double avg_ipc =
        (avg_cycles > 0) ? ((double)avg_instr / (double)avg_cycles) : 0.0;
    uint64_t avg_l1 = telem_samples ? (tot_l1 / telem_samples) : 0;
    uint64_t avg_l2 = telem_samples ? (tot_l2 / telem_samples) : 0;
    uint64_t avg_csw = telem_samples ? (tot_csw / telem_samples) : 0;
    uint64_t avg_mig = telem_samples ? (tot_mig / telem_samples) : 0;
    uint64_t avg_pgf = telem_samples ? (tot_pgf / telem_samples) : 0;

    /* Predictive model (Parallel Primitive Execution) */
    double c_cost = get_classical_cost(model, combo->classical_curve);
    double q_cost = get_pqc_cost(model, combo->pqc_alg);
    double kdf_cost = get_kdf_cost(model, kdf_name);
    double seq_pred = c_cost + q_cost + kdf_cost;
    double par_pred = fmax(c_cost, q_cost) + kdf_cost;
    double drift = (par_pred > 0.0) ? (emp_avg - par_pred) : 0.0;
    double accuracy = (emp_avg > 0.0)
                          ? (1.0 - (fabs(emp_avg - par_pred) / emp_avg)) * 100.0
                          : 0.0;
    if (accuracy < 0.0)
      accuracy = 0.0;

    printf("    -> Empirical Avg:          %.3f ms\n", emp_avg);
    printf("    -> Sequential Theoretical: %.3f ms\n", seq_pred);
    printf("    -> Parallel Predicted:    %.3f ms\n", par_pred);
    printf("    -> Parallel Model Acc:    %.2f%% (Drift: %+.3f ms)\n", accuracy,
           drift);
    printf("    -> HW Telemetry: Cycles: %llu | Instr: %llu | IPC: %.2f | L1 "
           "Miss: %llu | L2 Miss: %llu\n",
           (unsigned long long)avg_cycles, (unsigned long long)avg_instr,
           avg_ipc, (unsigned long long)avg_l1, (unsigned long long)avg_l2);

    /* Save for timing table */
    char short_label[128];
    const char *p = strstr(combo->label, "Hybrid: ");
    strncpy(short_label, p ? p + 8 : combo->label, 127);

    snprintf(rows[num_rows].label, sizeof(rows[num_rows].label), "%s",
             short_label);
    snprintf(rows[num_rows].kdf, sizeof(rows[num_rows].kdf), "%s", kdf_name);
    rows[num_rows].emp_avg = emp_avg;
    rows[num_rows].seq_pred = seq_pred;
    rows[num_rows].par_pred = par_pred;
    rows[num_rows].sd = sd;
    rows[num_rows].drift = drift;

    /* Save for telemetry table */
    snprintf(telem_rows[num_rows].label, sizeof(telem_rows[num_rows].label),
             "%s", short_label);
    snprintf(telem_rows[num_rows].kdf, sizeof(telem_rows[num_rows].kdf), "%s",
             kdf_name);
    telem_rows[num_rows].cycles = avg_cycles;
    telem_rows[num_rows].instructions = avg_instr;
    telem_rows[num_rows].ipc = avg_ipc;
    telem_rows[num_rows].l1_miss = avg_l1;
    telem_rows[num_rows].l2_miss = avg_l2;
    telem_rows[num_rows].ctx_sw = avg_csw;
    telem_rows[num_rows].migrations = avg_mig;
    telem_rows[num_rows].page_faults = avg_pgf;

    /* Save entry to JSON */
    if (telemetry_json) {
      char key_name[160];
      snprintf(key_name, sizeof(key_name), "%s (%s)", combo->label, kdf_name);

      cJSON *entry = cJSON_CreateObject();
      cJSON_AddStringToObject(entry, "profile", combo->label);
      cJSON_AddStringToObject(entry, "kdf", kdf_name);
      cJSON_AddNumberToObject(entry, "empirical_avg_ms", emp_avg);
      cJSON_AddNumberToObject(entry, "sd_jitter_ms", sd);
      cJSON_AddNumberToObject(entry, "cpu_cycles", (double)avg_cycles);
      cJSON_AddNumberToObject(entry, "cpu_instructions", (double)avg_instr);
      cJSON_AddNumberToObject(entry, "ipc", avg_ipc);
      cJSON_AddNumberToObject(entry, "l1_cache_misses", (double)avg_l1);
      cJSON_AddNumberToObject(entry, "l2_cache_misses", (double)avg_l2);
      cJSON_AddNumberToObject(entry, "context_switches", (double)avg_csw);
      cJSON_AddNumberToObject(entry, "cpu_migrations", (double)avg_mig);
      cJSON_AddNumberToObject(entry, "page_faults", (double)avg_pgf);
      cJSON_AddItemToObject(telemetry_json, key_name, entry);
    }

    num_rows++;
  }

  if (telem_ok)
    hw_telemetry_cleanup(&telem_sess);

  /* Print Timing Summary Table */
  puts("\n[Latency & Cost Model Matrix]");
  puts("======================================================================="
       "===================================");
  printf("%-24s | %-6s | %-13s | %-12s | %-12s | %-10s | %-10s\n",
         "Hybrid Profile", "KDF", "Empirical(ms)", "Seq Pred(ms)",
         "Par Pred(ms)", "SD Jitter", "Drift (Δ)");
  puts("-----------------------------------------------------------------------"
       "-----------------------------------");
  for (int i = 0; i < num_rows; i++) {
    printf("%-24s | %-6s | %-13.3f | %-12.3f | %-12.3f | %-10.3f | %+10.3f\n",
           rows[i].label, rows[i].kdf, rows[i].emp_avg, rows[i].seq_pred,
           rows[i].par_pred, rows[i].sd, rows[i].drift);
  }
  puts("======================================================================="
       "===================================");

  /* Print Hardware & OS Telemetry Table */
  puts("\n[Hardware Performance Counters & OS Telemetry Matrix]");
  puts("======================================================================="
       "======================================================================="
       "==");
  printf("%-24s | %-6s | %-12s | %-12s | %-6s | %-10s | %-10s | %-8s | %-6s | "
         "%-9s\n",
         "Hybrid Profile", "KDF", "CPU Cycles", "Instructions", "IPC",
         "L1 Miss", "L2 Miss", "Ctx Sw", "Mig", "Pg Faults");
  puts("-----------------------------------------------------------------------"
       "-----------------------------------------------------------------------"
       "--");
  for (int i = 0; i < num_rows; i++) {
    printf("%-24s | %-6s | %-12llu | %-12llu | %-6.2f | %-10llu | %-10llu | "
           "%-8llu | %-6llu | %-9llu\n",
           telem_rows[i].label, telem_rows[i].kdf,
           (unsigned long long)telem_rows[i].cycles,
           (unsigned long long)telem_rows[i].instructions, telem_rows[i].ipc,
           (unsigned long long)telem_rows[i].l1_miss,
           (unsigned long long)telem_rows[i].l2_miss,
           (unsigned long long)telem_rows[i].ctx_sw,
           (unsigned long long)telem_rows[i].migrations,
           (unsigned long long)telem_rows[i].page_faults);
  }
  puts("======================================================================="
       "======================================================================="
       "==\n");
}

/* -----------------------------------------------------------------------
 * Parse CLI arguments
 * ----------------------------------------------------------------------- */
static void parse_args(int argc, char *argv[]) {
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
int main(int argc, char *argv[]) {
  parse_args(argc, argv);

  printf("=== Native C Hybrid Core Performance Matrix Evaluation ===\n");
  printf("[*] Server: %s:%d | Runs: %d\n", g_host, 4444, g_num_runs);

  CostModel model = {0};

  /* Load and verify baseline weights */
  if (load_weights("baseline_matrix_weights.json", &model) != 0)
    return 1;

  /* Calibrate local KDF overhead */
  calibrate_kdf(&model, 500);

  /* Collect all hybrid combos */
  const AlgoCombo *hybrids[NUM_ALGO_COMBOS];
  int n_hybrids = 0;
  for (int i = 0; i < NUM_ALGO_COMBOS; i++) {
    if (ALGORITHM_COMBOS[i].profile == PROFILE_HYBRID)
      hybrids[n_hybrids++] = &ALGORITHM_COMBOS[i];
  }

  double *run_buf = malloc(sizeof(double) * (size_t)g_num_runs);
  if (!run_buf) {
    fprintf(stderr, "OOM\n");
    return 1;
  }

  cJSON *telemetry_json = cJSON_CreateObject();

  /* Phase 1: SHA-256 track */
  run_hybrid_track(hybrids, n_hybrids, "sha256", &model, run_buf,
                   telemetry_json);

  /* Phase 2: BLAKE3 track */
  run_hybrid_track(hybrids, n_hybrids, "blake3", &model, run_buf,
                   telemetry_json);

  free(run_buf);

  /* Export hybrid_telemetry_matrix.json */
  FILE *fp = fopen("hybrid_telemetry_matrix.json", "w");
  if (fp) {
    char *json_str = cJSON_Print(telemetry_json);
    if (json_str) {
      fputs(json_str, fp);
      free(json_str);
    }
    fclose(fp);
    printf("[✔] Hardware & OS telemetry matrix written to: "
           "hybrid_telemetry_matrix.json\n");
  } else {
    perror("fopen hybrid_telemetry_matrix.json");
  }
  cJSON_Delete(telemetry_json);

  printf("[✔] Hybrid evaluation complete.\n");
  return 0;
}
