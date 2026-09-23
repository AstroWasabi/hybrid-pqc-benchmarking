/* c/src/metrics.c
 * Statistical helpers for benchmark data analysis.
 * Mirrors telemetry/metrics_collector.py.
 */

#include "../include/metrics.h"
#include <math.h>

double metrics_mean(const double *vals, int n)
{
    if (n <= 0) return 0.0;
    double sum = 0.0;
    for (int i = 0; i < n; i++) sum += vals[i];
    return sum / n;
}

double metrics_stddev(const double *vals, int n)
{
    if (n <= 1) return 0.0;
    double mean = metrics_mean(vals, n);
    double variance = 0.0;
    for (int i = 0; i < n; i++) {
        double diff = vals[i] - mean;
        variance += diff * diff;
    }
    /* Sample standard deviation: ddof=1 — matches Python statistics.stdev */
    return sqrt(variance / (n - 1));
}

double metrics_stable_cost(const double *vals, int n)
{
    /* Skip iteration 0 (cold-start spike) — mirrors extract_stable_baseline_cost() */
    if (n <= 1) return metrics_mean(vals, n);
    return metrics_mean(vals + 1, n - 1);
}

double metrics_min(const double *vals, int n)
{
    if (n <= 0) return 0.0;
    double m = vals[0];
    for (int i = 1; i < n; i++) if (vals[i] < m) m = vals[i];
    return m;
}

double metrics_max(const double *vals, int n)
{
    if (n <= 0) return 0.0;
    double m = vals[0];
    for (int i = 1; i < n; i++) if (vals[i] > m) m = vals[i];
    return m;
}
