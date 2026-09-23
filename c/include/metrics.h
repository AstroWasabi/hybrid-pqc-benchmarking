/* c/include/metrics.h
 * Statistical helpers for benchmark data analysis.
 * Mirrors telemetry/metrics_collector.py functionality.
 */
#pragma once

#include <stddef.h>

/**
 * Compute arithmetic mean of an array of doubles.
 *
 * @param vals  Array of sample values
 * @param n     Number of samples
 * @returns     Mean, or 0.0 if n == 0
 */
double metrics_mean(const double *vals, int n);

/**
 * Compute sample standard deviation of an array of doubles.
 *
 * @param vals  Array of sample values
 * @param n     Number of samples
 * @returns     Std deviation (sample, ddof=1), or 0.0 if n <= 1
 */
double metrics_stddev(const double *vals, int n);

/**
 * Compute the stable baseline cost — mean of all samples EXCEPT the
 * first one (index 0), which is discarded as a cold-start outlier.
 * Mirrors extract_stable_baseline_cost() in Python.
 *
 * @param vals  Array of sample values
 * @param n     Number of samples
 * @returns     Mean of vals[1..n-1], or mean of all if n <= 1
 */
double metrics_stable_cost(const double *vals, int n);

/**
 * Minimum value in array.
 */
double metrics_min(const double *vals, int n);

/**
 * Maximum value in array.
 */
double metrics_max(const double *vals, int n);
