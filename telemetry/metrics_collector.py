# research/telemetry/metrics_collector.py
import statistics


def calculate_summary_stats(label: str, raw_runs: list) -> dict:
    """
    Computes standard descriptive statistics across an execution data array.
    """
    avg_latency = statistics.mean(raw_runs)
    jitter = statistics.stdev(raw_runs) if len(raw_runs) > 1 else 0.0

    return {
        "label": label,
        "avg": avg_latency,
        "jitter": jitter,
        "min": min(raw_runs),
        "max": max(raw_runs)
    }


def extract_stable_baseline_cost(raw_runs: list) -> float:
    """
    Strips away the Iteration 1 cold-start cache miss spike to expose
    the true, stable execution cost of the core cryptographic operations.
    Crucial for stabilizing the predictive cost model inputs.
    """
    if len(raw_runs) <= 1:
        return statistics.mean(raw_runs)

    # Exclude the first run index to capture steady-state hardware speed
    stable_window = raw_runs[1:]
    return statistics.mean(stable_window)