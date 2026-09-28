#!/usr/bin/env python3
"""
generate_tables.py
Produces clean formatted tables from the C benchmarking suite JSON outputs:
  - baseline_matrix_weights.json   (control baselines)
  - hybrid_telemetry_matrix.json   (hybrid profiles + HW telemetry)

Outputs:
  - Pretty-printed tables to stdout
  - outputs/baseline_table.csv
  - outputs/hybrid_latency_table.csv
  - outputs/hybrid_telemetry_table.csv
"""

import json
import os
from pathlib import Path

# ---------------------------------------------------------------------------
# Try tabulate; fall back to a simple formatter if unavailable
# ---------------------------------------------------------------------------
try:
    from tabulate import tabulate
    HAS_TABULATE = True
except ImportError:
    HAS_TABULATE = False

# ---------------------------------------------------------------------------
# Paths
# ---------------------------------------------------------------------------
BASE_DIR = Path(__file__).resolve().parent
BASELINE_JSON = BASE_DIR / "baseline_matrix_weights.json"
HYBRID_JSON   = BASE_DIR / "hybrid_telemetry_matrix.json"
OUTPUT_DIR    = BASE_DIR / "outputs"
OUTPUT_DIR.mkdir(exist_ok=True)


def load_json(path: Path) -> dict:
    with open(path) as f:
        return json.load(f)


def fmt(val, decimals=3):
    """Format a number to fixed decimals."""
    if isinstance(val, float):
        return f"{val:.{decimals}f}"
    return str(val)


def fmt_int(val):
    """Format an integer with thousand separators."""
    if isinstance(val, (int, float)):
        return f"{int(val):,}"
    return str(val)


def print_table(title, headers, rows, tablefmt="grid"):
    """Print a table with a title."""
    print(f"\n{'=' * 80}")
    print(f"  {title}")
    print(f"{'=' * 80}")
    if HAS_TABULATE:
        print(tabulate(rows, headers=headers, tablefmt=tablefmt, stralign="right"))
    else:
        # Simple fallback formatter
        col_widths = [max(len(str(h)), *(len(str(r[i])) for r in rows))
                      for i, h in enumerate(headers)]
        header_line = " | ".join(h.ljust(w) for h, w in zip(headers, col_widths))
        sep_line = "-+-".join("-" * w for w in col_widths)
        print(header_line)
        print(sep_line)
        for row in rows:
            print(" | ".join(str(c).ljust(w) for c, w in zip(row, col_widths)))
    print()


def save_csv(path: Path, headers: list, rows: list):
    """Save table as CSV."""
    with open(path, "w") as f:
        f.write(",".join(headers) + "\n")
        for row in rows:
            f.write(",".join(str(c) for c in row) + "\n")
    print(f"  [✔] Saved: {path}")


# ===========================================================================
# Table 1: Control Baselines
# ===========================================================================
def build_baseline_table():
    data = load_json(BASELINE_JSON)

    headers = ["Algorithm", "Profile", "Stable Cost (ms)"]
    rows = []
    for key, entry in data.items():
        rows.append([
            key,
            entry["profile"].replace("_", " ").title(),
            fmt(entry["stable_cost_ms"]),
        ])

    # Sort: classical first, then quantum
    rows.sort(key=lambda r: (0 if "Classical" in r[1] else 1, float(r[2])))

    print_table("Table 1: Control Baseline Costs (Native C — 1,000 runs)", headers, rows)
    save_csv(OUTPUT_DIR / "baseline_table.csv", headers, rows)


# ===========================================================================
# Table 2: Hybrid Latency & Cost Model
# ===========================================================================
def build_hybrid_latency_table():
    data = load_json(HYBRID_JSON)
    baselines = load_json(BASELINE_JSON)

    # Reconstruct predictive model costs from baselines
    baseline_costs = {k: v["stable_cost_ms"] for k, v in baselines.items()}

    # Map profile names to their component baseline keys
    PROFILE_COMPONENTS = {
        "Hybrid: X25519 + ML-KEM-768":     ("X25519",  "ML-KEM-768"),
        "Hybrid: SecP256r1 + ML-KEM-768":   ("P256",    "ML-KEM-768"),
        "Hybrid: SecP384r1 + ML-KEM-1024":  ("P384",    "ML-KEM-1024"),
    }

    headers = [
        "Hybrid Profile", "KDF", "Empirical (ms)",
        "Seq Pred (ms)", "Par Pred (ms)",
        "SD Jitter (ms)", "Drift (Δ ms)", "Par Acc (%)"
    ]
    rows = []

    for key, entry in data.items():
        profile = entry["profile"]
        kdf = entry["kdf"]
        empirical = entry["empirical_avg_ms"]
        sd = entry["sd_jitter_ms"]

        # Compute predictive costs
        if profile in PROFILE_COMPONENTS:
            c_key, q_key = PROFILE_COMPONENTS[profile]
            c_cost = baseline_costs.get(c_key, 0)
            q_cost = baseline_costs.get(q_key, 0)
            seq_pred = c_cost + q_cost
            par_pred = max(c_cost, q_cost)
            drift = empirical - par_pred
            par_acc = (par_pred / empirical) * 100 if empirical > 0 else 0
        else:
            seq_pred = par_pred = drift = par_acc = 0

        rows.append([
            profile, kdf.upper(),
            fmt(empirical), fmt(seq_pred), fmt(par_pred),
            fmt(sd), f"+{fmt(drift)}" if drift >= 0 else fmt(drift),
            fmt(par_acc, 1)
        ])

    # Sort by KDF then empirical cost
    rows.sort(key=lambda r: (r[1], float(r[2])))

    print_table(
        "Table 2: Hybrid Latency & Predictive Cost Model (Native C — 1,000 runs)",
        headers, rows
    )
    save_csv(OUTPUT_DIR / "hybrid_latency_table.csv", headers, rows)


# ===========================================================================
# Table 3: Hardware Performance Counters & OS Telemetry
# ===========================================================================
def build_hybrid_telemetry_table():
    data = load_json(HYBRID_JSON)

    headers = [
        "Hybrid Profile", "KDF", "CPU Cycles", "Instructions",
        "IPC", "L1 Misses", "L2 Misses", "Ctx Sw", "Migrations", "Pg Faults"
    ]
    rows = []

    for key, entry in data.items():
        rows.append([
            entry["profile"],
            entry["kdf"].upper(),
            fmt_int(entry["cpu_cycles"]),
            fmt_int(entry["cpu_instructions"]),
            fmt(entry["ipc"], 2),
            fmt_int(entry["l1_cache_misses"]),
            fmt_int(entry["l2_cache_misses"]),
            fmt_int(entry["context_switches"]),
            fmt_int(entry["cpu_migrations"]),
            fmt_int(entry["page_faults"]),
        ])

    rows.sort(key=lambda r: (r[1], r[0]))

    print_table(
        "Table 3: Hardware Performance Counters & OS Telemetry (Native C)",
        headers, rows
    )
    save_csv(OUTPUT_DIR / "hybrid_telemetry_table.csv", headers, rows)


# ===========================================================================
# Main
# ===========================================================================
if __name__ == "__main__":
    print("\n" + "━" * 80)
    print("  Hybrid PQC Benchmarking — Table Generator")
    print("━" * 80)

    build_baseline_table()
    build_hybrid_latency_table()
    build_hybrid_telemetry_table()

    print("━" * 80)
    print("  All tables generated. CSV files saved to: outputs/")
    print("━" * 80 + "\n")
