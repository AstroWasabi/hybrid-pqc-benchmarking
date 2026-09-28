#!/usr/bin/env python3
"""
generate_table_images.py
Renders publication-quality table images (PNG) from the C benchmarking
suite JSON outputs for embedding in papers or presentations.

Outputs to outputs/:
  - table_baselines.png
  - table_hybrid_latency.png
  - table_hybrid_telemetry.png
"""

import json
from pathlib import Path

import matplotlib
matplotlib.use("Agg")
import matplotlib.pyplot as plt
import matplotlib.colors as mcolors
import numpy as np

# ---------------------------------------------------------------------------
# Paths
# ---------------------------------------------------------------------------
BASE_DIR   = Path(__file__).resolve().parent
BASELINE_JSON = BASE_DIR / "baseline_matrix_weights.json"
HYBRID_JSON   = BASE_DIR / "hybrid_telemetry_matrix.json"
OUTPUT_DIR    = BASE_DIR / "outputs"
OUTPUT_DIR.mkdir(exist_ok=True)

# ---------------------------------------------------------------------------
# Style constants
# ---------------------------------------------------------------------------
FONT_FAMILY   = "monospace"
HEADER_COLOR  = "#2C3E50"
HEADER_TEXT    = "#FFFFFF"
ROW_LIGHT     = "#F8F9FA"
ROW_DARK      = "#EDF2F7"
ACCENT_BLUE   = "#3498DB"
ACCENT_GOLD   = "#F39C12"
ACCENT_GREEN  = "#27AE60"
BORDER_COLOR  = "#CBD5E0"
TITLE_COLOR   = "#1A202C"

plt.rcParams.update({
    "font.family": "sans-serif",
    "font.sans-serif": ["DejaVu Sans", "Arial", "Helvetica"],
    "font.size": 11,
})


def load_json(path: Path) -> dict:
    with open(path) as f:
        return json.load(f)


def fmt(val, decimals=3):
    if isinstance(val, float):
        return f"{val:.{decimals}f}"
    return str(val)


def fmt_int(val):
    if isinstance(val, (int, float)):
        return f"{int(val):,}"
    return str(val)


def render_table_image(
    title: str,
    headers: list[str],
    rows: list[list[str]],
    col_widths: list[float] | None = None,
    output_path: Path = None,
    header_color: str = HEADER_COLOR,
    accent_column: int | None = None,
):
    """Render a publication-quality table as a PNG image."""
    n_rows = len(rows)
    n_cols = len(headers)

    # Auto-calculate figure width from content
    if col_widths is None:
        col_widths = []
        for ci in range(n_cols):
            max_len = max(len(headers[ci]), *(len(str(rows[ri][ci])) for ri in range(n_rows)))
            col_widths.append(max(0.12, max_len * 0.095))

    fig_width = sum(col_widths) + 0.8
    fig_height = 1.2 + (n_rows + 1) * 0.42

    fig, ax = plt.subplots(figsize=(fig_width, fig_height))
    ax.axis("off")

    # Title
    fig.text(
        0.5, 0.95, title,
        ha="center", va="top",
        fontsize=13, fontweight="bold",
        color=TITLE_COLOR,
        fontfamily="sans-serif",
    )

    # Build table
    table = ax.table(
        cellText=rows,
        colLabels=headers,
        cellLoc="center",
        loc="center",
        colWidths=[w / sum(col_widths) for w in col_widths],
    )

    table.auto_set_font_size(False)
    table.set_fontsize(10)
    table.scale(1.0, 1.6)

    # Style header row
    for ci in range(n_cols):
        cell = table[0, ci]
        cell.set_facecolor(header_color)
        cell.set_text_props(color=HEADER_TEXT, fontweight="bold", fontsize=9.5)
        cell.set_edgecolor(BORDER_COLOR)
        cell.set_linewidth(0.5)

    # Style data rows
    for ri in range(n_rows):
        bg = ROW_LIGHT if ri % 2 == 0 else ROW_DARK
        for ci in range(n_cols):
            cell = table[ri + 1, ci]
            cell.set_facecolor(bg)
            cell.set_edgecolor(BORDER_COLOR)
            cell.set_linewidth(0.3)
            cell.set_text_props(fontsize=9.5, fontfamily="monospace")

            # Accent column highlight
            if accent_column is not None and ci == accent_column:
                cell.set_text_props(fontweight="bold", color="#2D3748")

    plt.subplots_adjust(top=0.88, bottom=0.05, left=0.05, right=0.95)

    if output_path:
        fig.savefig(output_path, dpi=200, bbox_inches="tight",
                    facecolor="white", edgecolor="none", pad_inches=0.3)
        print(f"  [✔] Saved: {output_path}")

    plt.close(fig)


# ===========================================================================
# Table 1: Control Baselines
# ===========================================================================
def generate_baseline_table():
    data = load_json(BASELINE_JSON)

    headers = ["Algorithm", "Profile", "Stable Cost (ms)"]
    rows = []
    for key, entry in data.items():
        rows.append([
            key,
            entry["profile"].replace("_", " ").title(),
            fmt(entry["stable_cost_ms"]),
        ])
    rows.sort(key=lambda r: (0 if "Classical" in r[1] else 1, float(r[2])))

    render_table_image(
        title="Table 1: Control Baseline Costs — Native C (1,000 runs per profile)",
        headers=headers,
        rows=rows,
        output_path=OUTPUT_DIR / "table_baselines.png",
        header_color="#2980B9",
        accent_column=2,
    )


# ===========================================================================
# Table 2: Hybrid Latency & Cost Model
# ===========================================================================
def generate_hybrid_latency_table():
    data = load_json(HYBRID_JSON)
    baselines = load_json(BASELINE_JSON)
    baseline_costs = {k: v["stable_cost_ms"] for k, v in baselines.items()}

    PROFILE_COMPONENTS = {
        "Hybrid: X25519 + ML-KEM-768":     ("X25519",  "ML-KEM-768"),
        "Hybrid: SecP256r1 + ML-KEM-768":   ("P256",    "ML-KEM-768"),
        "Hybrid: SecP384r1 + ML-KEM-1024":  ("P384",    "ML-KEM-1024"),
    }

    headers = [
        "Hybrid Profile", "KDF",
        "Empirical\n(ms)", "Seq Pred\n(ms)", "Par Pred\n(ms)",
        "SD Jitter\n(ms)", "Drift\n(Δ ms)", "Par Acc\n(%)"
    ]
    rows = []

    for key, entry in data.items():
        profile = entry["profile"]
        kdf = entry["kdf"]
        empirical = entry["empirical_avg_ms"]
        sd = entry["sd_jitter_ms"]

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

        # Clean up profile name for display
        short_profile = profile.replace("Hybrid: ", "")

        rows.append([
            short_profile, kdf.upper(),
            fmt(empirical), fmt(seq_pred), fmt(par_pred),
            fmt(sd), f"+{fmt(drift)}" if drift >= 0 else fmt(drift),
            fmt(par_acc, 1)
        ])

    rows.sort(key=lambda r: (r[1], float(r[2])))

    render_table_image(
        title="Table 2: Hybrid Latency & Predictive Cost Model — Native C (1,000 runs)",
        headers=headers,
        rows=rows,
        output_path=OUTPUT_DIR / "table_hybrid_latency.png",
        header_color="#D4880F",
        accent_column=2,
    )


# ===========================================================================
# Table 3: Hardware Performance Counters & OS Telemetry
# ===========================================================================
def generate_hybrid_telemetry_table():
    data = load_json(HYBRID_JSON)

    headers = [
        "Hybrid Profile", "KDF",
        "CPU Cycles", "Instructions", "IPC",
        "L1 Miss", "L2 Miss",
        "Ctx Sw", "Pg Faults"
    ]
    rows = []

    for key, entry in data.items():
        short_profile = entry["profile"].replace("Hybrid: ", "")
        rows.append([
            short_profile,
            entry["kdf"].upper(),
            fmt_int(entry["cpu_cycles"]),
            fmt_int(entry["cpu_instructions"]),
            fmt(entry["ipc"], 2),
            fmt_int(entry["l1_cache_misses"]),
            fmt_int(entry["l2_cache_misses"]),
            fmt_int(entry["context_switches"]),
            fmt_int(entry["page_faults"]),
        ])

    rows.sort(key=lambda r: (r[1], r[0]))

    render_table_image(
        title="Table 3: Hardware Performance Counters — Native C (perf_event)",
        headers=headers,
        rows=rows,
        output_path=OUTPUT_DIR / "table_hybrid_telemetry.png",
        header_color="#1E8449",
        accent_column=4,
    )


# ===========================================================================
# Main
# ===========================================================================
if __name__ == "__main__":
    print("\n━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━")
    print("  Generating publication-quality table images...")
    print("━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━\n")

    generate_baseline_table()
    generate_hybrid_latency_table()
    generate_hybrid_telemetry_table()

    print("\n━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━")
    print("  Done! PNG table images saved to: outputs/")
    print("━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━\n")
