# research/generate_conference_plots.py
import json
import os
import numpy as np
import matplotlib.pyplot as plt
from config.algorithms import ALGORITHM_COMBOS
from core.network_client import execute_handshake
from telemetry import metrics_collector, cost_model

HOST = "127.0.0.1"
NUM_RUNS = 200


def gather_handshake_data(predictor):
    hybrid_combos = [c for c in ALGORITHM_COMBOS if c["profile"] == "hybrid"]

    data = {
        "labels": [],
        "sha_emp": [], "sha_pred": [], "sha_err": [], "sha_acc": [],
        "blake_emp": [], "blake_pred": [], "blake_err": [], "blake_acc": []
    }

    for combo in hybrid_combos:
        short_label = combo["label"].replace("Hybrid: ", "")
        data["labels"].append(short_label)

        # SHA256 Data Collection
        sha_runs = [execute_handshake(HOST, combo, kdf_type="sha256") for _ in range(NUM_RUNS)]
        sha_avg = metrics_collector.calculate_summary_stats(combo["label"], sha_runs)["avg"]
        sha_pred = predictor.predict_hybrid_performance(combo["classical_name"], combo["pqc_name"], "sha256")

        data["sha_emp"].append(sha_avg)
        data["sha_pred"].append(sha_pred)
        data["sha_err"].append(sha_avg - sha_pred)  # Real - Theory
        data["sha_acc"].append((1 - (abs(sha_avg - sha_pred) / sha_avg)) * 100)

        # BLAKE3 Data Collection
        blake_runs = [execute_handshake(HOST, combo, kdf_type="blake3") for _ in range(NUM_RUNS)]
        blake_avg = metrics_collector.calculate_summary_stats(combo["label"], blake_runs)["avg"]
        blake_pred = predictor.predict_hybrid_performance(combo["classical_name"], combo["pqc_name"], "blake3")

        data["blake_emp"].append(blake_avg)
        data["blake_pred"].append(blake_pred)
        data["blake_err"].append(blake_avg - blake_pred)  # Real - Theory
        data["blake_acc"].append((1 - (abs(blake_avg - blake_pred) / blake_avg)) * 100)

    return data


def plot_option2_residual(data):
    """Generates Option 2: Residual Error Chart."""
    fig, ax = plt.subplots(figsize=(11, 6))
    x = np.arange(len(data["labels"]))

    # Plot a clean zero baseline. Zero means 100% perfect prediction.
    ax.axhline(0, color="black", linestyle="--", linewidth=1.2, alpha=0.7)

    # Scatter plot with vertical line indicators (stems)
    ax.stem(x - 0.15, data["sha_err"], linefmt="C0-", markerfmt="C0o", label="SHA-256 Model Drift")
    ax.stem(x + 0.15, data["blake_err"], linefmt="C1-", markerfmt="C1o", label="BLAKE3 Model Drift")

    ax.set_ylabel("Prediction Error Delta ($\Delta$ ms)\n[Positive = Real World was Slower]", fontsize=11,
                  fontweight="bold")
    ax.set_title("Cost Model Residual Analysis\n(Isolating Pure Systemic & Context-Switching Overhead)", fontsize=13,
                 fontweight="bold", pad=15)
    ax.set_xticks(x)
    ax.set_xticklabels(data["labels"], fontsize=10, fontweight="bold")
    ax.grid(True, linestyle=":", alpha=0.5)
    ax.legend(loc="upper left")

    # Text annotations for the exact millisecond values
    for i in x:
        ax.annotate(f'{data["sha_err"][i]:+.3f} ms', xy=(i - 0.15, data["sha_err"][i]),
                    xytext=(0, 5 if data["sha_err"][i] >= 0 else -12), textcoords="offset points", ha='center',
                    fontsize=9, fontweight='bold', color='C0')
        ax.annotate(f'{data["blake_err"][i]:+.3f} ms', xy=(i + 0.15, data["blake_err"][i]),
                    xytext=(0, 5 if data["blake_err"][i] >= 0 else -12), textcoords="offset points", ha='center',
                    fontsize=9, fontweight='bold', color='C1')

    plt.tight_layout()
    plt.savefig("conference_option2_residual.png", dpi=300)
    plt.close()


def plot_option3_dual_axis(data):
    """Generates Option 3: Dual-Axis Latency + Accuracy Chart."""
    fig, ax1 = plt.subplots(figsize=(12, 7))
    x = np.arange(len(data["labels"]))
    width = 0.35

    # Left Axis: Empirical Handshake Performance Bars
    rects1 = ax1.bar(x - width / 2, data["sha_emp"], width, label='SHA-256 Handshake (Real)', color='#1f77b4',
                     alpha=0.85)
    rects2 = ax1.bar(x + width / 2, data["blake_emp"], width, label='BLAKE3 Handshake (Real)', color='#ff7f0e',
                     alpha=0.85)

    ax1.set_ylabel('Empirical Handshake Latency (ms)', fontsize=11, fontweight='bold', color='black')
    ax1.set_xticks(x)
    ax1.set_xticklabels(data["labels"], fontsize=10, fontweight='bold')
    ax1.set_ylim(0, 8)
    ax1.grid(axis='y', linestyle=':', alpha=0.5)

    # Right Axis: Trend lines for Model Accuracy Percentages
    ax2 = ax1.twinx()
    ax2.plot(x - width / 2, data["sha_acc"], color='#d62728', marker='s', linewidth=2,
             label='SHA-256 Model Accuracy (%)')
    ax2.plot(x + width / 2, data["blake_acc"], color='#2ca02c', marker='^', linewidth=2,
             label='BLAKE3 Model Accuracy (%)')

    ax2.set_ylabel('Predictive Cost Model Accuracy (%)', fontsize=11, fontweight='bold', color='black')
    ax2.set_ylim(50, 105)  # Keeps accuracy paths cleanly separated visually from bar heights

    # Combine legends from both axes
    lines1, labels1 = ax1.get_legend_handles_labels()
    lines2, labels2 = ax2.get_legend_handles_labels()
    ax1.legend(lines1 + lines2, labels1 + labels2, loc='upper left', fontsize=10)

    # Add numeric percentage labels right on top of the line points
    for i in x:
        ax2.annotate(f'{data["sha_acc"][i]:.1f}%', xy=(i - width / 2, data["sha_acc"][i]), xytext=(0, 8),
                     textcoords="offset points", ha='center', fontsize=9, fontweight='bold', color='#d62728')
        ax2.annotate(f'{data["blake_acc"][i]:.1f}%', xy=(i + width / 2, data["blake_acc"][i]), xytext=(0, 8),
                     textcoords="offset points", ha='center', fontsize=9, fontweight='bold', color='#2ca02c')

    plt.title("Empirical Handshake Performance vs. Predictive Model Verification Matrix", fontsize=13,
              fontweight='bold', pad=20)
    plt.tight_layout()
    plt.savefig("conference_option3_dual_axis.png", dpi=300)
    plt.close()


def main():
    if not os.path.exists("baseline_matrix_weights.json"):
        print("[!] Missing weights configuration. Run bench_baselines.py first.")
        return

    with open("baseline_matrix_weights.json", "r") as f:
        weights = json.load(f)

    predictor = cost_model.PredictiveCostModel()
    for algo_key, data in weights.items():
        predictor.register_baseline_cost(data["label"], data["profile"], data["stable_cost_ms"])

    print("[*] Running active handshakes to generate comparison datasets...")
    plot_data = gather_handshake_data(predictor)

    print("[*] Drawing Option 2: Residual Plot...")
    plot_option2_residual(plot_data)

    print("[*] Drawing Option 3: Dual-Axis Graph...")
    plot_option3_dual_axis(plot_data)

    print("\n[✔] Success! Two alternate slide visualizations compiled cleanly.")


if __name__ == "__main__":
    main()