# research/telemetry/visualizer.py
import matplotlib.pyplot as plt


def generate_density_timeline(results: list, engine_name: str, num_runs: int):
    """
    Generates a high-density, stacked subplot grid for 1,000 iterations.
    Enforces a strict uniform Y-axis range across distinct KDF test configurations.
    """
    num_plots = len(results)
    fig, axes = plt.subplots(num_plots, 1, figsize=(14, 2 * num_plots), sharex=True)

    iterations = range(1, num_runs + 1)
    colors = ['#1f77b4', '#ff7f0e', '#2ca02c', '#d62728', '#9467bd', '#8c564b', '#e377c2']

    for idx, r in enumerate(results):
        ax = axes[idx] if num_plots > 1 else axes
        ax.plot(iterations, r["raw_runs"], color=colors[idx % len(colors)], linewidth=0.5, alpha=0.7, label=r["label"])

        # Enforce uniform vertical grid limits to capture true relative differences
        ax.set_ylim(0, 18)

        ax.legend(loc="upper right", fontsize=8)
        ax.grid(True, linestyle=":", alpha=0.4)

    fig.text(0.01, 0.5, 'Handshake Latency (ms)', va='center', rotation='vertical', fontsize=12)
    plt.xlabel(f"Iteration Timeline Index (1 to {num_runs})", fontsize=11)
    plt.suptitle(f"Run-by-Run Execution Variance ({engine_name.upper()} Engine - {num_runs} Runs)", fontsize=13, y=0.99)

    filename = f"pqc_timeline_{engine_name.lower()}.png"
    plt.tight_layout(rect=[0.02, 0, 1, 0.97])
    plt.savefig(filename, dpi=300)
    plt.close()
    print(f"[*] Saved clean, high-density visualization: {filename}")