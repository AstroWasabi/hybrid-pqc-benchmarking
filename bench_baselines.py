# research/bench_baselines.py
import json
from config.algorithms import ALGORITHM_COMBOS
from core.network_client import execute_handshake
from telemetry import metrics_collector, visualizer, cost_model

HOST = "127.0.0.1"  # Set to Server IP for remote cloud testing
NUM_RUNS = 1000


def main():
    print(f"=== Initiating Control Baselines Pipeline ({NUM_RUNS} runs per profile) ===")

    # Filter matrix to process ONLY pure classical and pure quantum profiles
    baseline_combos = [c for c in ALGORITHM_COMBOS if c["profile"] in ("pure_classical", "pure_quantum")]

    baseline_results = []
    model_training_data = {}

    for combo in baseline_combos:
        print(f"\n[*] Profiling baseline execution for: {combo['label']}...")

        try:
            # Execute the 1,000-run socket loop (Defaults safely to sha256 wrapper for pure data)
            raw_runs = [execute_handshake(HOST, combo, kdf_type="sha256") for _ in range(NUM_RUNS)]

            # Extract summary stats and the clean, steady-state cost (omitting iteration 1)
            stats = metrics_collector.calculate_summary_stats(combo["label"], raw_runs)
            stable_cost = metrics_collector.extract_stable_baseline_cost(raw_runs)

            print(f"    -> Complete. Steady-State Cost: {stable_cost:.3f} ms | Max Jitter: {stats['jitter']:.3f} ms")

            # Save for high-density timeline visualization mapping
            baseline_results.append({
                "label": combo["label"].replace("Pure Classical: ", "").replace("Pure Quantum: ", ""),
                "raw_runs": raw_runs
            })

            # Save the clean mathematical weights to a training map dictionary
            algo_key = combo["classical_name"] if combo["profile"] == "pure_classical" else combo["pqc_name"]
            model_training_data[algo_key] = {
                "label": combo["label"],
                "profile": combo["profile"],
                "stable_cost_ms": stable_cost
            }

        except Exception as e:
            print(f" [!] Execution aborted for baseline {combo['label']}: {e}")

    # --- SAVE TRAINING MATRIX LAYER ---
    # This dumps the mathematical weights to disk so cost_model can pull them in bench_hybrid.py
    with open("baseline_matrix_weights.json", "w") as f:
        json.dump(model_training_data, f, indent=4)
    print("\n[✔] Baseline weight values successfully compiled to: baseline_matrix_weights.json")

    # --- GENERATE ISOLATED BASELINES VISUALIZATION ---
    print("[*] Spooling baseline timeline data graphics...")
    visualizer.generate_density_timeline(baseline_results, "baselines", NUM_RUNS)


if __name__ == "__main__":
    main()