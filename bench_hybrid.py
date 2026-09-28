# bench_hybrid.py
import json
import os
from config.algorithms import ALGORITHM_COMBOS
from core.network_client import execute_handshake
from telemetry import metrics_collector, visualizer, cost_model

HOST = "127.0.0.1"
NUM_RUNS = 1000


def load_trained_cost_model():
    """Initializes and trains the cost engine using baseline data files."""
    model = cost_model.PredictiveCostModel()

    if not os.path.exists("baseline_matrix_weights.json"):
        print("[!] Warning: baseline_matrix_weights.json not found.")
        print("    Run 'python3 bench_baselines.py' first to generate predictive targets.")
        return None

    with open("baseline_matrix_weights.json", "r") as f:
        weights = json.load(f)

    for algo_key, data in weights.items():
        model.register_baseline_cost(
            algorithm_label=data["label"],
            profile_type=data["profile"],
            stable_cost_ms=data["stable_cost_ms"]
        )
    return model


def run_hybrid_track(hybrid_combos, kdf_engine_name, predictor):
    print(f"\n--- Activating Hybrid Execution Phase: {kdf_engine_name.upper()} ---")
    track_results = []
    summary_table_rows = []

    # Try loading raw baseline file for local drift computation
    try:
        with open("baseline_matrix_weights.json", "r") as f:
            weights = json.load(f)
    except FileNotFoundError:
        weights = {}

    for combo in hybrid_combos:
        print(f"[*] Benchmarking: {combo['label']} via {kdf_engine_name.upper()}...")

        try:
            # Gather empirical wall times
            raw_runs = [execute_handshake(HOST, combo, kdf_type=kdf_engine_name) for _ in range(NUM_RUNS)]
            stats = metrics_collector.calculate_summary_stats(combo["label"], raw_runs)

            # Pack results for plot visualizer
            track_results.append({"label": combo["label"], "raw_runs": raw_runs})

            # Calculate standard deviation jitter omitting iteration 0
            steady_state = raw_runs[1:]
            n = len(steady_state)
            if n > 0:
                emp_avg = sum(steady_state) / n
                variance = sum((x - emp_avg) ** 2 for x in steady_state) / n
                sd = variance ** 0.5
            else:
                emp_avg, sd = 0.0, 0.0

            # Calculate predictive baseline drift values (c_cost + q_cost + calibrated KDF cost)
            c_cost = weights.get(combo["classical_name"], {}).get("stable_cost_ms", 0.0)
            q_cost = weights.get(combo["pqc_name"], {}).get("stable_cost_ms", 0.0)
            kdf_cost = predictor.kdf_weights.get(kdf_engine_name.lower(), 0.0) if predictor else 0.0
            predicted = c_cost + q_cost + kdf_cost
            drift = emp_avg - predicted if predicted > 0 else 0.0

            lbl = combo["label"].replace("Hybrid: ", "")
            summary_table_rows.append((lbl, kdf_engine_name.upper(), emp_avg, sd, drift))

            if predictor:
                predicted_val = predictor.predict_hybrid_performance(
                    classical_name=combo["classical_name"],
                    pqc_name=combo["pqc_name"],
                    kdf_type=kdf_engine_name
                )
                accuracy_report = predictor.evaluate_model_accuracy(stats["avg"], predicted_val)

                print(f"    -> Empirical Avg: {stats['avg']:.3f} ms")
                print(f"    -> Predicted Avg: {predicted_val:.3f} ms")
                print(f"    -> Model Accuracy: {accuracy_report['accuracy_percentage']:.2f}% (Error: {accuracy_report['absolute_error_ms']:.3f} ms)")
            else:
                print(f"    -> Empirical Avg: {stats['avg']:.3f} ms | Jitter: {stats['jitter']:.3f} ms")

        except Exception as e:
            print(f" [!] Error processing hybrid combination {combo['label']}: {e}")

    # --- PRINT TRACK MATRIX TABLE ---
    print("\n" + "=" * 80)
    print(f"{'Hybrid Profile':<24} | {'KDF':<6} | {'Empirical(ms)':<13} | {'SD Jitter':<10} | {'Drift (Δ)':<10}")
    print("-" * 80)
    for row in summary_table_rows:
        print(f"{row[0]:<24} | {row[1]:<6} | {row[2]:<13.3f} | {row[3]:<10.3f} | {row[4]:+10.3f}")
    print("=" * 80 + "\n")

    # Send values directly to our custom visualizer module to draw high-density subplots
    visualizer.generate_density_timeline(track_results, kdf_engine_name, NUM_RUNS)


def main():
    print(f"=== Initiating Upgraded Hybrid Core Performance Matrix Evaluation ===")

    # Isolate only hybrid combos
    hybrid_combos = [c for c in ALGORITHM_COMBOS if c["profile"] == "hybrid"]

    # Prepare the predictive analytic layer
    predictor = load_trained_cost_model()

    # Phase 1: Benchmark hybrid array using SHA256
    run_hybrid_track(hybrid_combos, "sha256", predictor)

    # Phase 2: Benchmark hybrid array using BLAKE3
    run_hybrid_track(hybrid_combos, "blake3", predictor)

    print("\n[✔] Hybrid evaluation loops terminated cleanly. Check working directory for timeline png files.")


if __name__ == "__main__":
    main()
