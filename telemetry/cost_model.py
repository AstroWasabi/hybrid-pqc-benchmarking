# research/telemetry/cost_model.py

class PredictiveCostModel:
    def __init__(self):
        """
        Initializes the component tracking structures for the predictive model matrix.
        Formula: T_predicted = T_classical + T_pqc + T_kdf
        """
        self.classical_costs = {}
        self.pqc_costs = {}

        # Microbenchmarked KDF execution delta weights on local bare-metal loops
        # (Can be dynamically adjusted based on isolated micro-testing profiles)
        self.kdf_weights = {
            "sha256": 0.05,  # Measured overhead baseline in ms
            "blake3": 0.01  # Measured parallel SIMD overhead baseline in ms
        }

    def register_baseline_cost(self, algorithm_label: str, profile_type: str, stable_cost_ms: float):
        """
        Ingests processed baseline measurements from the control tests
        to train the predictive matrix variables.
        """
        if profile_type == "pure_classical":
            # Map clean name (e.g., 'X25519') to its isolated hardware speed
            name = algorithm_label.replace("Pure Classical: ", "").strip()
            self.classical_costs[name] = stable_cost_ms
            print(f"[Model Matrix] Registered Classical Baseline -> {name}: {stable_cost_ms:.3f} ms")

        elif profile_type == "pure_quantum":
            # Map clean name (e.g., 'ML-KEM-768') to its isolated hardware speed
            name = algorithm_label.replace("Pure Quantum: ", "").strip()
            self.pqc_costs[name] = stable_cost_ms
            print(f"[Model Matrix] Registered Quantum Baseline -> {name}: {stable_cost_ms:.3f} ms")

    def predict_hybrid_performance(self, classical_name: str, pqc_name: str, kdf_type: str) -> float:
        """
        Executes the predictive cost model equation.
        Combines the independent variable weights to formulate a deterministic prediction.
        """
        t_classical = self.classical_costs.get(classical_name, 0.0)
        t_pqc = self.pqc_costs.get(pqc_name, 0.0)
        t_kdf = self.kdf_weights.get(kdf_type.lower(), 0.0)

        # Mathematical projection construction
        predicted_latency = t_classical + t_pqc + t_kdf
        return predicted_latency

    def evaluate_model_accuracy(self, real_avg_ms: float, predicted_avg_ms: float) -> dict:
        """
        Quantifies the mathematical drift between the empirical real-world testing
        and the model's prediction to evaluate overall accuracy.
        """
        absolute_error = abs(real_avg_ms - predicted_avg_ms)
        accuracy_percentage = (1 - (absolute_error / real_avg_ms)) * 100 if real_avg_ms > 0 else 0.0

        return {
            "absolute_error_ms": absolute_error,
            "accuracy_percentage": max(0.0, accuracy_percentage)
        }