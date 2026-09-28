# telemetry/cost_model.py
import time
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
import blake3


class PredictiveCostModel:
    def __init__(self):
        """
        Initializes the component tracking structures for the predictive model matrix.
        Formula: T_predicted = T_classical + T_pqc + T_kdf
        """
        self.classical_costs = {}
        self.pqc_costs = {}

        # Default fallbacks
        self.kdf_weights = {
            "sha256": 0.05,
            "blake3": 0.01
        }

        # Dynamically calibrate KDF costs based on host CPU speed
        self.calibrate_kdf_weights()

    def calibrate_kdf_weights(self, num_iterations: int = 500):
        """
        Microbenchmarks the actual cryptographic overhead of HKDF-SHA256 and BLAKE3
        key derivations on the local system hardware.
        """
        # Set up realistic-sized dummy inputs
        classical_secret = b"\x00" * 32
        pqc_secret = b"\x00" * 32
        combined_input = classical_secret + pqc_secret
        info_label = b"Calibration-Info-Label-v1"
        salt = b"Calibration-Salt-v1"

        try:
            # 1. Benchmark SHA-256 HKDF
            t0 = time.perf_counter()
            for _ in range(num_iterations):
                hkdf = HKDF(
                    algorithm=hashes.SHA256(),
                    length=32,
                    salt=salt,
                    info=info_label,
                )
                _ = hkdf.derive(combined_input)
            t1 = time.perf_counter()
            sha256_avg_ms = ((t1 - t0) / num_iterations) * 1000

            # 2. Benchmark BLAKE3
            t0 = time.perf_counter()
            for _ in range(num_iterations):
                hasher = blake3.blake3()
                hasher.update(info_label)
                hasher.update(combined_input)
                _ = hasher.digest(length=32)
            t1 = time.perf_counter()
            blake3_avg_ms = ((t1 - t0) / num_iterations) * 1000

            self.kdf_weights["sha256"] = sha256_avg_ms
            self.kdf_weights["blake3"] = blake3_avg_ms
            print(f"[Model Matrix] Calibrated local KDF execution -> SHA-256: {sha256_avg_ms:.5f} ms | BLAKE3: {blake3_avg_ms:.5f} ms")

        except Exception as e:
            print(f"[!] Warning: KDF dynamic calibration failed, reverting to defaults. Reason: {e}")

    def register_baseline_cost(self, algorithm_label: str, profile_type: str, stable_cost_ms: float):
        """
        Ingests processed baseline measurements from the control tests
        to train the predictive matrix variables.
        """
        if profile_type == "pure_classical":
            # Map clean name (e.g., 'X25519') to its isolated hardware speed
            name = algorithm_label.replace("Pure Classical: ", "").strip()
            # Normalize names to match classical_name values (e.g., "SecP256r1" -> "P256")
            if "SecP256r1" in name or name == "P256":
                name = "P256"
            elif "SecP384r1" in name or name == "P384":
                name = "P384"
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
