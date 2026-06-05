# pqc-benchmarking/config/algorithms.py

ALGORITHM_COMBOS = [
    # --- HYBRID PROFILES ---
    {
        "id": 1, "label": "Hybrid: X25519 + ML-KEM-768", "profile": "hybrid",
        "pqc_name": "ML-KEM-768", "classical_name": "X25519", "info": b"Hybrid-X25519-MLKEM768-v1"
    },
    {
        "id": 2, "label": "Hybrid: SecP256r1 + ML-KEM-768", "profile": "hybrid",
        "pqc_name": "ML-KEM-768", "classical_name": "P256", "info": b"Hybrid-P256-MLKEM768-v1"
    },
    {
        "id": 3, "label": "Hybrid: SecP384r1 + ML-KEM-1024", "profile": "hybrid",
        "pqc_name": "ML-KEM-1024", "classical_name": "P384", "info": b"Hybrid-P384-MLKEM1024-v1"
    },
    # --- PURE CLASSICAL BASELINES ---
    {
        "id": 4, "label": "Pure Classical: X25519", "profile": "pure_classical",
        "pqc_name": None, "classical_name": "X25519", "info": b"Pure-Classical-X25519-v1"
    },
    {
        "id": 5, "label": "Pure Classical: SecP256r1", "profile": "pure_classical",
        "pqc_name": None, "classical_name": "P256", "info": b"Pure-Classical-P256-v1"
    },
    # --- PURE QUANTUM BASELINES ---
    {
        "id": 6, "label": "Pure Quantum: ML-KEM-768", "profile": "pure_quantum",
        "pqc_name": "ML-KEM-768", "classical_name": None, "info": b"Pure-Quantum-MLKEM768-v1"
    },
    {
        "id": 7, "label": "Pure Quantum: ML-KEM-1024", "profile": "pure_quantum",
        "pqc_name": "ML-KEM-1024", "classical_name": None, "info": b"Pure-Quantum-MLKEM1024-v1"
    }
]

def get_combo_by_id(combo_id: int):
    for c in ALGORITHM_COMBOS:
        if c["id"] == combo_id:
            return c
    raise ValueError(f"Unknown combo_id: {combo_id}")