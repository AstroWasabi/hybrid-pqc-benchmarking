# research/core/network_client.py
import socket
import time
import oqs
from core.crypto_engine import (
    generate_classical_kex_keypair,
    derive_classical_kex_secret,
    derive_hybrid_secret_sha256,
    derive_hybrid_secret_blake3,
    b64e, b64d, send_json, recv_json,
)

PORT = 4443
STATIC_SALT = b"IEICE-Kyoto-Conference-2026"


def execute_handshake(host: str, combo: dict, kdf_type: str) -> float:
    """
    Executes a single cryptographic handshake over a network socket.
    Returns the total execution duration in milliseconds (ms).
    """
    # Only supply a salt if we are running the legacy hybrid SHA-256 track
    current_salt = STATIC_SALT if combo["profile"] == "hybrid" and kdf_type == "sha256" else None

    wall_start = time.perf_counter()

    with socket.create_connection((host, PORT)) as sock:
        fh = sock.makefile("rwb", buffering=0)

        # 1. Negotiate profile and setup parameters
        setup_payload = {
            "type": "ProfileSelect",
            "combo_id": combo["id"],
            "kdf_type": kdf_type,
            "salt": b64e(current_salt) if current_salt else None
        }
        send_json(fh, setup_payload)

        # 2. Handle Classical Key Exchange Path
        c_secret = None
        if combo["profile"] in ("hybrid", "pure_classical"):
            c_priv, c_pub_bytes = generate_classical_kex_keypair(combo["classical_name"])
            send_json(fh, {"type": "ClientHello", "c_pub": b64e(c_pub_bytes)})

        # Read server key material response
        resp = recv_json(fh)

        if combo["profile"] in ("hybrid", "pure_classical"):
            srv_c_pub = b64d(resp["c_pub"])
            c_secret = derive_classical_kex_secret(combo["classical_name"], c_priv, srv_c_pub)

        # 3. Handle Post-Quantum KEM Path
        q_secret = None
        if combo["profile"] in ("hybrid", "pure_quantum"):
            with oqs.KeyEncapsulation(combo["pqc_name"]) as kem:
                ct, q_secret = kem.encap_secret(b64d(resp["q_pk"]))
                send_json(fh, {"type": "PQCCiphertext", "ct": b64e(ct)})

        # 4. Final Core Key Derivation
        if kdf_type == "blake3":
            session_key = derive_hybrid_secret_blake3(c_secret, q_secret, combo["info"])
        else:
            session_key = derive_hybrid_secret_sha256(c_secret, q_secret, combo["info"], salt=current_salt)

        # Await final handshake verification confirmation from the server
        recv_json(fh)

    # Calculate final elapsed wall-clock delta converted straight to ms
    return (time.perf_counter() - wall_start) * 1000