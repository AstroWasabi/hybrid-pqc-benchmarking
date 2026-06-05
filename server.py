# research/server.py
import socket
import oqs
from core.crypto_engine import (
    generate_classical_kex_keypair,
    derive_classical_kex_secret,  # <-- Using our verified cross-format engine
    derive_hybrid_secret_sha256,
    derive_hybrid_secret_blake3,
    b64e, b64d, send_json, recv_json,
)
from config.algorithms import get_combo_by_id

HOST = "0.0.0.0"
PORT = 4443


def run_server():
    print(f"[*] Multi-KDF Cryptographic Server Active and Listening on port {PORT}...")

    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        s.bind((HOST, PORT))
        s.listen()

        while True:
            conn, addr = s.accept()
            with conn:
                fh = conn.makefile("rwb", buffering=0)
                try:
                    # 1. Parse initial configuration packet from client
                    sel = recv_json(fh)
                    combo = get_combo_by_id(sel["combo_id"])
                    kdf_choice = sel.get("kdf_type", "sha256")
                    client_salt = b64d(sel["salt"]) if sel.get("salt") else None

                    response_packet = {}
                    c_secret = None

                    # 2. Process Classical Exchange if mapped to profile
                    if combo["profile"] in ("hybrid", "pure_classical"):
                        cli_hello = recv_json(fh)
                        cli_c_pub = b64d(cli_hello["c_pub"])

                        # Generate keys using the clean crypto engine layer
                        srv_c_priv, srv_c_pub = generate_classical_kex_keypair(combo["classical_name"])

                        # --- FIX: Uses crypto_engine wrapper which explicitly supports both X25519 and NIST curves ---
                        c_secret = derive_classical_kex_secret(combo["classical_name"], srv_c_priv, cli_c_pub)

                        response_packet["c_pub"] = b64e(srv_c_pub)

                    # 3. Process Quantum KEM Exchange if mapped to profile
                    q_secret = None
                    if combo["profile"] in ("hybrid", "pure_quantum"):
                        with oqs.KeyEncapsulation(combo["pqc_name"]) as kem:
                            q_pk = kem.generate_keypair()
                            response_packet["q_pk"] = b64e(q_pk)

                            # Transmit key material to client
                            send_json(fh, response_packet)

                            # Await ciphertext encapsulation message back
                            ct_msg = recv_json(fh)
                            q_secret = kem.decap_secret(b64d(ct_msg["ct"]))
                    else:
                        # Flush pure classical configuration packet down the wire
                        send_json(fh, response_packet)

                    # 4. Process Core Key Derivation
                    if kdf_choice == "blake3":
                        session_key = derive_hybrid_secret_blake3(c_secret, q_secret, combo["info"])
                    else:
                        session_key = derive_hybrid_secret_sha256(c_secret, q_secret, combo["info"], salt=client_salt)

                    # 5. Issue final confirmation acknowledgment back to client
                    send_json(fh, {"type": "ServerFinished", "status": "success"})

                except Exception as e:
                    # Print internal server faults to standard output so troubleshooting is transparent
                    print(f" [!] Internal Handshake Processing Exception: {e}")


if __name__ == "__main__":
    run_server()