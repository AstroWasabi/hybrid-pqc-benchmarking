# research/core/crypto_engine.py
import base64
import json
import blake3
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec, x25519


# --- BASE64 JSON HELPERS ---
def b64e(b: bytes) -> str:
    return base64.b64encode(b).decode("utf-8") if b else ""


def b64d(s: str) -> bytes:
    return base64.b64decode(s.encode("utf-8")) if s else b""


def send_json(fh, obj):
    line = json.dumps(obj) + "\n"
    fh.write(line.encode("utf-8"))


def recv_json(fh):
    line = fh.readline()
    if not line:
        raise ConnectionError("Socket closed prematurely while reading JSON line.")
    return json.loads(line.decode("utf-8"))


# --- CLASSICAL KEY EXCHANGE ENGINE ---
def generate_classical_kex_keypair(curve_name: str):
    if curve_name == "X25519":
        priv = x25519.X25519PrivateKey.generate()
        pub_bytes = priv.public_key().public_bytes(
            serialization.Encoding.Raw,
            serialization.PublicFormat.Raw
        )
        return priv, pub_bytes
    elif curve_name in ("P256", "P384"):
        curve = ec.SECP256R1() if curve_name == "P256" else ec.SECP384R1()
        priv = ec.generate_private_key(curve)

        # Output public key as standard DER SubjectPublicKeyInfo structure
        pub_bytes = priv.public_key().public_bytes(
            serialization.Encoding.DER,
            serialization.PublicFormat.SubjectPublicKeyInfo
        )
        return priv, pub_bytes
    raise ValueError(f"Unsupported curve: {curve_name}")


def derive_classical_kex_secret(curve_name: str, priv_key, peer_pub_bytes: bytes) -> bytes:
    if curve_name == "X25519":
        peer_pub = x25519.X25519PublicKey.from_public_bytes(peer_pub_bytes)
        return priv_key.exchange(peer_pub)
    elif curve_name in ("P256", "P384"):
        # UNIVERSAL FIX: load_der_public_key works perfectly across ALL library versions
        peer_pub = serialization.load_der_public_key(peer_pub_bytes)
        return priv_key.exchange(ec.ECDH(), peer_pub)
    raise ValueError(f"Unsupported curve: {curve_name}")


# --- KEY DERIVATION ENGINES (KDF) ---
def derive_hybrid_secret_sha256(classical_secret: bytes, pqc_secret: bytes, info_label: bytes,
                                salt: bytes = None) -> bytes:
    from cryptography.hazmat.primitives.kdf.hkdf import HKDF
    if classical_secret and pqc_secret:
        combined_input = classical_secret + pqc_secret
    elif classical_secret:
        combined_input = classical_secret
    elif pqc_secret:
        combined_input = pqc_secret
    else:
        raise ValueError("No input keying material provided.")

    hkdf = HKDF(
        algorithm=hashes.SHA256(),
        length=32,
        salt=salt,
        info=info_label,
    )
    return hkdf.derive(combined_input)


def derive_hybrid_secret_blake3(classical_secret: bytes, pqc_secret: bytes, info_label: bytes) -> bytes:
    if classical_secret and pqc_secret:
        combined_input = classical_secret + pqc_secret
    elif classical_secret:
        combined_input = classical_secret
    elif pqc_secret:
        combined_input = pqc_secret
    else:
        raise ValueError("No input keying material provided.")

    hasher = blake3.blake3()
    hasher.update(info_label)
    hasher.update(combined_input)
    return hasher.digest(length=32)