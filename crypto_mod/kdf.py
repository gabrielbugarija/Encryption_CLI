from __future__ import annotations
import os
from dataclasses import dataclass

from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives import hashes


@dataclass(frozen=True)
class KDFParams:
    # PBKDF2 iteration count: choose reasonably high for a weekend demo.
    # (In real deployments, tune based on target hardware + policy.)
    iterations: int = 310_000
    salt_len: int = 16
    key_len: int = 32  # 32 bytes = 256-bit key (AES-256)


def new_salt(params: KDFParams = KDFParams()) -> bytes:
    return os.urandom(params.salt_len)


def derive_key(password: str, salt: bytes, params: KDFParams = KDFParams()) -> bytes:
    if not isinstance(password, str) or len(password) == 0:
        raise ValueError("Password must be a non-empty string.")
    if not isinstance(salt, (bytes, bytearray)) or len(salt) < 8:
        raise ValueError("Salt must be bytes (>= 8 bytes).")

    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=params.key_len,
        salt=bytes(salt),
        iterations=params.iterations,
    )
    return kdf.derive(password.encode("utf-8"))