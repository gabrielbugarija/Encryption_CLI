from __future__ import annotations
import os
from dataclasses import dataclass

from cryptography.hazmat.primitives.ciphers.aead import AESGCM

from .kdf import KDFParams, derive_key, new_salt


MAGIC = b"SVLT"      # file signature
VERSION = b"\x01"    # format version 1


@dataclass(frozen=True)
class FileFormat:
    salt_len: int = 16
    nonce_len: int = 12  # AES-GCM standard nonce length
    tag_len: int = 16    # GCM tag length is included by AESGCM in ciphertext


def _build_header(salt: bytes, nonce: bytes) -> bytes:
    # Header: MAGIC(4) | VERSION(1) | salt_len(1) | nonce_len(1) | salt | nonce
    if len(salt) > 255 or len(nonce) > 255:
        raise ValueError("Salt/nonce too long for 1-byte length fields.")
    return MAGIC + VERSION + bytes([len(salt)]) + bytes([len(nonce)]) + salt + nonce


def _parse_header(blob: bytes) -> tuple[bytes, bytes, bytes]:
    # Returns (aad, salt, nonce)
    if len(blob) < 4 + 1 + 1 + 1:
        raise ValueError("File too small to be a SecureVault file.")

    if blob[:4] != MAGIC:
        raise ValueError("Not a SecureVault file (bad magic).")

    version = blob[4:5]
    if version != VERSION:
        raise ValueError(f"Unsupported SecureVault version: {int.from_bytes(version, 'big')}")

    salt_len = blob[5]
    nonce_len = blob[6]

    header_len = 4 + 1 + 1 + 1 + salt_len + nonce_len
    if len(blob) < header_len:
        raise ValueError("Truncated header.")

    salt = blob[7 : 7 + salt_len]
    nonce = blob[7 + salt_len : header_len]

    aad = blob[:header_len]  # authenticated, not encrypted
    return aad, salt, nonce


def encrypt_bytes(plaintext: bytes, password: str, kdf_params: KDFParams = KDFParams()) -> bytes:
    if not isinstance(plaintext, (bytes, bytearray)):
        raise ValueError("Plaintext must be bytes.")

    salt = new_salt(kdf_params)
    key = derive_key(password=password, salt=salt, params=kdf_params)
    nonce = os.urandom(FileFormat.nonce_len)

    header = _build_header(salt=salt, nonce=nonce)
    aesgcm = AESGCM(key)

    # Use header as AAD so tampering with format/salt/nonce is detected.
    ciphertext = aesgcm.encrypt(nonce=nonce, data=bytes(plaintext), associated_data=header)

    # Best-effort key "zeroization" (Python doesn't guarantee, but we can reduce risk a bit)
    key = b"\x00" * len(key)

    return header + ciphertext


def decrypt_bytes(blob: bytes, password: str, kdf_params: KDFParams = KDFParams()) -> bytes:
    if not isinstance(blob, (bytes, bytearray)):
        raise ValueError("Encrypted blob must be bytes.")

    aad, salt, nonce = _parse_header(bytes(blob))
    key = derive_key(password=password, salt=salt, params=kdf_params)
    aesgcm = AESGCM(key)

    ciphertext = bytes(blob[len(aad):])

    try:
        plaintext = aesgcm.decrypt(nonce=nonce, data=ciphertext, associated_data=aad)
    except Exception as e:
        # Wrong password OR tampered data OR corrupted file
        raise ValueError("Decryption failed (wrong password or file was modified).") from e
    finally:
        key = b"\x00" * len(key)

    return plaintext


def encrypt_file(in_path: str, out_path: str, password: str) -> None:
    with open(in_path, "rb") as f:
        pt = f.read()
    enc = encrypt_bytes(pt, password=password)
    with open(out_path, "wb") as f:
        f.write(enc)


def decrypt_file(in_path: str, out_path: str, password: str) -> None:
    with open(in_path, "rb") as f:
        blob = f.read()
    pt = decrypt_bytes(blob, password=password)
    with open(out_path, "wb") as f:
        f.write(pt)