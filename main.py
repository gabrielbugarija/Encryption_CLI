from __future__ import annotations
import argparse
import os
import sys
from getpass import getpass

from crypto_mod.file_crypto import encrypt_file, decrypt_file

def default_out_path(in_path: str, mode: str) -> str:
    if mode == "encrypt":
        return in_path + ".svlt"
    if mode == "decrypt":
        if in_path.endswith(".svlt"):
            return in_path[:-5]
        return in_path + ".decrypted"
    raise ValueError("Invalid mode.")


def main() -> int:
    parser = argparse.ArgumentParser(
        prog="securevault",
        description="SecureVault CLI - AES-256-GCM file encryption with PBKDF2-HMAC-SHA256 key derivation.",
    )
    sub = parser.add_subparsers(dest="cmd", required=True)

    enc = sub.add_parser("encrypt", help="Encrypt a file -> .svlt")
    enc.add_argument("input", help="Path to input file")
    enc.add_argument("-o", "--output", help="Output path (default: input + .svlt)")

    dec = sub.add_parser("decrypt", help="Decrypt a .svlt file")
    dec.add_argument("input", help="Path to encrypted .svlt file")
    dec.add_argument("-o", "--output", help="Output path (default: remove .svlt or add .decrypted)")

    args = parser.parse_args()

    in_path = args.input
    if not os.path.exists(in_path):
        print(f"Error: input file not found: {in_path}", file=sys.stderr)
        return 2

    out_path = args.output or default_out_path(in_path, args.cmd)

    password = getpass("Password: ")
    confirm = getpass("Confirm password: ") if args.cmd == "encrypt" else password
    if args.cmd == "encrypt" and password != confirm:
        print("Error: passwords do not match.", file=sys.stderr)
        return 2

    try:
        if args.cmd == "encrypt":
            encrypt_file(in_path, out_path, password=password)
            print(f"Encrypted -> {out_path}")
        else:
            decrypt_file(in_path, out_path, password=password)
            print(f"Decrypted -> {out_path}")
        return 0
    except Exception as e:
        print(f"Error: {e}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())