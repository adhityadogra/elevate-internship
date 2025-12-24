#!/usr/bin/env python3
"""
aes_secure_storage.py

AES-256 file encrypt/decrypt utility using:
 - PBKDF2-HMAC-SHA256 for key derivation (salted)
 - AES-GCM (256-bit) for authenticated encryption

Features:
 - encrypt: create `filename.ext.enc` and `filename.ext.enc.meta.json`
 - decrypt: recover original file (writes to a provided output path or same dir)
 - verify: check integrity by comparing stored SHA256 with decrypted content (without writing)
 - metadata: stores original filename, timestamp, plaintext SHA256, base64 salt/nonce, kdf iterations

Dependencies:
 pip install cryptography

Author: ChatGPT (GPT-5 Thinking mini)
"""

import argparse
import base64
import json
import os
import sys
import hashlib
import getpass
from datetime import datetime

from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.backends import default_backend

# ----- Config -----
KDF_ITERATIONS = 200_000  # reasonable default for PBKDF2; adjust for speed/security tradeoff
SALT_SIZE = 16
NONCE_SIZE = 12  # recommended for AESGCM
MAGIC = b"AESSTORE1"  # magic header for potential extension (not written to file to keep format simple)

# ----- Helpers -----


def derive_key(password: bytes, salt: bytes, iterations: int = KDF_ITERATIONS) -> bytes:
    """Derive a 32-byte (256-bit) key from password and salt."""
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=32,
        salt=salt,
        iterations=iterations,
        backend=default_backend(),
    )
    key = kdf.derive(password)
    return key


def sha256_bytes(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def b64(x: bytes) -> str:
    return base64.b64encode(x).decode("utf-8")


def ub64(s: str) -> bytes:
    return base64.b64decode(s.encode("utf-8"))


def write_file(path: str, data: bytes):
    with open(path, "wb") as f:
        f.write(data)


def read_file(path: str) -> bytes:
    with open(path, "rb") as f:
        return f.read()


# ----- Core operations -----


def encrypt_file(input_path: str, password: str, output_path: str = None):
    if not os.path.isfile(input_path):
        raise FileNotFoundError(f"Input file not found: {input_path}")

    data = read_file(input_path)
    salt = os.urandom(SALT_SIZE)
    key = derive_key(password.encode("utf-8"), salt)
    aesgcm = AESGCM(key)
    nonce = os.urandom(NONCE_SIZE)
    ciphertext = aesgcm.encrypt(nonce=nonce, data=data, associated_data=None)

    if output_path is None:
        output_path = input_path + ".enc"

    # File format: raw ciphertext (ciphertext includes auth tag at end).
    write_file(output_path, ciphertext)

    # metadata
    meta = {
        "original_filename": os.path.basename(input_path),
        "original_path": os.path.abspath(input_path),
        "encrypted_filename": os.path.basename(output_path),
        "encrypted_path": os.path.abspath(output_path),
        "timestamp_utc": datetime.utcnow().isoformat() + "Z",
        "plaintext_sha256": sha256_bytes(data),
        "salt_b64": b64(salt),
        "nonce_b64": b64(nonce),
        "kdf": "PBKDF2-HMAC-SHA256",
        "kdf_iterations": KDF_ITERATIONS,
        "aes": "AES-GCM-256",
    }
    meta_path = output_path + ".meta.json"
    with open(meta_path, "w", encoding="utf-8") as mf:
        json.dump(meta, mf, indent=2)

    print(f"Encrypted: {input_path} -> {output_path}")
    print(f"Metadata: {meta_path}")


def decrypt_file(enc_path: str, password: str, out_path: str = None, overwrite: bool = False):
    if not os.path.isfile(enc_path):
        raise FileNotFoundError(f"Encrypted file not found: {enc_path}")

    meta_path = enc_path + ".meta.json"
    if not os.path.isfile(meta_path):
        raise FileNotFoundError(f"Missing metadata file: {meta_path}")

    with open(meta_path, "r", encoding="utf-8") as mf:
        meta = json.load(mf)

    salt = ub64(meta["salt_b64"])
    nonce = ub64(meta["nonce_b64"])
    iterations = meta.get("kdf_iterations", KDF_ITERATIONS)

    key = derive_key(password.encode("utf-8"), salt, iterations)
    aesgcm = AESGCM(key)

    ciphertext = read_file(enc_path)
    try:
        plaintext = aesgcm.decrypt(nonce=nonce, data=ciphertext, associated_data=None)
    except Exception as e:
        raise ValueError("Decryption failed. Wrong password or file corrupted.") from e

    # verify sha256 matches metadata (optional additional check)
    actual_hash = sha256_bytes(plaintext)
    if actual_hash != meta.get("plaintext_sha256"):
        print("Warning: plaintext SHA256 differs from metadata (file may have been modified).")

    if out_path is None:
        # default: original filename in current working directory
        out_path = meta.get("original_filename", "decrypted_output")

    if os.path.exists(out_path) and not overwrite:
        raise FileExistsError(f"Output file exists: {out_path} (use --overwrite to force)")

    write_file(out_path, plaintext)
    print(f"Decrypted: {enc_path} -> {out_path}")


def verify_file(enc_path: str, password: str) -> bool:
    """
    Decrypts in-memory and checks that computed sha256 equals metadata.
    Returns True if checksum matches, else False.
    """
    if not os.path.isfile(enc_path):
        raise FileNotFoundError(f"Encrypted file not found: {enc_path}")

    meta_path = enc_path + ".meta.json"
    if not os.path.isfile(meta_path):
        raise FileNotFoundError(f"Missing metadata file: {meta_path}")

    with open(meta_path, "r", encoding="utf-8") as mf:
        meta = json.load(mf)

    salt = ub64(meta["salt_b64"])
    nonce = ub64(meta["nonce_b64"])
    iterations = meta.get("kdf_iterations", KDF_ITERATIONS)

    key = derive_key(password.encode("utf-8"), salt, iterations)
    aesgcm = AESGCM(key)
    ciphertext = read_file(enc_path)

    try:
        plaintext = aesgcm.decrypt(nonce=nonce, data=ciphertext, associated_data=None)
    except Exception:
        print("Decryption failed. Likely wrong password or corruption.")
        return False

    actual_hash = sha256_bytes(plaintext)
    expected_hash = meta.get("plaintext_sha256")
    if actual_hash == expected_hash:
        print("OK: SHA256 matches metadata.")
        return True
    else:
        print("FAIL: SHA256 does NOT match metadata.")
        return False


# ----- CLI -----
def parse_args():
    p = argparse.ArgumentParser(description="AES-256 Secure File Storage (AES-GCM + PBKDF2)")
    sub = p.add_subparsers(dest="cmd", required=True)

    enc = sub.add_parser("encrypt", help="Encrypt a file")
    enc.add_argument("input", help="Path to input file")
    enc.add_argument("-o", "--output", help="Path to output encrypted file (.enc). Default: input + .enc")

    dec = sub.add_parser("decrypt", help="Decrypt a file")
    dec.add_argument("input", help="Path to .enc file")
    dec.add_argument("-o", "--output", help="Output path for decrypted file. Default: original filename from metadata.")
    dec.add_argument("--overwrite", action="store_true", help="Overwrite output if exists")

    ver = sub.add_parser("verify", help="Verify encrypted file integrity (decrypts in-memory)")
    ver.add_argument("input", help="Path to .enc file")

    p.add_argument("--password-stdin", action="store_true", help="Read password from stdin (non-interactive)")

    return p.parse_args()


def read_password(args) -> str:
    if args.password_stdin:
        pwd = sys.stdin.read().rstrip("\n")
        if not pwd:
            raise ValueError("Empty password from stdin")
        return pwd
    else:
        p1 = getpass.getpass("Password: ")
        # Optional: could prompt twice on encrypt for confirmation
        return p1


def main():
    args = parse_args()
    try:
        if args.cmd == "encrypt":
            pwd = read_password(args)
            encrypt_file(args.input, pwd, output_path=args.output)
        elif args.cmd == "decrypt":
            pwd = read_password(args)
            decrypt_file(args.input, pwd, out_path=args.output, overwrite=args.overwrite)
        elif args.cmd == "verify":
            pwd = read_password(args)
            ok = verify_file(args.input, pwd)
            if not ok:
                sys.exit(2)
        else:
            print("Unknown command")
            sys.exit(1)
    except Exception as e:
        print("ERROR:", str(e))
        sys.exit(1)


if __name__ == "__main__":
    main()
