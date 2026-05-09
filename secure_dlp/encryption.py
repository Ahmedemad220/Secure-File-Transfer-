"""
File Encryption Engine — AES-256-GCM
Provides zero-knowledge local encryption/decryption for all file operations.
"""

import os
import json
import base64
import hashlib
import secrets
from pathlib import Path
from typing import Optional, Tuple

from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.backends import default_backend


def get_random_bytes(n: int) -> bytes:
    return os.urandom(n)


MAGIC_HEADER = b"SDLP\x01\x00"   # Secure-DLP v1.0 signature
SALT_SIZE    = 32
IV_SIZE      = 16
TAG_SIZE     = 16
KEY_SIZE     = 32   # 256-bit
CHUNK_SIZE   = 64 * 1024  # 64 KB chunks for streaming


class EncryptionError(Exception):
    pass


class DecryptionError(Exception):
    pass


class FileEncryptionEngine:
    """
    Handles AES-256-GCM encryption and decryption of files.
    Supports password-based key derivation (PBKDF2-SHA256) and raw key mode.
    """

    def __init__(self):
        pass

    # ── Key derivation ────────────────────────────────────────────────────────

    def derive_key_from_password(self, password: str, salt: Optional[bytes] = None) -> Tuple[bytes, bytes]:
        """Derive a 256-bit key from a password using PBKDF2-SHA256 (310,000 iterations)."""
        if salt is None:
            salt = get_random_bytes(SALT_SIZE)
        kdf = PBKDF2HMAC(
            algorithm=hashes.SHA256(),
            length=KEY_SIZE,
            salt=salt,
            iterations=310_000,
            backend=default_backend()
        )
        key = kdf.derive(password.encode("utf-8"))
        return key, salt

    def generate_random_key(self) -> bytes:
        """Generate a cryptographically random 256-bit key."""
        return get_random_bytes(KEY_SIZE)

    def hash_key(self, key: bytes) -> str:
        """Return a SHA-256 hex digest of the key (for storage/verification, never the key itself)."""
        return hashlib.sha256(key).hexdigest()

    # ── Encrypt ───────────────────────────────────────────────────────────────

    def encrypt_file(
        self,
        source_path: str,
        dest_path: str,
        key: bytes,
        metadata: Optional[dict] = None
    ) -> dict:
        """
        Encrypt a file using AES-256-GCM.

        File format (binary):
            [6]  MAGIC_HEADER
            [32] PBKDF2 salt (zeros if key was provided directly)
            [16] GCM nonce
            [N]  metadata length as 4-byte big-endian uint
            [N]  JSON metadata (encrypted as part of AAD)
            [M]  ciphertext (GCM-encrypted file contents)
            [16] GCM authentication tag

        Returns a dict with encryption metadata (key_hash, original_size, etc.)
        """
        source = Path(source_path)
        if not source.exists():
            raise EncryptionError(f"Source file not found: {source_path}")

        nonce    = get_random_bytes(IV_SIZE)
        aesgcm   = AESGCM(key)

        meta = {
            "filename":      source.name,
            "original_size": source.stat().st_size,
            "key_hash":      self.hash_key(key),
            **(metadata or {})
        }
        meta_bytes = json.dumps(meta).encode("utf-8")

        dest = Path(dest_path)
        dest.parent.mkdir(parents=True, exist_ok=True)

        plaintext  = source.read_bytes()
        # AAD = metadata bytes; AESGCM appends 16-byte tag automatically
        ciphertext_with_tag = aesgcm.encrypt(nonce, plaintext, meta_bytes)

        with open(dest, "wb") as fout:
            fout.write(MAGIC_HEADER)
            fout.write(b"\x00" * SALT_SIZE)
            fout.write(nonce)
            fout.write(len(meta_bytes).to_bytes(4, "big"))
            fout.write(meta_bytes)
            fout.write(ciphertext_with_tag)

        return {
            "key_hash":      meta["key_hash"],
            "original_size": meta["original_size"],
            "encrypted_size": dest.stat().st_size,
            "nonce":          base64.b64encode(nonce).decode(),
            "algorithm":      "AES-256-GCM",
        }

    def encrypt_file_with_password(
        self,
        source_path: str,
        dest_path: str,
        password: str,
        metadata: Optional[dict] = None
    ) -> dict:
        """Encrypt using a password (derives key internally, stores salt in file header)."""
        key, salt = self.derive_key_from_password(password)
        result = self.encrypt_file(source_path, dest_path, key, metadata)

        # Patch the salt into the reserved bytes in the header
        with open(dest_path, "r+b") as f:
            f.seek(len(MAGIC_HEADER))
            f.write(salt)

        result["salt"] = base64.b64encode(salt).decode()
        return result

    # ── Decrypt ───────────────────────────────────────────────────────────────

    def decrypt_file(
        self,
        source_path: str,
        dest_path: str,
        key: bytes
    ) -> dict:
        """
        Decrypt an AES-256-GCM encrypted file.
        Raises DecryptionError if the tag verification fails (tampered or wrong key).
        """
        source = Path(source_path)
        if not source.exists():
            raise DecryptionError(f"Encrypted file not found: {source_path}")

        with open(source, "rb") as f:
            magic = f.read(len(MAGIC_HEADER))
            if magic != MAGIC_HEADER:
                raise DecryptionError("Not a valid SDLP-encrypted file.")

            _salt     = f.read(SALT_SIZE)
            nonce     = f.read(IV_SIZE)
            meta_len  = int.from_bytes(f.read(4), "big")
            meta_bytes = f.read(meta_len)
            ciphertext_with_tag = f.read()   # ciphertext + 16-byte GCM tag

        aesgcm = AESGCM(key)
        try:
            plaintext = aesgcm.decrypt(nonce, ciphertext_with_tag, meta_bytes)
        except Exception:
            raise DecryptionError("Authentication failed — file may be tampered or key is wrong.")

        meta = json.loads(meta_bytes.decode("utf-8"))

        dest = Path(dest_path)
        dest.parent.mkdir(parents=True, exist_ok=True)
        dest.write_bytes(plaintext)

        return meta

    def decrypt_file_with_password(
        self,
        source_path: str,
        dest_path: str,
        password: str
    ) -> dict:
        """Decrypt using a password — reads salt from file header to re-derive the key."""
        with open(source_path, "rb") as f:
            magic = f.read(len(MAGIC_HEADER))
            if magic != MAGIC_HEADER:
                raise DecryptionError("Not a valid SDLP-encrypted file.")
            salt = f.read(SALT_SIZE)

        if salt == b"\x00" * SALT_SIZE:
            raise DecryptionError("File was not encrypted with a password (no salt stored).")

        key, _ = self.derive_key_from_password(password, salt)
        return self.decrypt_file(source_path, dest_path, key)

    # ── Utilities ─────────────────────────────────────────────────────────────

    def generate_sharing_token(self, key: bytes, expiry_ts: int) -> str:
        """
        Pack key + expiry into a URL-safe base64 sharing token.
        Format: base64url(key[32] + expiry[8 big-endian])
        """
        payload = key + expiry_ts.to_bytes(8, "big")
        return base64.urlsafe_b64encode(payload).decode()

    def parse_sharing_token(self, token: str) -> Tuple[bytes, int]:
        """Parse a sharing token back into (key, expiry_timestamp)."""
        try:
            payload = base64.urlsafe_b64decode(token.encode())
            if len(payload) != KEY_SIZE + 8:
                raise ValueError("Invalid token length")
            key    = payload[:KEY_SIZE]
            expiry = int.from_bytes(payload[KEY_SIZE:], "big")
            return key, expiry
        except Exception as e:
            raise EncryptionError(f"Invalid sharing token: {e}")

    def verify_file_integrity(self, encrypted_path: str) -> bool:
        """Quick sanity-check: verify the magic header is present and well-formed."""
        try:
            with open(encrypted_path, "rb") as f:
                return f.read(len(MAGIC_HEADER)) == MAGIC_HEADER
        except OSError:
            return False
