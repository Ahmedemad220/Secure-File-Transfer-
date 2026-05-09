"""
Secure File Sharing Module
Creates encrypted sharing tokens with TTL, manages share lifecycle,
and handles link generation and validation.
"""

import os
import uuid
import json
import time
import hashlib
import secrets
import base64
from pathlib import Path
from datetime import datetime, timedelta
from typing import Optional, Dict, List
from dataclasses import dataclass, asdict, field
from enum import Enum

from .encryption import FileEncryptionEngine, EncryptionError, DecryptionError


class ShareStatus(str, Enum):
    ACTIVE   = "active"
    EXPIRED  = "expired"
    REVOKED  = "revoked"
    ACCESSED = "accessed"   # single-use share that was consumed


class ShareExpiry(int, Enum):
    ONE_HOUR   = 3600
    SIX_HOURS  = 21600
    ONE_DAY    = 86400
    THREE_DAYS = 259200
    ONE_WEEK   = 604800
    NEVER      = 0           # 0 = no expiry


@dataclass
class ShareRecord:
    share_id:        str
    encrypted_path:  str
    original_name:   str
    created_at:      float
    expires_at:      float          # 0 = never
    recipient_email: str
    single_use:      bool
    access_count:    int
    max_access:      int            # 0 = unlimited
    status:          ShareStatus
    key_token:       str            # base64url-encoded key+expiry blob
    notes:           str = ""

    def to_dict(self) -> dict:
        d = asdict(self)
        d["status"] = self.status.value
        return d

    @classmethod
    def from_dict(cls, d: dict) -> "ShareRecord":
        d = d.copy()
        d["status"] = ShareStatus(d["status"])
        return cls(**d)

    @property
    def is_expired(self) -> bool:
        if self.expires_at == 0:
            return False
        return time.time() > self.expires_at

    @property
    def is_active(self) -> bool:
        return (
            self.status == ShareStatus.ACTIVE
            and not self.is_expired
            and (self.max_access == 0 or self.access_count < self.max_access)
        )

    @property
    def expires_in_str(self) -> str:
        if self.expires_at == 0:
            return "Never"
        remaining = self.expires_at - time.time()
        if remaining <= 0:
            return "Expired"
        if remaining < 60:
            return f"{int(remaining)}s"
        if remaining < 3600:
            return f"{int(remaining/60)}m"
        if remaining < 86400:
            return f"{int(remaining/3600)}h"
        return f"{int(remaining/86400)}d"

    @property
    def share_link(self) -> str:
        """Human-readable share token (not a real URL — for local transfer)."""
        return f"sdlp://share/{self.share_id}?token={self.key_token}"


@dataclass
class ShareAccessResult:
    success:     bool
    record:      Optional[ShareRecord]
    output_path: Optional[str]
    error:       Optional[str] = None


class SecureSharingManager:
    """
    Manages the full lifecycle of encrypted file shares:
    create → share link → recipient accesses → decrypt & deliver.
    All share records are stored in-memory; persistence is handled by the AuditDB.
    """

    def __init__(self, shares_dir: str):
        self.shares_dir = Path(shares_dir)
        self.shares_dir.mkdir(parents=True, exist_ok=True)
        self._engine = FileEncryptionEngine()
        self._shares: Dict[str, ShareRecord] = {}   # share_id -> ShareRecord

    # ── Create ────────────────────────────────────────────────────────────────

    def create_share(
        self,
        source_file: str,
        recipient_email: str,
        expiry: ShareExpiry = ShareExpiry.ONE_DAY,
        single_use: bool = False,
        max_access: int = 0,
        notes: str = ""
    ) -> ShareRecord:
        """
        Encrypt the source file and create a share record with a scoped key token.

        The share token embeds the decryption key + expiry timestamp so the recipient
        needs only the token to decrypt — no separate key exchange.
        """
        source = Path(source_file)
        if not source.exists():
            raise FileNotFoundError(f"Source file not found: {source_file}")

        share_id = secrets.token_urlsafe(16)
        key      = self._engine.generate_random_key()
        now      = time.time()
        expires  = (now + expiry.value) if expiry != ShareExpiry.NEVER else 0

        # Store encrypted file in shares directory
        enc_name = f"{share_id}.sdlp"
        enc_path = self.shares_dir / enc_name

        metadata = {
            "share_id":   share_id,
            "recipient":  recipient_email,
            "created_at": now,
            "expires_at": expires,
        }
        self._engine.encrypt_file(str(source), str(enc_path), key, metadata)

        # Build a token that embeds key + expiry (so recipient can self-service)
        key_token = self._engine.generate_sharing_token(key, int(expires) if expires else 0)

        record = ShareRecord(
            share_id=share_id,
            encrypted_path=str(enc_path),
            original_name=source.name,
            created_at=now,
            expires_at=expires,
            recipient_email=recipient_email,
            single_use=single_use,
            access_count=0,
            max_access=max_access,
            status=ShareStatus.ACTIVE,
            key_token=key_token,
            notes=notes,
        )

        self._shares[share_id] = record
        return record

    # ── Access ────────────────────────────────────────────────────────────────

    def access_share(
        self,
        share_id: str,
        token: str,
        output_dir: str,
        recipient_email: Optional[str] = None
    ) -> ShareAccessResult:
        """
        Verify the token, check expiry/access limits, and decrypt the file.
        """
        record = self._shares.get(share_id)
        if not record:
            return ShareAccessResult(False, None, None, "Share not found")

        if record.status == ShareStatus.REVOKED:
            return ShareAccessResult(False, record, None, "Share has been revoked")

        if record.status == ShareStatus.ACCESSED:
            return ShareAccessResult(False, record, None, "Single-use share has already been accessed")

        if record.is_expired:
            record.status = ShareStatus.EXPIRED
            return ShareAccessResult(False, record, None, "Share link has expired")

        if record.max_access > 0 and record.access_count >= record.max_access:
            return ShareAccessResult(False, record, None, "Maximum access count reached")

        if recipient_email and record.recipient_email.lower() != recipient_email.lower():
            return ShareAccessResult(False, record, None, "Recipient email mismatch")

        # Decode token
        try:
            key, token_expiry = self._engine.parse_sharing_token(token)
        except EncryptionError as e:
            return ShareAccessResult(False, record, None, str(e))

        # Validate token expiry (0 = never)
        if token_expiry != 0 and time.time() > token_expiry:
            return ShareAccessResult(False, record, None, "Token has expired")

        # Decrypt
        output_path = str(Path(output_dir) / record.original_name)
        try:
            self._engine.decrypt_file(record.encrypted_path, output_path, key)
        except DecryptionError as e:
            return ShareAccessResult(False, record, None, f"Decryption failed: {e}")

        # Update record
        record.access_count += 1
        if record.single_use:
            record.status = ShareStatus.ACCESSED

        return ShareAccessResult(True, record, output_path)

    # ── Management ────────────────────────────────────────────────────────────

    def revoke_share(self, share_id: str) -> bool:
        record = self._shares.get(share_id)
        if not record:
            return False
        record.status = ShareStatus.REVOKED
        # Remove the encrypted file from disk
        try:
            Path(record.encrypted_path).unlink(missing_ok=True)
        except OSError:
            pass
        return True

    def list_shares(self, active_only: bool = False) -> List[ShareRecord]:
        shares = list(self._shares.values())
        # Update expired statuses
        for s in shares:
            if s.status == ShareStatus.ACTIVE and s.is_expired:
                s.status = ShareStatus.EXPIRED
        if active_only:
            return [s for s in shares if s.status == ShareStatus.ACTIVE]
        return sorted(shares, key=lambda s: s.created_at, reverse=True)

    def get_share(self, share_id: str) -> Optional[ShareRecord]:
        return self._shares.get(share_id)

    def cleanup_expired(self) -> int:
        """Remove expired/revoked encrypted files from disk. Returns count removed."""
        removed = 0
        for record in list(self._shares.values()):
            if record.status in (ShareStatus.EXPIRED, ShareStatus.REVOKED, ShareStatus.ACCESSED):
                try:
                    Path(record.encrypted_path).unlink(missing_ok=True)
                    removed += 1
                except OSError:
                    pass
        return removed

    def load_shares(self, records: List[dict]):
        """Restore share records from persisted dicts (called by AuditDB on startup)."""
        for d in records:
            try:
                r = ShareRecord.from_dict(d)
                # Don't restore if encrypted file is missing
                if Path(r.encrypted_path).exists() or r.status != ShareStatus.ACTIVE:
                    self._shares[r.share_id] = r
            except Exception:
                pass

    def dump_shares(self) -> List[dict]:
        """Serialize all share records for persistence."""
        return [r.to_dict() for r in self._shares.values()]
