"""
Application Controller
Wires the four core modules together and provides a single clean API
for the GUI layer to call.
"""

import os
import time
import shutil
from pathlib import Path
from typing import Optional, List, Tuple

from .core import (
    FileEncryptionEngine, EncryptionError, DecryptionError,
    DLPPolicyEngine, DLPPolicy, DLPResult, PolicyAction,
    SecureSharingManager, ShareRecord, ShareExpiry,
    AuditDB, EventType,
)


class AppController:
    """
    Single entry-point for all application operations.
    Handles data-flow between encryption, DLP, sharing, and audit.
    """

    APP_DIR     = Path.home() / ".secure_dlp"
    SHARES_DIR  = APP_DIR / "shares"
    VAULT_DIR   = APP_DIR / "vault"
    DB_PATH     = APP_DIR / "audit.db"

    def __init__(self):
        self.APP_DIR.mkdir(exist_ok=True)
        self.SHARES_DIR.mkdir(exist_ok=True)
        self.VAULT_DIR.mkdir(exist_ok=True)

        self.crypto  = FileEncryptionEngine()
        self.audit   = AuditDB(str(self.DB_PATH))
        self.sharing = SecureSharingManager(str(self.SHARES_DIR))
        self.dlp     = DLPPolicyEngine()

        self._load_persisted_state()
        self.audit.log(EventType.APP_STARTED, details={"version": "1.0.0"})

    # ── Lifecycle ─────────────────────────────────────────────────────────────

    def shutdown(self):
        self._persist_state()
        self.audit.log(EventType.APP_STOPPED)

    def _persist_state(self):
        self.audit.save_shares(self.sharing.dump_shares())
        self.audit.save_policy("active", self.dlp.policy.to_dict())

    def _load_persisted_state(self):
        shares = self.audit.load_shares()
        self.sharing.load_shares(shares)

        policy_data = self.audit.load_policy("active")
        if policy_data:
            try:
                self.dlp.set_policy(DLPPolicy.from_dict(policy_data))
            except Exception:
                pass

    # ── Encrypt ───────────────────────────────────────────────────────────────

    def encrypt_file(self, source: str, password: str, recipient: str = "") -> Tuple[bool, str, dict]:
        """
        DLP scan → encrypt → audit.
        Returns (success, message, details_dict)
        """
        dlp_result = self.dlp.evaluate_file(source, recipient or None)

        if dlp_result.action == PolicyAction.BLOCK:
            self.audit.log(
                EventType.DLP_BLOCKED,
                file_name=dlp_result.file_name,
                file_path=source,
                recipient=recipient,
                details=dlp_result.to_dict(),
            )
            reasons = "; ".join(dlp_result.blocked_reasons)
            return False, f"DLP BLOCKED: {reasons}", dlp_result.to_dict()

        if dlp_result.action == PolicyAction.QUARANTINE:
            self.audit.log(
                EventType.DLP_QUARANTINED,
                file_name=dlp_result.file_name,
                file_path=source,
                recipient=recipient,
                details=dlp_result.to_dict(),
            )
            # Quarantine = encrypt to vault but don't share
            dest = str(self.VAULT_DIR / (Path(source).stem + "_quarantined.sdlp"))
        else:
            dest = str(self.VAULT_DIR / (Path(source).stem + ".sdlp"))

        if dlp_result.action == PolicyAction.WARN:
            self.audit.log(
                EventType.DLP_WARNING,
                file_name=dlp_result.file_name,
                file_path=source,
                recipient=recipient,
                details=dlp_result.to_dict(),
            )
        else:
            self.audit.log(
                EventType.DLP_SCAN,
                file_name=dlp_result.file_name,
                file_path=source,
                details=dlp_result.to_dict(),
            )

        try:
            enc_result = self.crypto.encrypt_file_with_password(source, dest, password)
            self.audit.log(
                EventType.FILE_ENCRYPTED,
                file_name=Path(source).name,
                file_path=source,
                recipient=recipient,
                details={**enc_result, "dest": dest},
            )
            msg = "Quarantined (sensitive content detected)" if dlp_result.action == PolicyAction.QUARANTINE else "Encrypted successfully"
            return True, msg, {"encrypted_path": dest, "dlp": dlp_result.to_dict(), **enc_result}
        except Exception as e:
            self.audit.log(EventType.ERROR, file_name=Path(source).name, details={"error": str(e)})
            return False, f"Encryption failed: {e}", {}

    # ── Decrypt ───────────────────────────────────────────────────────────────

    def decrypt_file(self, source: str, password: str, output_dir: str) -> Tuple[bool, str, dict]:
        try:
            out_dir_path = Path(output_dir)
            out_dir_path.mkdir(parents=True, exist_ok=True)

            # Decrypt to a temporary path first, then restore the original filename from metadata.
            temp_output = str(out_dir_path / Path(source).stem.replace("_quarantined", ""))
            meta = self.crypto.decrypt_file_with_password(source, temp_output, password)

            final_name = meta.get("filename", Path(temp_output).name)
            final_output = out_dir_path / final_name
            if Path(temp_output) != final_output:
                if final_output.exists():
                    final_output.unlink()
                Path(temp_output).replace(final_output)

            self.audit.log(
                EventType.FILE_DECRYPTED,
                file_name=Path(source).name,
                file_path=source,
                details={"output_dir": output_dir, "output_path": str(final_output), **meta},
            )
            return True, "Decrypted successfully", {**meta, "output_path": str(final_output)}
        except DecryptionError as e:
            self.audit.log(EventType.ERROR, file_name=Path(source).name, details={"error": str(e)})
            return False, str(e), {}
        except Exception as e:
            return False, f"Unexpected error: {e}", {}

    # ── Sharing ───────────────────────────────────────────────────────────────

    def create_share(
        self,
        source: str,
        recipient: str,
        expiry: ShareExpiry = ShareExpiry.ONE_DAY,
        single_use: bool = False,
        notes: str = ""
    ) -> Tuple[bool, str, Optional[ShareRecord]]:
        # DLP check first
        dlp_result = self.dlp.evaluate_file(source, recipient)
        if dlp_result.action in (PolicyAction.BLOCK, PolicyAction.QUARANTINE, PolicyAction.WARN):
            self.audit.log(
                EventType.DLP_BLOCKED, file_name=Path(source).name,
                file_path=source, recipient=recipient, details=dlp_result.to_dict()
            )
            if dlp_result.blocked_reasons:
                reason = "; ".join(dlp_result.blocked_reasons)
                return False, f"DLP prevented share: {reason}", None
            if dlp_result.content_matches:
                findings = ", ".join(m.pattern_name for m in dlp_result.content_matches[:3])
                if len(dlp_result.content_matches) > 3:
                    findings += ", ..."
                return False, f"DLP prevented share due to sensitive content ({findings})", None
            return False, f"DLP prevented share ({dlp_result.action.value})", None

        try:
            record = self.sharing.create_share(source, recipient, expiry, single_use, notes=notes)
            self.audit.log(
                EventType.FILE_SHARED,
                file_name=Path(source).name,
                file_path=source,
                recipient=recipient,
                details={
                    "share_id":   record.share_id,
                    "expires_in": record.expires_in_str,
                    "single_use": single_use,
                },
            )
            self._persist_state()
            return True, "Share created", record
        except Exception as e:
            self.audit.log(EventType.ERROR, file_name=Path(source).name, details={"error": str(e)})
            return False, str(e), None

    def access_share(self, share_id: str, token: str, output_dir: str, email: str = "") -> Tuple[bool, str]:
        result = self.sharing.access_share(share_id, token, output_dir, email or None)
        event  = EventType.FILE_ACCESSED if result.success else EventType.ERROR
        self.audit.log(
            event,
            file_name=result.record.original_name if result.record else "",
            recipient=email,
            details={"share_id": share_id, "success": result.success, "error": result.error},
        )
        if result.success:
            self._persist_state()
            return True, f"File saved to: {result.output_path}"
        return False, result.error or "Access failed"

    def revoke_share(self, share_id: str) -> bool:
        ok = self.sharing.revoke_share(share_id)
        if ok:
            self.audit.log(EventType.SHARE_REVOKED, details={"share_id": share_id})
            self._persist_state()
        return ok

    def list_shares(self, active_only: bool = False) -> List[ShareRecord]:
        return self.sharing.list_shares(active_only)

    # ── DLP policy management ─────────────────────────────────────────────────

    def set_policy(self, policy: DLPPolicy):
        self.dlp.set_policy(policy)
        self.audit.log(EventType.POLICY_CHANGED, details={"policy_name": policy.name})
        self._persist_state()

    def get_policy(self) -> DLPPolicy:
        return self.dlp.policy

    # ── Audit ─────────────────────────────────────────────────────────────────

    def get_audit_events(self, **kwargs):
        return self.audit.get_events(**kwargs)

    def get_stats(self) -> dict:
        return self.audit.get_stats()

    def verify_audit_integrity(self) -> Tuple[bool, Optional[int]]:
        return self.audit.verify_chain()

    def export_audit(self) -> str:
        return self.audit.export_json()
