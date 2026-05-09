#!/usr/bin/env python3
"""
run.py — Launch the SecureDLP desktop application.
Usage:
    python run.py             # Launch GUI
    python run.py --test      # Run a headless self-test of all four core modules
"""

import sys
import os

sys.path.insert(0, os.path.dirname(__file__))


def run_gui():
    from secure_dlp.ui.main_window import main
    main()


def run_selftest():
    """Quick smoke-test of all four modules without a GUI."""
    import tempfile
    import time
    from pathlib import Path

    print("\nSecureDLP - Self-Test\n" + "=" * 48)

    # ── 1. Encryption ─────────────────────────────────────────────────────────
    print("\n[1] Encryption Engine (AES-256-GCM)")
    from secure_dlp.core import FileEncryptionEngine, DecryptionError

    eng = FileEncryptionEngine()
    with tempfile.TemporaryDirectory() as tmp:
        # Write a test file
        src = Path(tmp) / "test.txt"
        src.write_text("Hello World — this is a test document with sensitive data: 4111111111111111")

        enc = Path(tmp) / "test.sdlp"
        dec = Path(tmp) / "test_decrypted.txt"

        result = eng.encrypt_file_with_password(str(src), str(enc), "hunter2")
        print(f"   [OK] Encrypted: {result['original_size']} bytes -> {result['encrypted_size']} bytes")

        meta = eng.decrypt_file_with_password(str(enc), str(dec), "hunter2")
        assert dec.read_text() == src.read_text(), "Decrypted content mismatch!"
        print(f"   [OK] Decrypted: '{meta['filename']}' matches original")

        try:
            eng.decrypt_file_with_password(str(enc), str(Path(tmp) / "bad.txt"), "wrongpassword")
            print("   [FAIL] Should have raised DecryptionError!")
        except DecryptionError:
            print("   [OK] Wrong password correctly rejected")

    # ── 2. DLP ────────────────────────────────────────────────────────────────
    print("\n[2] DLP Policy Engine")
    from secure_dlp.core import DLPPolicyEngine, DLPPolicy, PolicyAction

    engine = DLPPolicyEngine()

    with tempfile.TemporaryDirectory() as tmp:
        # Clean file
        clean = Path(tmp) / "report.txt"
        clean.write_text("This is a quarterly business report with no sensitive information.")
        r = engine.evaluate_file(str(clean))
        assert r.action == PolicyAction.ALLOW, f"Expected ALLOW, got {r.action}"
        print(f"   [OK] Clean file -> {r.action.value.upper()} (risk: {r.risk_score})")

        # PII file
        pii = Path(tmp) / "customers.txt"
        pii.write_text("Name: John Doe\nSSN: 123-45-6789\nCard: 4111111111111111\nEmail: john@example.com")
        r = engine.evaluate_file(str(pii))
        print(f"   [OK] PII file -> {r.action.value.upper()} (sensitivity: {r.sensitivity.value}, risk: {r.risk_score})")
        assert len(r.content_matches) > 0, "Expected content matches"

        # Blocked type
        exe = Path(tmp) / "setup.exe"
        exe.write_bytes(b"MZ\x90\x00")  # PE header magic
        r = engine.evaluate_file(str(exe))
        assert r.action == PolicyAction.BLOCK, f"Expected BLOCK, got {r.action}"
        print(f"   [OK] Executable -> {r.action.value.upper()} ({r.blocked_reasons[0]})")

    # ── 3. Sharing ────────────────────────────────────────────────────────────
    print("\n[3] Secure Sharing")
    from secure_dlp.core import SecureSharingManager, ShareExpiry, ShareStatus

    with tempfile.TemporaryDirectory() as tmp:
        mgr = SecureSharingManager(tmp + "/shares")
        src = Path(tmp) / "shared.txt"
        src.write_text("Confidential content for recipient only.")

        record = mgr.create_share(str(src), "alice@example.com", ShareExpiry.ONE_HOUR, single_use=True)
        print(f"   [OK] Share created: {record.share_id[:8]}... expires in {record.expires_in_str}")
        assert record.is_active

        out_dir = tmp + "/received"
        os.makedirs(out_dir)
        result = mgr.access_share(record.share_id, record.key_token, out_dir)
        assert result.success, f"Access failed: {result.error}"
        assert Path(result.output_path).read_text() == src.read_text()
        print(f"   [OK] File accessed and decrypted: {result.output_path}")
        assert record.status == ShareStatus.ACCESSED, "Single-use share should be ACCESSED"
        print(f"   [OK] Single-use share status: {record.status.value}")

        # Try again (should fail)
        result2 = mgr.access_share(record.share_id, record.key_token, out_dir)
        assert not result2.success
        print(f"   [OK] Second access correctly denied: '{result2.error}'")

    # ── 4. Audit ──────────────────────────────────────────────────────────────
    print("\n[4] Audit Log & Hash Chain")
    from secure_dlp.core import AuditDB, EventType

    with tempfile.TemporaryDirectory() as tmp:
        db = AuditDB(tmp + "/audit.db")
        db.log(EventType.APP_STARTED, details={"version": "1.0"})
        db.log(EventType.FILE_ENCRYPTED, file_name="doc.txt", details={"size": 1024})
        db.log(EventType.DLP_BLOCKED, file_name="bad.exe", details={"reason": "executable"})

        events = db.get_events()
        assert len(events) == 3
        print(f"   [OK] {len(events)} events logged")

        ok, bad_id = db.verify_chain()
        assert ok, f"Chain broken at {bad_id}"
        print(f"   [OK] Hash chain integrity verified")

        stats = db.get_stats()
        print(f"   [OK] Stats: {stats['total']} total, {stats['by_severity']} by severity")

    print("\n" + "=" * 48)
    print("[OK] All tests passed!\n")


if __name__ == "__main__":
    if "--test" in sys.argv:
        run_selftest()
    else:
        run_gui()
