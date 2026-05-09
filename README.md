# 🛡 SecureDLP — Secure File Transfer & Data Leakage Prevention System

A fully local, zero-knowledge desktop application that encrypts files using AES-256-GCM,
enforces DLP policies before every transfer, creates expiring encrypted sharing links,
and maintains a tamper-evident audit trail — all without any cloud dependency.

---

## Features

| Module | What it does |
|---|---|
| **Encryption Engine** | AES-256-GCM + PBKDF2-SHA256 (310k iterations). Zero-knowledge: key never leaves device |
| **DLP Policy Engine** | Pattern scanning (PII, credit cards, SSNs, API keys…), file-type blocking, recipient rules |
| **Secure Sharing** | Encrypted links with expiry (1h → 1 week), single-use mode, revocation |
| **Audit Log** | SHA-256 hash-chained SQLite log. Every operation recorded. Tamper detection built-in |

---

## Quick Start

### 1. Install dependencies
```bash
pip install cryptography PyQt5
```

### 2. Run the GUI
```bash
python run.py
```

### 3. Run the self-test (no GUI needed)
```bash
python run.py --test
```

---

## Project Structure

```
secure_dlp/
├── core/
│   ├── __init__.py          # Public API exports
│   ├── encryption.py        # AES-256-GCM engine (PBKDF2 key derivation)
│   ├── dlp.py               # DLP policy engine (patterns, file types, recipients)
│   ├── sharing.py           # Encrypted sharing with expiry + revocation
│   └── audit.py             # Hash-chained SQLite audit log
├── ui/
│   └── main_window.py       # PyQt5 desktop GUI (4 tabs)
├── app.py                   # AppController — wires all modules together
└── __init__.py

run.py                       # Entry point (GUI or --test)
requirements.txt
```

---

## Module Details

### 1. Encryption Engine (`core/encryption.py`)

**File format (binary layout):**
```
[6 bytes]  Magic header: SDLP\x01\x00
[32 bytes] PBKDF2 salt (zeros in raw-key mode)
[16 bytes] AES-GCM nonce
[4 bytes]  Metadata length (big-endian uint32)
[N bytes]  JSON metadata (used as AAD — authenticated but not encrypted)
[M bytes]  AES-256-GCM ciphertext + 16-byte authentication tag
```

**Key APIs:**
```python
from secure_dlp.core import FileEncryptionEngine

eng = FileEncryptionEngine()

# Password-based encryption (recommended)
eng.encrypt_file_with_password("secret.pdf", "secret.sdlp", "mypassword")
eng.decrypt_file_with_password("secret.sdlp", "recovered.pdf", "mypassword")

# Raw key (for sharing module)
key = eng.generate_random_key()            # 32 random bytes
eng.encrypt_file("file.txt", "file.sdlp", key)
eng.decrypt_file("file.sdlp", "file.txt", key)

# Sharing tokens (key + expiry packed into URL-safe base64)
token = eng.generate_sharing_token(key, expiry_timestamp)
key, expiry = eng.parse_sharing_token(token)
```

---

### 2. DLP Policy Engine (`core/dlp.py`)

**Built-in patterns:** Credit cards, SSNs, email addresses, IPs, API keys, passwords, phone numbers, IBANs.

**Actions:** `ALLOW` → `WARN` → `QUARANTINE` → `BLOCK`

**Sensitivity levels:** `PUBLIC` → `INTERNAL` → `CONFIDENTIAL` → `RESTRICTED`

```python
from secure_dlp.core import DLPPolicyEngine, DLPPolicy

engine = DLPPolicyEngine()

# Use a preset
engine.set_policy(DLPPolicy.default_strict())

# Evaluate a file
result = engine.evaluate_file("customers.csv", recipient="alice@company.com")
print(result.action)        # PolicyAction.QUARANTINE
print(result.sensitivity)   # SensitivityLevel.RESTRICTED
print(result.risk_score)    # 0–100
print(result.content_matches)   # List[ContentMatch]
print(result.blocked_reasons)   # List[str]

# Custom policy
policy = DLPPolicy(
    name="My Policy",
    block_executables=True,
    block_archives=True,
    max_file_size_mb=25,
    enabled_patterns=["credit_card", "ssn", "api_key"],
    allowed_recipients=["@mycompany.com"],
)
engine.set_policy(policy)
```

---

### 3. Secure Sharing (`core/sharing.py`)

```python
from secure_dlp.core import SecureSharingManager, ShareExpiry

mgr = SecureSharingManager(shares_dir="/path/to/shares")

# Create a share
record = mgr.create_share(
    source_file="report.pdf",
    recipient_email="bob@example.com",
    expiry=ShareExpiry.ONE_DAY,
    single_use=True,          # revoke after first download
)
print(record.share_link)      # sdlp://share/<id>?token=<key+expiry base64>
print(record.expires_in_str)  # "23h"

# Access (recipient side)
result = mgr.access_share(
    share_id=record.share_id,
    token=record.key_token,
    output_dir="/downloads",
)
if result.success:
    print(f"File saved: {result.output_path}")

# Revoke
mgr.revoke_share(record.share_id)   # deletes encrypted file from disk

# List all shares
for s in mgr.list_shares(active_only=True):
    print(s.share_id, s.expires_in_str, s.access_count)
```

**Expiry options:** `ONE_HOUR`, `SIX_HOURS`, `ONE_DAY`, `THREE_DAYS`, `ONE_WEEK`, `NEVER`

---

### 4. Audit Log (`core/audit.py`)

Every event is SHA-256 chained to the previous one — making any retroactive tampering detectable.

```python
from secure_dlp.core import AuditDB, EventType

db = AuditDB("audit.db")

# Log events
db.log(EventType.FILE_ENCRYPTED, file_name="doc.pdf", details={"size": 2048})
db.log(EventType.DLP_BLOCKED, file_name="malware.exe", details={"reason": "executable"})

# Query
events = db.get_events(limit=100, severity="critical", search="malware")
stats  = db.get_stats()   # {"total": N, "today": N, "by_type": {...}, "by_severity": {...}}

# Verify tamper-evidence
ok, bad_id = db.verify_chain()   # (True, None) if intact

# Export
json_str = db.export_json()
```

**Event types:** `file_encrypted`, `file_decrypted`, `file_shared`, `file_accessed`,
`share_revoked`, `dlp_scan`, `dlp_blocked`, `dlp_quarantined`, `dlp_warning`,
`policy_changed`, `app_started`, `error`

---

## AppController (recommended interface)

For the GUI or any integration, use `AppController` which wires all four modules:

```python
from secure_dlp.app import AppController

ctrl = AppController()

# Encrypt (DLP scan runs automatically first)
ok, msg, details = ctrl.encrypt_file("secret.pdf", "password123", "alice@corp.com")

# Decrypt
ok, msg, meta = ctrl.decrypt_file("secret.sdlp", "password123", "/output/dir")

# Share (DLP check runs first)
ok, msg, record = ctrl.create_share("file.pdf", "bob@corp.com", expiry=ShareExpiry.ONE_DAY)

# DLP policy
ctrl.set_policy(DLPPolicy.default_strict())

# Audit
events = ctrl.get_audit_events(limit=50, severity="warning")
ok, bad_id = ctrl.verify_audit_integrity()

ctrl.shutdown()   # persists state, logs APP_STOPPED
```

---

## Data Storage

All data is stored locally in `~/.secure_dlp/`:

```
~/.secure_dlp/
├── audit.db          # SQLite — events, share records, policy config
├── vault/            # Encrypted files (.sdlp)
└── shares/           # Encrypted sharing copies (.sdlp)
```

No network calls. No cloud. Fully offline.

---

## Security Notes

- **AES-256-GCM** — authenticated encryption; any bit flip is detected
- **PBKDF2-SHA256, 310,000 iterations** — aligned with NIST SP 800-132 recommendations
- **Hash-chained audit log** — SHA-256 links every event to the previous; tampering is detectable
- **Metadata as AAD** — file name, size, and recipient are authenticated (not encrypted) so they can be read without the key, but cannot be silently modified
- **Sharing tokens** — embed key + expiry in a single base64 blob; no separate key exchange needed
- **Single-use shares** — marked `ACCESSED` on first download; subsequent attempts are rejected

---

## Requirements

- Python 3.9+
- `cryptography` (AES-256-GCM, PBKDF2)
- `PyQt5` (desktop GUI)
- `sqlite3` (stdlib — audit database)

```
pip install cryptography PyQt5
```
