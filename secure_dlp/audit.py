"""
Audit Logging System
Tamper-evident, timestamped local audit trail stored in SQLite.
Every operation (encrypt, decrypt, share, DLP scan, policy change) is logged.
"""

import sqlite3
import json
import time
import hashlib
import os
from pathlib import Path
from datetime import datetime
from typing import List, Optional, Dict, Any, Tuple
from dataclasses import dataclass, asdict
from enum import Enum
from contextlib import contextmanager


class EventType(str, Enum):
    # File operations
    FILE_ENCRYPTED   = "file_encrypted"
    FILE_DECRYPTED   = "file_decrypted"
    FILE_SHARED      = "file_shared"
    FILE_ACCESSED    = "file_accessed"
    SHARE_REVOKED    = "share_revoked"
    SHARE_EXPIRED    = "share_expired"

    # DLP events
    DLP_SCAN         = "dlp_scan"
    DLP_BLOCKED      = "dlp_blocked"
    DLP_QUARANTINED  = "dlp_quarantined"
    DLP_WARNING      = "dlp_warning"

    # System events
    POLICY_CHANGED   = "policy_changed"
    APP_STARTED      = "app_started"
    APP_STOPPED      = "app_stopped"
    KEY_GENERATED    = "key_generated"
    ERROR            = "error"


class Severity(str, Enum):
    INFO     = "info"
    WARNING  = "warning"
    ERROR    = "error"
    CRITICAL = "critical"


SEVERITY_MAP: Dict[EventType, Severity] = {
    EventType.FILE_ENCRYPTED:  Severity.INFO,
    EventType.FILE_DECRYPTED:  Severity.INFO,
    EventType.FILE_SHARED:     Severity.INFO,
    EventType.FILE_ACCESSED:   Severity.INFO,
    EventType.SHARE_REVOKED:   Severity.WARNING,
    EventType.SHARE_EXPIRED:   Severity.INFO,
    EventType.DLP_SCAN:        Severity.INFO,
    EventType.DLP_BLOCKED:     Severity.CRITICAL,
    EventType.DLP_QUARANTINED: Severity.ERROR,
    EventType.DLP_WARNING:     Severity.WARNING,
    EventType.POLICY_CHANGED:  Severity.WARNING,
    EventType.APP_STARTED:     Severity.INFO,
    EventType.APP_STOPPED:     Severity.INFO,
    EventType.KEY_GENERATED:   Severity.INFO,
    EventType.ERROR:           Severity.ERROR,
}


@dataclass
class AuditEvent:
    event_id:    int
    event_type:  str
    severity:    str
    timestamp:   float
    timestamp_hr: str        # Human-readable ISO timestamp
    user:        str
    file_name:   str
    file_path:   str
    recipient:   str
    details:     dict        # Parsed JSON blob
    hash_chain:  str         # SHA-256(prev_hash + this_event_data)

    def to_dict(self) -> dict:
        d = asdict(self)
        return d

    @property
    def datetime_obj(self) -> datetime:
        return datetime.fromtimestamp(self.timestamp)

    @property
    def severity_color(self) -> str:
        return {
            "info":     "#4CAF50",
            "warning":  "#FF9800",
            "error":    "#F44336",
            "critical": "#9C27B0",
        }.get(self.severity, "#999")


# ── Database schema ───────────────────────────────────────────────────────────

SCHEMA = """
CREATE TABLE IF NOT EXISTS audit_events (
    event_id    INTEGER PRIMARY KEY AUTOINCREMENT,
    event_type  TEXT    NOT NULL,
    severity    TEXT    NOT NULL DEFAULT 'info',
    timestamp   REAL    NOT NULL,
    timestamp_hr TEXT   NOT NULL,
    user        TEXT    NOT NULL DEFAULT 'local',
    file_name   TEXT    NOT NULL DEFAULT '',
    file_path   TEXT    NOT NULL DEFAULT '',
    recipient   TEXT    NOT NULL DEFAULT '',
    details     TEXT    NOT NULL DEFAULT '{}',
    hash_chain  TEXT    NOT NULL DEFAULT ''
);

CREATE TABLE IF NOT EXISTS share_records (
    share_id        TEXT PRIMARY KEY,
    data            TEXT NOT NULL,
    updated_at      REAL NOT NULL
);

CREATE TABLE IF NOT EXISTS dlp_policies (
    policy_name     TEXT PRIMARY KEY,
    data            TEXT NOT NULL,
    updated_at      REAL NOT NULL
);

CREATE INDEX IF NOT EXISTS idx_timestamp  ON audit_events(timestamp);
CREATE INDEX IF NOT EXISTS idx_event_type ON audit_events(event_type);
CREATE INDEX IF NOT EXISTS idx_severity   ON audit_events(severity);
CREATE INDEX IF NOT EXISTS idx_file_name  ON audit_events(file_name);
"""


class AuditDB:
    """
    SQLite-backed audit database.
    Uses a hash-chain over log entries to detect tampering.
    """

    def __init__(self, db_path: str):
        self.db_path = str(db_path)
        Path(self.db_path).parent.mkdir(parents=True, exist_ok=True)
        self._init_db()
        self._last_hash = self._get_last_hash()
        self._user = os.environ.get("USER", os.environ.get("USERNAME", "local"))

    # ── Init ──────────────────────────────────────────────────────────────────

    def _init_db(self):
        with self._conn() as conn:
            conn.executescript(SCHEMA)

    @contextmanager
    def _conn(self):
        conn = sqlite3.connect(self.db_path, timeout=10)
        conn.row_factory = sqlite3.Row
        try:
            yield conn
            conn.commit()
        finally:
            conn.close()

    # ── Hash chain ────────────────────────────────────────────────────────────

    def _get_last_hash(self) -> str:
        with self._conn() as conn:
            row = conn.execute(
                "SELECT hash_chain FROM audit_events ORDER BY event_id DESC LIMIT 1"
            ).fetchone()
            return row["hash_chain"] if row else "GENESIS"

    def _compute_hash(self, prev_hash: str, event_data: str) -> str:
        payload = f"{prev_hash}|{event_data}"
        return hashlib.sha256(payload.encode()).hexdigest()

    # ── Log ───────────────────────────────────────────────────────────────────

    def log(
        self,
        event_type: EventType,
        file_name:  str = "",
        file_path:  str = "",
        recipient:  str = "",
        details:    Optional[dict] = None,
        user:       Optional[str] = None,
    ) -> int:
        """Insert an audit event. Returns the new event_id."""
        now      = time.time()
        ts_hr    = datetime.fromtimestamp(now).isoformat(timespec="seconds")
        severity = SEVERITY_MAP.get(event_type, Severity.INFO).value
        det_str  = json.dumps(details or {})
        usr      = user or self._user

        event_data = f"{event_type.value}|{ts_hr}|{usr}|{file_name}|{det_str}"
        chain_hash = self._compute_hash(self._last_hash, event_data)
        self._last_hash = chain_hash

        with self._conn() as conn:
            cur = conn.execute(
                """INSERT INTO audit_events
                   (event_type, severity, timestamp, timestamp_hr, user,
                    file_name, file_path, recipient, details, hash_chain)
                   VALUES (?,?,?,?,?,?,?,?,?,?)""",
                (event_type.value, severity, now, ts_hr, usr,
                 file_name, file_path, recipient, det_str, chain_hash)
            )
            return cur.lastrowid

    # ── Query ─────────────────────────────────────────────────────────────────

    def get_events(
        self,
        limit:      int = 200,
        event_type: Optional[str] = None,
        severity:   Optional[str] = None,
        since:      Optional[float] = None,
        search:     Optional[str] = None,
    ) -> List[AuditEvent]:
        clauses, params = [], []
        if event_type:
            clauses.append("event_type = ?"); params.append(event_type)
        if severity:
            clauses.append("severity = ?"); params.append(severity)
        if since:
            clauses.append("timestamp >= ?"); params.append(since)
        if search:
            clauses.append("(file_name LIKE ? OR recipient LIKE ? OR details LIKE ?)")
            params += [f"%{search}%", f"%{search}%", f"%{search}%"]

        where = ("WHERE " + " AND ".join(clauses)) if clauses else ""
        params.append(limit)

        with self._conn() as conn:
            rows = conn.execute(
                f"SELECT * FROM audit_events {where} ORDER BY timestamp DESC LIMIT ?",
                params
            ).fetchall()

        return [self._row_to_event(r) for r in rows]

    def get_stats(self) -> dict:
        with self._conn() as conn:
            total       = conn.execute("SELECT COUNT(*) FROM audit_events").fetchone()[0]
            by_type     = conn.execute(
                "SELECT event_type, COUNT(*) as c FROM audit_events GROUP BY event_type"
            ).fetchall()
            by_severity = conn.execute(
                "SELECT severity, COUNT(*) as c FROM audit_events GROUP BY severity"
            ).fetchall()
            today       = conn.execute(
                "SELECT COUNT(*) FROM audit_events WHERE timestamp >= ?",
                (time.time() - 86400,)
            ).fetchone()[0]

        return {
            "total":       total,
            "today":       today,
            "by_type":     {r["event_type"]: r["c"] for r in by_type},
            "by_severity": {r["severity"]: r["c"] for r in by_severity},
        }

    def verify_chain(self) -> Tuple[bool, Optional[int]]:
        """
        Walk the hash chain and verify no entries were tampered with.
        Returns (True, None) if intact, (False, first_bad_event_id) if broken.
        """
        with self._conn() as conn:
            rows = conn.execute(
                "SELECT * FROM audit_events ORDER BY event_id ASC"
            ).fetchall()

        prev = "GENESIS"
        for row in rows:
            det = row["details"]
            event_data = f"{row['event_type']}|{row['timestamp_hr']}|{row['user']}|{row['file_name']}|{det}"
            expected = self._compute_hash(prev, event_data)
            if expected != row["hash_chain"]:
                return False, row["event_id"]
            prev = row["hash_chain"]

        return True, None

    def export_json(self, since: Optional[float] = None) -> str:
        events = self.get_events(limit=100_000, since=since)
        return json.dumps([e.to_dict() for e in events], indent=2)

    # ── Share persistence ─────────────────────────────────────────────────────

    def save_shares(self, share_data: list):
        with self._conn() as conn:
            conn.execute("DELETE FROM share_records")
            for record in share_data:
                conn.execute(
                    "INSERT INTO share_records (share_id, data, updated_at) VALUES (?,?,?)",
                    (record["share_id"], json.dumps(record), time.time())
                )

    def load_shares(self) -> list:
        with self._conn() as conn:
            rows = conn.execute("SELECT data FROM share_records").fetchall()
        return [json.loads(r["data"]) for r in rows]

    # ── Policy persistence ────────────────────────────────────────────────────

    def save_policy(self, name: str, data: dict):
        with self._conn() as conn:
            conn.execute(
                "INSERT OR REPLACE INTO dlp_policies (policy_name, data, updated_at) VALUES (?,?,?)",
                (name, json.dumps(data), time.time())
            )

    def load_policy(self, name: str) -> Optional[dict]:
        with self._conn() as conn:
            row = conn.execute(
                "SELECT data FROM dlp_policies WHERE policy_name = ?", (name,)
            ).fetchone()
        return json.loads(row["data"]) if row else None

    # ── Internal ──────────────────────────────────────────────────────────────

    def _row_to_event(self, row) -> AuditEvent:
        try:
            details = json.loads(row["details"])
        except Exception:
            details = {}
        return AuditEvent(
            event_id=row["event_id"],
            event_type=row["event_type"],
            severity=row["severity"],
            timestamp=row["timestamp"],
            timestamp_hr=row["timestamp_hr"],
            user=row["user"],
            file_name=row["file_name"],
            file_path=row["file_path"],
            recipient=row["recipient"],
            details=details,
            hash_chain=row["hash_chain"],
        )
