"""
DLP Policy Engine
Enforces data-loss-prevention rules: pattern matching, file-type restrictions,
recipient allow-lists, and size limits.
"""

import re
import os
import json
import mimetypes
from pathlib import Path
from dataclasses import dataclass, field, asdict
from typing import List, Optional, Dict, Any
from enum import Enum


class PolicyAction(str, Enum):
    ALLOW      = "allow"
    BLOCK      = "block"
    QUARANTINE = "quarantine"
    WARN       = "warn"


class SensitivityLevel(str, Enum):
    PUBLIC       = "public"
    INTERNAL     = "internal"
    CONFIDENTIAL = "confidential"
    RESTRICTED   = "restricted"


# ── Built-in sensitive content patterns ──────────────────────────────────────

BUILTIN_PATTERNS = {
    "credit_card": {
        "description": "Credit / debit card numbers",
        "pattern": r"\b(?:4[0-9]{12}(?:[0-9]{3})?|5[1-5][0-9]{14}|3[47][0-9]{13}|3(?:0[0-5]|[68][0-9])[0-9]{11}|6(?:011|5[0-9]{2})[0-9]{12}|(?:2131|1800|35\d{3})\d{11})\b",
        "severity": "high",
    },
    "ssn": {
        "description": "US Social Security Numbers",
        "pattern": r"\b(?!000|666|9\d{2})\d{3}-(?!00)\d{2}-(?!0000)\d{4}\b",
        "severity": "high",
    },
    "email_address": {
        "description": "Email addresses",
        "pattern": r"\b[A-Za-z0-9._%+\-]+@[A-Za-z0-9.\-]+\.[A-Za-z]{2,}\b",
        "severity": "medium",
    },
    "ip_address": {
        "description": "IPv4 addresses",
        "pattern": r"\b(?:25[0-5]|2[0-4]\d|[01]?\d\d?)\.(?:25[0-5]|2[0-4]\d|[01]?\d\d?)\.(?:25[0-5]|2[0-4]\d|[01]?\d\d?)\.(?:25[0-5]|2[0-4]\d|[01]?\d\d?)\b",
        "severity": "low",
    },
    "api_key": {
        "description": "Potential API keys / tokens",
        "pattern": r"\b(?:api[_-]?key|apikey|access[_-]?token|secret[_-]?key)\s*[:=]\s*['\"]?[A-Za-z0-9\-_]{20,}['\"]?",
        "severity": "critical",
    },
    "password_field": {
        "description": "Hardcoded passwords in text",
        "pattern": r"(?i)\bpassword\s*[:=]\s*['\"]?.{4,}['\"]?",
        "severity": "critical",
    },
    "phone_number": {
        "description": "US/international phone numbers",
        "pattern": r"\b(?:\+?1[-.\s]?)?\(?\d{3}\)?[-.\s]\d{3}[-.\s]\d{4}\b",
        "severity": "medium",
    },
    "iban": {
        "description": "International Bank Account Numbers",
        "pattern": r"\b[A-Z]{2}\d{2}[A-Z0-9]{4}\d{7}(?:[A-Z0-9]?){0,16}\b",
        "severity": "high",
    },
}

# ── Blocked file types by category ───────────────────────────────────────────

BLOCKED_EXTENSIONS = {
    "executable": [".exe", ".bat", ".cmd", ".com", ".scr", ".pif", ".vbs", ".ps1", ".msi", ".dll"],
    "script":     [".sh", ".bash", ".zsh", ".py", ".rb", ".pl", ".php", ".js", ".ts"],
    "archive":    [".zip", ".tar", ".gz", ".rar", ".7z", ".bz2"],
    "database":   [".sql", ".db", ".sqlite", ".mdb", ".accdb"],
    "key_cert":   [".pem", ".key", ".pfx", ".p12", ".cer", ".crt", ".p8"],
}

MAX_SCAN_BYTES = 10 * 1024 * 1024  # Scan first 10 MB of text files


# ── Data structures ───────────────────────────────────────────────────────────

@dataclass
class ContentMatch:
    pattern_name: str
    description:  str
    severity:     str
    match_count:  int
    sample:       str = ""          # redacted sample for the audit log


@dataclass
class DLPResult:
    file_path:       str
    file_name:       str
    file_size:       int
    file_extension:  str
    action:          PolicyAction
    sensitivity:     SensitivityLevel
    content_matches: List[ContentMatch] = field(default_factory=list)
    blocked_reasons: List[str]          = field(default_factory=list)
    warnings:        List[str]          = field(default_factory=list)
    scanned_bytes:   int = 0

    def to_dict(self) -> dict:
        d = asdict(self)
        d["action"]      = self.action.value
        d["sensitivity"] = self.sensitivity.value
        d["content_matches"] = [asdict(m) for m in self.content_matches]
        return d

    @property
    def is_allowed(self) -> bool:
        return self.action in (PolicyAction.ALLOW, PolicyAction.WARN)

    @property
    def risk_score(self) -> int:
        """0–100 risk score based on findings."""
        severity_weights = {"critical": 40, "high": 25, "medium": 10, "low": 3}
        score = sum(
            severity_weights.get(m.severity, 0) * min(m.match_count, 3)
            for m in self.content_matches
        )
        if self.action == PolicyAction.BLOCK:
            score = max(score, 80)
        return min(score, 100)


@dataclass
class DLPPolicy:
    name:                  str
    enabled:               bool = True
    block_executables:     bool = True
    block_scripts:         bool = True
    block_archives:        bool = False
    block_databases:       bool = True
    block_key_files:       bool = True
    max_file_size_mb:      int  = 100
    enabled_patterns:      List[str] = field(default_factory=lambda: list(BUILTIN_PATTERNS.keys()))
    custom_patterns:       Dict[str, str] = field(default_factory=dict)  # name -> regex
    allowed_recipients:    List[str] = field(default_factory=list)        # email allow-list
    blocked_recipients:    List[str] = field(default_factory=list)        # email block-list
    auto_classify:         bool = True
    quarantine_on_sensitive: bool = True

    def to_dict(self) -> dict:
        return asdict(self)

    @classmethod
    def from_dict(cls, d: dict) -> "DLPPolicy":
        return cls(**{k: v for k, v in d.items() if k in cls.__dataclass_fields__})

    @classmethod
    def default_strict(cls) -> "DLPPolicy":
        return cls(name="Strict", block_archives=True, max_file_size_mb=50)

    @classmethod
    def default_standard(cls) -> "DLPPolicy":
        return cls(name="Standard")

    @classmethod
    def default_permissive(cls) -> "DLPPolicy":
        return cls(
            name="Permissive",
            block_scripts=False,
            block_databases=False,
            enabled_patterns=["credit_card", "ssn", "api_key", "password_field"],
        )


# ── Engine ────────────────────────────────────────────────────────────────────

class DLPPolicyEngine:
    """
    Evaluates a file against a DLPPolicy and returns a DLPResult.
    Combines: file-type rules, content pattern scanning, size limits, recipient checks.
    """

    def __init__(self, policy: Optional[DLPPolicy] = None):
        self.policy = policy or DLPPolicy.default_standard()
        self._compiled: Dict[str, re.Pattern] = {}
        self._compile_patterns()

    def set_policy(self, policy: DLPPolicy):
        self.policy = policy
        self._compiled.clear()
        self._compile_patterns()

    def _compile_patterns(self):
        for name in self.policy.enabled_patterns:
            if name in BUILTIN_PATTERNS:
                try:
                    self._compiled[name] = re.compile(
                        BUILTIN_PATTERNS[name]["pattern"], re.IGNORECASE | re.MULTILINE
                    )
                except re.error:
                    pass
        for name, pat in self.policy.custom_patterns.items():
            try:
                self._compiled[name] = re.compile(pat, re.IGNORECASE | re.MULTILINE)
            except re.error:
                pass

    # ── Public API ────────────────────────────────────────────────────────────

    def evaluate_file(self, file_path: str, recipient: Optional[str] = None) -> DLPResult:
        """Full DLP evaluation of a file. Returns a DLPResult with action and findings."""
        path = Path(file_path)
        ext  = path.suffix.lower()
        size = path.stat().st_size if path.exists() else 0

        result = DLPResult(
            file_path=str(path),
            file_name=path.name,
            file_size=size,
            file_extension=ext,
            action=PolicyAction.ALLOW,
            sensitivity=SensitivityLevel.PUBLIC,
        )

        self._check_file_type(result, ext)
        self._check_file_size(result, size)

        if recipient:
            self._check_recipient(result, recipient)

        if path.exists() and result.action != PolicyAction.BLOCK:
            self._scan_content(result, path)

        self._classify_sensitivity(result)
        self._determine_final_action(result)

        return result

    def check_recipient(self, recipient: str) -> PolicyAction:
        """Quick recipient-only check without a file."""
        recipient = recipient.lower().strip()
        if any(b.lower() in recipient for b in self.policy.blocked_recipients):
            return PolicyAction.BLOCK
        if self.policy.allowed_recipients:
            if not any(a.lower() in recipient for a in self.policy.allowed_recipients):
                return PolicyAction.WARN
        return PolicyAction.ALLOW

    # ── Internal checks ───────────────────────────────────────────────────────

    def _check_file_type(self, result: DLPResult, ext: str):
        checks = [
            (self.policy.block_executables, "executable"),
            (self.policy.block_scripts,     "script"),
            (self.policy.block_archives,    "archive"),
            (self.policy.block_databases,   "database"),
            (self.policy.block_key_files,   "key_cert"),
        ]
        for enabled, category in checks:
            if enabled and ext in BLOCKED_EXTENSIONS.get(category, []):
                result.action = PolicyAction.BLOCK
                result.blocked_reasons.append(f"Blocked file type: {category} ({ext})")

    def _check_file_size(self, result: DLPResult, size: int):
        limit = self.policy.max_file_size_mb * 1024 * 1024
        if size > limit:
            result.action = PolicyAction.BLOCK
            result.blocked_reasons.append(
                f"File size {size // (1024*1024)} MB exceeds limit of {self.policy.max_file_size_mb} MB"
            )

    def _check_recipient(self, result: DLPResult, recipient: str):
        r = recipient.lower().strip()
        if any(b.lower() in r for b in self.policy.blocked_recipients):
            result.action = PolicyAction.BLOCK
            result.blocked_reasons.append(f"Recipient '{recipient}' is on the block-list")
            return
        if self.policy.allowed_recipients:
            if not any(a.lower() in r for a in self.policy.allowed_recipients):
                result.warnings.append(f"Recipient '{recipient}' is not on the allow-list")

    def _scan_content(self, result: DLPResult, path: Path):
        """Scan file content for sensitive patterns (text files only)."""
        mime, _ = mimetypes.guess_type(str(path))
        if mime and not (mime.startswith("text/") or mime in ("application/json", "application/xml")):
            return

        try:
            with open(path, "rb") as f:
                raw = f.read(MAX_SCAN_BYTES)
            result.scanned_bytes = len(raw)

            # Try common text encodings (Notepad often writes UTF-16 .txt files).
            text = None
            for enc in ("utf-8-sig", "utf-16", "utf-16-le", "utf-16-be"):
                try:
                    candidate = raw.decode(enc)
                    # Decoding may "succeed" with wrong codec; reject NUL-heavy output.
                    if candidate.count("\x00") > max(1, len(candidate) // 10):
                        continue
                    text = candidate
                    break
                except UnicodeDecodeError:
                    continue

            if text is None:
                try:
                    text = raw.decode("latin-1")
                except Exception:
                    return

            for name, compiled in self._compiled.items():
                matches = compiled.findall(text)
                if matches:
                    meta = BUILTIN_PATTERNS.get(name, {})
                    sample = str(matches[0])
                    # Redact middle of sample
                    if len(sample) > 6:
                        sample = sample[:2] + "*" * (len(sample) - 4) + sample[-2:]
                    result.content_matches.append(ContentMatch(
                        pattern_name=name,
                        description=meta.get("description", name),
                        severity=meta.get("severity", "medium"),
                        match_count=len(matches),
                        sample=sample,
                    ))
        except (OSError, PermissionError):
            result.warnings.append("Could not read file for content scanning")

    def _classify_sensitivity(self, result: DLPResult):
        if not result.content_matches:
            result.sensitivity = SensitivityLevel.PUBLIC
            return

        severities = {m.severity for m in result.content_matches}
        if "critical" in severities:
            result.sensitivity = SensitivityLevel.RESTRICTED
        elif "high" in severities:
            result.sensitivity = SensitivityLevel.CONFIDENTIAL
        elif "medium" in severities:
            result.sensitivity = SensitivityLevel.INTERNAL
        else:
            result.sensitivity = SensitivityLevel.PUBLIC

    def _determine_final_action(self, result: DLPResult):
        if result.action == PolicyAction.BLOCK:
            return  # Already blocked

        if result.sensitivity == SensitivityLevel.RESTRICTED:
            if self.policy.quarantine_on_sensitive:
                result.action = PolicyAction.QUARANTINE
            else:
                result.action = PolicyAction.WARN
        elif result.sensitivity == SensitivityLevel.CONFIDENTIAL:
            result.action = PolicyAction.WARN
        elif result.sensitivity == SensitivityLevel.INTERNAL:
            result.action = PolicyAction.WARN
        elif result.warnings:
            result.action = PolicyAction.WARN
        else:
            result.action = PolicyAction.ALLOW
