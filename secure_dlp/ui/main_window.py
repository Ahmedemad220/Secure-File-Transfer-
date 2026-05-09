"""
Secure DLP — PyQt5 Desktop GUI
Modern dark security-focused interface with four main tabs:
Encrypt/Decrypt · Share · DLP Policy · Audit Log
"""

import sys
import os
import time
import re
from urllib.parse import urlparse, parse_qs, unquote
from pathlib import Path
from datetime import datetime
from typing import Optional

from PyQt5.QtWidgets import (
    QApplication, QMainWindow, QWidget, QVBoxLayout, QHBoxLayout,
    QTabWidget, QLabel, QPushButton, QLineEdit, QFileDialog, QTextEdit,
    QTableWidget, QTableWidgetItem, QHeaderView, QComboBox, QCheckBox,
    QGroupBox, QFormLayout, QSpinBox, QProgressBar, QSplitter,
    QMessageBox, QDialog, QDialogButtonBox, QListWidget, QListWidgetItem,
    QFrame, QScrollArea, QSizePolicy, QStatusBar, QToolBar, QAction,
    QAbstractItemView
)
from PyQt5.QtCore import (
    Qt, QThread, pyqtSignal, QTimer, QSize, QPropertyAnimation,
    QEasingCurve, QPoint, QRect
)
from PyQt5.QtGui import (
    QFont, QFontDatabase, QPalette, QColor, QIcon, QPixmap,
    QPainter, QPen, QBrush, QLinearGradient, QTextCursor
)


def _resource_path(filename: str) -> str:
    """Resolve asset path for normal run and PyInstaller one-file mode."""
    base_dir = getattr(sys, "_MEIPASS", os.path.abspath(os.path.join(os.path.dirname(__file__), "..", "..")))
    return os.path.join(base_dir, filename)


# ── Styles ────────────────────────────────────────────────────────────────────

PALETTE = {
    "bg":        "#0D1117",
    "surface":   "#161B22",
    "header":    "#0F172A",
    "surface2":  "#21262D",
    "border":    "#30363D",
    "accent":    "#2EA043",
    "accent2":   "#1F6FEB",
    "warn":      "#E3B341",
    "danger":    "#F85149",
    "critical":  "#BC8CFF",
    "text":      "#E6EDF3",
    "text2":     "#8B949E",
    "text3":     "#6E7681",
}

STYLESHEET = f"""
QMainWindow, QWidget {{
    background: {PALETTE['bg']};
    color: {PALETTE['text']};
    font-family: 'Segoe UI', 'SF Pro Display', 'Helvetica Neue', Arial, sans-serif;
    font-size: 13px;
}}
QTabWidget::pane {{
    border: 1px solid {PALETTE['border']};
    background: {PALETTE['surface']};
    border-radius: 8px;
}}
QTabBar::tab {{
    background: {PALETTE['bg']};
    color: {PALETTE['text2']};
    padding: 10px 20px;
    border: none;
    border-bottom: 2px solid transparent;
    font-weight: 500;
    font-size: 13px;
}}
QTabBar::tab:selected {{
    color: {PALETTE['text']};
    border-bottom: 2px solid {PALETTE['accent2']};
    background: {PALETTE['surface']};
}}
QTabBar::tab:hover {{
    color: {PALETTE['text']};
    background: {PALETTE['surface']};
}}
QGroupBox {{
    border: 1px solid {PALETTE['border']};
    border-radius: 8px;
    margin-top: 12px;
    padding: 12px;
    font-weight: 600;
    color: {PALETTE['text2']};
    font-size: 12px;
    text-transform: uppercase;
    letter-spacing: 1px;
}}
QGroupBox::title {{
    subcontrol-origin: margin;
    left: 10px;
    padding: 0 6px;
    background: {PALETTE['surface']};
}}
QPushButton {{
    background: {PALETTE['surface2']};
    color: {PALETTE['text']};
    border: 1px solid {PALETTE['border']};
    border-radius: 6px;
    padding: 8px 16px;
    font-weight: 500;
    font-size: 13px;
}}
QPushButton:hover {{
    background: {PALETTE['border']};
    border-color: {PALETTE['text3']};
}}
QPushButton:pressed {{
    background: {PALETTE['bg']};
}}
QPushButton#primary {{
    background: {PALETTE['accent']};
    border-color: {PALETTE['accent']};
    color: white;
    font-weight: 600;
}}
QPushButton#primary:hover {{
    background: #3FB950;
    border-color: #3FB950;
}}
QPushButton#danger {{
    background: transparent;
    border-color: {PALETTE['danger']};
    color: {PALETTE['danger']};
}}
QPushButton#danger:hover {{
    background: {PALETTE['danger']};
    color: white;
}}
QPushButton#warn-btn {{
    background: transparent;
    border-color: {PALETTE['warn']};
    color: {PALETTE['warn']};
}}
QLineEdit, QTextEdit, QComboBox, QSpinBox {{
    background: {PALETTE['bg']};
    color: {PALETTE['text']};
    border: 1px solid {PALETTE['border']};
    border-radius: 6px;
    padding: 7px 10px;
    font-size: 13px;
    selection-background-color: {PALETTE['accent2']};
}}
QLineEdit:focus, QTextEdit:focus, QComboBox:focus, QSpinBox:focus {{
    border-color: {PALETTE['accent2']};
    outline: none;
}}
QComboBox::drop-down {{
    border: none;
    padding-right: 8px;
}}
QComboBox::down-arrow {{
    image: none;
    border-left: 4px solid transparent;
    border-right: 4px solid transparent;
    border-top: 6px solid {PALETTE['text2']};
    margin-right: 4px;
}}
QTableWidget {{
    background: {PALETTE['surface']};
    gridline-color: {PALETTE['border']};
    border: 1px solid {PALETTE['border']};
    border-radius: 8px;
    font-size: 12px;
}}
QTableWidget::item {{
    padding: 8px 12px;
    border-bottom: 1px solid {PALETTE['border']};
}}
QTableWidget::item:selected {{
    background: {PALETTE['surface2']};
    color: {PALETTE['text']};
}}
QHeaderView::section {{
    background: {PALETTE['surface2']};
    color: {PALETTE['text2']};
    padding: 8px 12px;
    border: none;
    border-bottom: 1px solid {PALETTE['border']};
    font-weight: 600;
    font-size: 11px;
    text-transform: uppercase;
    letter-spacing: 0.5px;
}}
QScrollBar:vertical {{
    background: {PALETTE['surface']};
    width: 8px;
    border-radius: 4px;
}}
QScrollBar::handle:vertical {{
    background: {PALETTE['border']};
    border-radius: 4px;
    min-height: 30px;
}}
QScrollBar::add-line:vertical, QScrollBar::sub-line:vertical {{
    height: 0;
}}
QProgressBar {{
    background: {PALETTE['surface2']};
    border: 1px solid {PALETTE['border']};
    border-radius: 4px;
    height: 6px;
    text-align: center;
}}
QProgressBar::chunk {{
    background: {PALETTE['accent2']};
    border-radius: 4px;
}}
QStatusBar {{
    background: {PALETTE['surface']};
    color: {PALETTE['text2']};
    border-top: 1px solid {PALETTE['border']};
    font-size: 12px;
    padding: 0 8px;
}}
QCheckBox {{
    spacing: 8px;
    color: {PALETTE['text']};
}}
QCheckBox::indicator {{
    width: 16px;
    height: 16px;
    border: 1px solid {PALETTE['border']};
    border-radius: 4px;
    background: {PALETTE['bg']};
}}
QCheckBox::indicator:checked {{
    background: {PALETTE['accent2']};
    border-color: {PALETTE['accent2']};
}}
QLabel#section-title {{
    font-size: 20px;
    font-weight: 700;
    color: {PALETTE['text']};
    padding-bottom: 4px;
}}
QLabel#section-sub {{
    font-size: 13px;
    color: {PALETTE['text2']};
    padding-bottom: 12px;
}}
QFrame#divider {{
    background: {PALETTE['border']};
    max-height: 1px;
    min-height: 1px;
    margin: 8px 0;
}}
"""


# ── Badge widget ───────────────────────────────────────────────────────────────

class Badge(QLabel):
    COLORS = {
        "green":  ("#1C4429", "#2EA043"),
        "blue":   ("#1A2D4D", "#1F6FEB"),
        "yellow": ("#3D3000", "#E3B341"),
        "red":    ("#3D1A1A", "#F85149"),
        "purple": ("#2D1A4D", "#BC8CFF"),
        "gray":   ("#21262D", "#8B949E"),
    }

    def __init__(self, text: str, color: str = "gray", parent=None):
        super().__init__(text, parent)
        bg, fg = self.COLORS.get(color, self.COLORS["gray"])
        self.setStyleSheet(f"""
            background: {bg};
            color: {fg};
            border: 1px solid {fg};
            border-radius: 10px;
            padding: 2px 8px;
            font-size: 11px;
            font-weight: 600;
        """)
        self.setMaximumHeight(22)


# ── Worker threads ────────────────────────────────────────────────────────────

class EncryptWorker(QThread):
    finished = pyqtSignal(bool, str, dict)

    def __init__(self, controller, source, password, recipient):
        super().__init__()
        self.controller = controller
        self.source     = source
        self.password   = password
        self.recipient  = recipient

    def run(self):
        ok, msg, details = self.controller.encrypt_file(self.source, self.password, self.recipient)
        self.finished.emit(ok, msg, details)


class ShareWorker(QThread):
    finished = pyqtSignal(bool, str, object)

    def __init__(self, controller, source, recipient, expiry, single_use):
        super().__init__()
        self.controller = controller
        self.source     = source
        self.recipient  = recipient
        self.expiry     = expiry
        self.single_use = single_use

    def run(self):
        ok, msg, record = self.controller.create_share(
            self.source, self.recipient, self.expiry, self.single_use
        )
        self.finished.emit(ok, msg, record)


# ── Encrypt / Decrypt tab ────────────────────────────────────────────────────

class EncryptTab(QWidget):
    def __init__(self, controller):
        super().__init__()
        self.controller = controller
        self._build()

    def _build(self):
        layout = QVBoxLayout(self)
        layout.setContentsMargins(24, 24, 24, 24)
        layout.setSpacing(16)

        t = QLabel("File Encryption"); t.setObjectName("section-title"); layout.addWidget(t)
        s = QLabel("AES-256-GCM zero-knowledge encryption with DLP pre-scan")
        s.setObjectName("section-sub"); layout.addWidget(s)

        d = QFrame(); d.setObjectName("divider"); layout.addWidget(d)

        # Encrypt group
        enc = QGroupBox("Encrypt File")
        enc_layout = QFormLayout(enc)
        enc_layout.setSpacing(12)

        self.enc_file = QLineEdit(); self.enc_file.setPlaceholderText("Select file to encrypt…")
        browse = QPushButton("Browse"); browse.setFixedWidth(90)
        browse.clicked.connect(self._browse_encrypt)
        file_row = QHBoxLayout()
        file_row.addWidget(self.enc_file); file_row.addWidget(browse)
        enc_layout.addRow("File:", file_row)

        self.enc_password = QLineEdit(); self.enc_password.setEchoMode(QLineEdit.Password)
        self.enc_password.setPlaceholderText("Encryption password")
        enc_layout.addRow("Password:", self.enc_password)

        self.enc_recipient = QLineEdit(); self.enc_recipient.setPlaceholderText("recipient@example.com (optional, for DLP check)")
        enc_layout.addRow("Recipient:", self.enc_recipient)

        self.enc_btn = QPushButton("🔒  Encrypt & Scan"); self.enc_btn.setObjectName("primary")
        self.enc_btn.setFixedHeight(40)
        self.enc_btn.clicked.connect(self._do_encrypt)
        enc_layout.addRow("", self.enc_btn)

        layout.addWidget(enc)

        # Decrypt group
        dec = QGroupBox("Decrypt File")
        dec_layout = QFormLayout(dec)
        dec_layout.setSpacing(12)

        self.dec_file = QLineEdit(); self.dec_file.setPlaceholderText("Select .sdlp file…")
        browse2 = QPushButton("Browse"); browse2.setFixedWidth(90)
        browse2.clicked.connect(self._browse_decrypt)
        dec_row = QHBoxLayout()
        dec_row.addWidget(self.dec_file); dec_row.addWidget(browse2)
        dec_layout.addRow("File:", dec_row)

        self.dec_password = QLineEdit(); self.dec_password.setEchoMode(QLineEdit.Password)
        self.dec_password.setPlaceholderText("Decryption password")
        dec_layout.addRow("Password:", self.dec_password)

        self.dec_out = QLineEdit(); self.dec_out.setPlaceholderText("Output directory…")
        browse3 = QPushButton("Browse"); browse3.setFixedWidth(90)
        browse3.clicked.connect(self._browse_dec_out)
        dec_out_row = QHBoxLayout()
        dec_out_row.addWidget(self.dec_out); dec_out_row.addWidget(browse3)
        dec_layout.addRow("Output dir:", dec_out_row)

        self.dec_btn = QPushButton("🔓  Decrypt File"); self.dec_btn.setObjectName("primary")
        self.dec_btn.setFixedHeight(40)
        self.dec_btn.clicked.connect(self._do_decrypt)
        dec_layout.addRow("", self.dec_btn)

        layout.addWidget(dec)

        # Result
        self.result_box = QTextEdit()
        self.result_box.setReadOnly(True)
        self.result_box.setMaximumHeight(160)
        self.result_box.setPlaceholderText("Results will appear here…")
        layout.addWidget(self.result_box)

        self.progress = QProgressBar(); self.progress.setVisible(False)
        layout.addWidget(self.progress)
        layout.addStretch()

    def _browse_encrypt(self):
        f, _ = QFileDialog.getOpenFileName(self, "Select file to encrypt")
        if f: self.enc_file.setText(f)

    def _browse_decrypt(self):
        f, _ = QFileDialog.getOpenFileName(self, "Select encrypted file", filter="SDLP Files (*.sdlp);;All Files (*)")
        if f: self.dec_file.setText(f)

    def _browse_dec_out(self):
        d = QFileDialog.getExistingDirectory(self, "Select output directory")
        if d: self.dec_out.setText(d)

    def _do_encrypt(self):
        src = self.enc_file.text().strip()
        pwd = self.enc_password.text()
        rec = self.enc_recipient.text().strip()

        if not src:
            self._show_result("⚠ Please select a file.", "warn")
            return
        if not pwd:
            self._show_result("⚠ Please enter a password.", "warn")
            return

        self.enc_btn.setEnabled(False)
        self.enc_btn.setText("Encrypting…")
        self.progress.setVisible(True)
        self.progress.setRange(0, 0)

        self._worker = EncryptWorker(self.controller, src, pwd, rec)
        self._worker.finished.connect(self._on_encrypt_done)
        self._worker.start()

    def _on_encrypt_done(self, ok, msg, details):
        self.progress.setVisible(False)
        self.enc_btn.setEnabled(True)
        self.enc_btn.setText("🔒  Encrypt & Scan")

        if ok:
            dlp = details.get("dlp", {})
            matches = dlp.get("content_matches", [])
            lines = [f"✅  {msg}", f"   Output: {details.get('encrypted_path', '')}",
                     f"   Original size: {details.get('original_size', 0):,} bytes",
                     f"   Algorithm: {details.get('algorithm', 'AES-256-GCM')}",
                     f"   DLP sensitivity: {dlp.get('sensitivity', 'public').upper()}",
                     f"   DLP risk score: {dlp.get('risk_score', 0)}/100"]
            if matches:
                lines.append(f"   ⚠ Sensitive patterns found: {', '.join(m['pattern_name'] for m in matches)}")
            self._show_result("\n".join(lines), "ok")
        else:
            self._show_result(f"❌  {msg}", "error")

    def _do_decrypt(self):
        src  = self.dec_file.text().strip()
        pwd  = self.dec_password.text()
        outd = self.dec_out.text().strip()

        if not src or not outd:
            self._show_result("⚠ Select an encrypted file and output directory.", "warn")
            return
        if not pwd:
            self._show_result("⚠ Enter the decryption password.", "warn")
            return

        ok, msg, meta = self.controller.decrypt_file(src, pwd, outd)
        if ok:
            self._show_result(
                f"✅  {msg}\n"
                f"   File: {meta.get('filename', '')}\n"
                f"   Saved to: {meta.get('output_path', '')}\n"
                f"   Original size: {meta.get('original_size', 0):,} bytes",
                "ok",
            )
        else:
            self._show_result(f"❌  {msg}", "error")

    def _show_result(self, text, kind="ok"):
        colors = {"ok": PALETTE["accent"], "warn": PALETTE["warn"], "error": PALETTE["danger"]}
        color = colors.get(kind, PALETTE["text"])
        self.result_box.setStyleSheet(f"QTextEdit {{ border: 1px solid {color}; border-radius: 6px; padding: 10px; background: {PALETTE['bg']}; color: {PALETTE['text']}; font-family: 'Courier New', monospace; font-size: 12px; }}")
        self.result_box.setPlainText(text)


# ── Sharing tab ───────────────────────────────────────────────────────────────

class SharingTab(QWidget):
    def __init__(self, controller):
        super().__init__()
        self.controller = controller
        self._build()

    def _build(self):
        layout = QVBoxLayout(self)
        layout.setContentsMargins(0, 0, 0, 0)
        layout.setSpacing(0)

        scroll = QScrollArea()
        scroll.setWidgetResizable(True)
        scroll.setFrameShape(QFrame.NoFrame)
        layout.addWidget(scroll)

        content = QWidget()
        scroll.setWidget(content)

        content_layout = QVBoxLayout(content)
        content_layout.setContentsMargins(24, 24, 24, 24)
        content_layout.setSpacing(16)

        t = QLabel("Secure File Sharing"); t.setObjectName("section-title"); content_layout.addWidget(t)
        s = QLabel("Create encrypted sharing links with expiration and access controls")
        s.setObjectName("section-sub"); content_layout.addWidget(s)

        d = QFrame(); d.setObjectName("divider"); content_layout.addWidget(d)

        # Create share
        create_grp = QGroupBox("Create New Share")
        cf = QFormLayout(create_grp); cf.setSpacing(12)
        cf.setFieldGrowthPolicy(QFormLayout.AllNonFixedFieldsGrow)

        self.sh_file = QLineEdit(); self.sh_file.setPlaceholderText("File to share…")
        self.sh_file.setMinimumHeight(36)
        self.sh_file.setSizePolicy(QSizePolicy.Expanding, QSizePolicy.Fixed)
        br = QPushButton("Browse"); br.setFixedWidth(90); br.clicked.connect(self._browse_share)
        br.setMinimumHeight(36)
        fr = QHBoxLayout(); fr.addWidget(self.sh_file); fr.addWidget(br)
        cf.addRow("File:", fr)

        self.sh_recipient = QLineEdit(); self.sh_recipient.setPlaceholderText("recipient@example.com")
        self.sh_recipient.setMinimumHeight(36)
        self.sh_recipient.setSizePolicy(QSizePolicy.Expanding, QSizePolicy.Fixed)
        cf.addRow("Recipient:", self.sh_recipient)

        self.sh_expiry = QComboBox()
        for label, val in [("1 hour", 3600), ("6 hours", 21600), ("1 day", 86400),
                            ("3 days", 259200), ("1 week", 604800), ("Never", 0)]:
            self.sh_expiry.addItem(label, val)
        self.sh_expiry.setCurrentIndex(2)
        self.sh_expiry.setMinimumHeight(36)
        cf.addRow("Expires:", self.sh_expiry)

        self.sh_single = QCheckBox("Single-use (revoke after first access)")
        cf.addRow("", self.sh_single)

        self.sh_btn = QPushButton("🔗  Create Share Link"); self.sh_btn.setObjectName("primary")
        self.sh_btn.setFixedHeight(40); self.sh_btn.clicked.connect(self._do_share)
        cf.addRow("", self.sh_btn)

        self.sh_result = QLineEdit(); self.sh_result.setReadOnly(True)
        self.sh_result.setPlaceholderText("Share token will appear here…")
        self.sh_result.setMinimumHeight(36)
        self.sh_result.setSizePolicy(QSizePolicy.Expanding, QSizePolicy.Fixed)
        self.sh_result.setStyleSheet(f"font-family: 'Courier New', monospace; font-size: 11px; color: {PALETTE['accent']};")
        cf.addRow("Share link:", self.sh_result)

        content_layout.addWidget(create_grp, 0)

        # Access incoming share
        access_grp = QGroupBox("Access Shared File")
        af = QFormLayout(access_grp); af.setSpacing(12)
        af.setFieldGrowthPolicy(QFormLayout.AllNonFixedFieldsGrow)

        self.ac_link = QLineEdit()
        self.ac_link.setPlaceholderText("Paste full link: sdlp://share/<id>?token=<token> (optional)")
        self.ac_link.setMinimumHeight(36)
        self.ac_link.setSizePolicy(QSizePolicy.Expanding, QSizePolicy.Fixed)
        parse_btn = QPushButton("Parse Link"); parse_btn.setFixedWidth(110)
        parse_btn.clicked.connect(self._parse_share_link)
        parse_btn.setMinimumHeight(36)
        lr = QHBoxLayout(); lr.addWidget(self.ac_link); lr.addWidget(parse_btn)
        af.addRow("Share link:", lr)

        self.ac_id = QLineEdit(); self.ac_id.setPlaceholderText("Share ID")
        self.ac_id.setMinimumHeight(36)
        self.ac_id.setSizePolicy(QSizePolicy.Expanding, QSizePolicy.Fixed)
        af.addRow("Share ID:", self.ac_id)

        self.ac_token = QLineEdit(); self.ac_token.setPlaceholderText("Access token")
        self.ac_token.setMinimumHeight(36)
        self.ac_token.setSizePolicy(QSizePolicy.Expanding, QSizePolicy.Fixed)
        af.addRow("Token:", self.ac_token)

        self.ac_email = QLineEdit(); self.ac_email.setPlaceholderText("recipient@example.com (optional)")
        self.ac_email.setMinimumHeight(36)
        self.ac_email.setSizePolicy(QSizePolicy.Expanding, QSizePolicy.Fixed)
        af.addRow("Recipient:", self.ac_email)

        self.ac_out = QLineEdit(); self.ac_out.setPlaceholderText("Output directory…")
        self.ac_out.setMinimumHeight(36)
        self.ac_out.setSizePolicy(QSizePolicy.Expanding, QSizePolicy.Fixed)
        out_btn = QPushButton("Browse"); out_btn.setFixedWidth(90)
        out_btn.clicked.connect(self._browse_access_out)
        out_btn.setMinimumHeight(36)
        orow = QHBoxLayout(); orow.addWidget(self.ac_out); orow.addWidget(out_btn)
        af.addRow("Output dir:", orow)

        self.ac_btn = QPushButton("⬇  Access Shared File"); self.ac_btn.setObjectName("primary")
        self.ac_btn.setFixedHeight(40); self.ac_btn.clicked.connect(self._do_access_share)
        af.addRow("", self.ac_btn)

        content_layout.addWidget(access_grp, 0)

        # Active shares
        shares_grp = QGroupBox("Active Shares")
        sl = QVBoxLayout(shares_grp)

        toolbar = QHBoxLayout()
        self.refresh_btn = QPushButton("↻  Refresh"); self.refresh_btn.clicked.connect(self._refresh_shares)
        self.revoke_btn  = QPushButton("✕  Revoke Selected"); self.revoke_btn.setObjectName("danger")
        self.revoke_btn.clicked.connect(self._revoke_selected)
        toolbar.addWidget(self.refresh_btn); toolbar.addWidget(self.revoke_btn); toolbar.addStretch()
        sl.addLayout(toolbar)

        self.shares_table = QTableWidget()
        self.shares_table.setColumnCount(6)
        self.shares_table.setHorizontalHeaderLabels(["ID", "File", "Recipient", "Expires In", "Access", "Status"])
        self.shares_table.horizontalHeader().setSectionResizeMode(1, QHeaderView.Stretch)
        self.shares_table.horizontalHeader().setSectionResizeMode(2, QHeaderView.Stretch)
        self.shares_table.setSelectionBehavior(QAbstractItemView.SelectRows)
        self.shares_table.setEditTriggers(QAbstractItemView.NoEditTriggers)
        self.shares_table.setAlternatingRowColors(False)
        self.shares_table.setMinimumHeight(260)
        sl.addWidget(self.shares_table)

        content_layout.addWidget(shares_grp, 1)
        content_layout.setStretch(0, 0)
        content_layout.setStretch(1, 0)
        content_layout.setStretch(2, 1)
        self._refresh_shares()

    def _browse_share(self):
        f, _ = QFileDialog.getOpenFileName(self, "Select file to share")
        if f: self.sh_file.setText(f)

    def _do_share(self):
        src = self.sh_file.text().strip()
        rec = self.sh_recipient.text().strip()

        if not src:
            QMessageBox.warning(self, "Missing File", "Please select a file to share.")
            return
        if not rec:
            QMessageBox.warning(self, "Missing Recipient", "Please enter a recipient email.")
            return

        from secure_dlp.core import ShareExpiry
        expiry_val = self.sh_expiry.currentData()
        expiry = ShareExpiry(expiry_val)

        self.sh_btn.setEnabled(False); self.sh_btn.setText("Creating…")
        self._share_worker = ShareWorker(self.controller, src, rec, expiry, self.sh_single.isChecked())
        self._share_worker.finished.connect(self._on_share_done)
        self._share_worker.start()

    def _on_share_done(self, ok, msg, record):
        self.sh_btn.setEnabled(True); self.sh_btn.setText("🔗  Create Share Link")
        if ok and record:
            self.sh_result.setText(record.share_link)
            self._refresh_shares()
            QMessageBox.information(self, "Share Created",
                f"Share created successfully!\nID: {record.share_id[:8]}…\nExpires: {record.expires_in_str}")
        else:
            QMessageBox.critical(self, "Share Failed", msg)

    def _parse_share_link(self):
        link = self.ac_link.text().strip()
        if not link:
            QMessageBox.warning(self, "Missing Link", "Please paste a share link first.")
            return

        parsed = self._extract_share_parts(link)
        if not parsed:
            QMessageBox.warning(self, "Invalid Link", "Expected format: sdlp://share/<id>?token=<token>")
            return

        share_id, token = parsed
        self.ac_id.setText(share_id)
        self.ac_token.setText(token)
        QMessageBox.information(self, "Parsed", "Share ID and token extracted successfully.")

    def _extract_share_parts(self, link: str):
        """Parse share link and return (share_id, token) or None."""
        link = (link or "").strip()
        if not link:
            return None

        # Fast path for expected shape.
        m = re.match(r"^sdlp://share/([^?]+)\?token=(.+)$", link)
        if m:
            return m.group(1).strip(), unquote(m.group(2).strip())

        # Robust path for encoded/messy links.
        try:
            p = urlparse(link)
            if p.scheme != "sdlp" or p.netloc != "share":
                return None
            share_id = p.path.lstrip("/").strip()
            token = parse_qs(p.query).get("token", [""])[0].strip()
            if not share_id or not token:
                return None
            return share_id, unquote(token)
        except Exception:
            return None

    def _browse_access_out(self):
        d = QFileDialog.getExistingDirectory(self, "Select output directory")
        if d:
            self.ac_out.setText(d)

    def _do_access_share(self):
        share_id = self.ac_id.text().strip()
        token = self.ac_token.text().strip()
        out_dir = self.ac_out.text().strip()
        email = self.ac_email.text().strip()

        # If user pasted only the full link, parse it automatically.
        if (not share_id or not token) and self.ac_link.text().strip():
            parsed = self._extract_share_parts(self.ac_link.text().strip())
            if parsed:
                share_id, token = parsed
                self.ac_id.setText(share_id)
                self.ac_token.setText(token)

        if not share_id or not token:
            QMessageBox.warning(self, "Missing Data", "Please provide both Share ID and Token.")
            return
        if not out_dir:
            QMessageBox.warning(self, "Missing Output", "Please choose an output directory.")
            return

        self.ac_btn.setEnabled(False); self.ac_btn.setText("Accessing…")
        ok, msg = self.controller.access_share(share_id, token, out_dir, email)
        self.ac_btn.setEnabled(True); self.ac_btn.setText("⬇  Access Shared File")

        if ok:
            self._refresh_shares()
            QMessageBox.information(self, "Access Successful", msg)
        else:
            QMessageBox.critical(self, "Access Failed", msg)

    def _refresh_shares(self):
        shares = self.controller.list_shares()
        self.shares_table.setRowCount(len(shares))
        status_colors = {"active": "green", "expired": "gray", "revoked": "red", "accessed": "blue"}

        for i, s in enumerate(shares):
            self.shares_table.setItem(i, 0, QTableWidgetItem(s.share_id[:8] + "…"))
            self.shares_table.setItem(i, 1, QTableWidgetItem(s.original_name))
            self.shares_table.setItem(i, 2, QTableWidgetItem(s.recipient_email))
            self.shares_table.setItem(i, 3, QTableWidgetItem(s.expires_in_str))
            self.shares_table.setItem(i, 4, QTableWidgetItem(str(s.access_count)))

            badge_w = QWidget()
            badge_l = QHBoxLayout(badge_w); badge_l.setContentsMargins(4, 2, 4, 2)
            badge = Badge(s.status.value.upper(), status_colors.get(s.status.value, "gray"))
            badge_l.addWidget(badge); badge_l.addStretch()
            self.shares_table.setCellWidget(i, 5, badge_w)

        self.shares_table.resizeRowsToContents()

    def _revoke_selected(self):
        row = self.shares_table.currentRow()
        if row < 0:
            return
        shares = self.controller.list_shares()
        if row >= len(shares):
            return
        share = shares[row]
        if QMessageBox.question(self, "Revoke Share",
            f"Revoke share {share.share_id[:8]}…?\nThis will delete the encrypted file.",
            QMessageBox.Yes | QMessageBox.No) == QMessageBox.Yes:
            self.controller.revoke_share(share.share_id)
            self._refresh_shares()


# ── DLP Policy tab ────────────────────────────────────────────────────────────

class DLPTab(QWidget):
    def __init__(self, controller):
        super().__init__()
        self.controller = controller
        self._build()
        self._load_policy()

    def _build(self):
        layout = QVBoxLayout(self)
        layout.setContentsMargins(24, 24, 24, 24)
        layout.setSpacing(16)

        t = QLabel("DLP Policy Engine"); t.setObjectName("section-title"); layout.addWidget(t)
        s = QLabel("Configure data loss prevention rules, blocked file types, and content patterns")
        s.setObjectName("section-sub"); layout.addWidget(s)

        d = QFrame(); d.setObjectName("divider"); layout.addWidget(d)

        scroll = QScrollArea(); scroll.setWidgetResizable(True); scroll.setFrameShape(QFrame.NoFrame)
        inner  = QWidget()
        inner_l = QVBoxLayout(inner); inner_l.setSpacing(16)

        # Preset row
        preset_grp = QGroupBox("Quick Presets")
        preset_l = QHBoxLayout(preset_grp)
        for name, method in [("Strict", "default_strict"), ("Standard", "default_standard"), ("Permissive", "default_permissive")]:
            btn = QPushButton(name); btn.clicked.connect(lambda _, m=method: self._load_preset(m))
            preset_l.addWidget(btn)
        preset_l.addStretch()
        inner_l.addWidget(preset_grp)

        # File type rules
        ft_grp = QGroupBox("Blocked File Types")
        ft_l = QVBoxLayout(ft_grp)
        self.chk_exe = QCheckBox("Executables (.exe, .bat, .cmd, .msi, .dll…)")
        self.chk_script = QCheckBox("Scripts (.py, .sh, .js, .ps1, .rb…)")
        self.chk_archive = QCheckBox("Archives (.zip, .rar, .7z, .tar…)")
        self.chk_db = QCheckBox("Databases (.sql, .sqlite, .mdb…)")
        self.chk_key = QCheckBox("Keys & certificates (.pem, .key, .pfx…)")
        for chk in [self.chk_exe, self.chk_script, self.chk_archive, self.chk_db, self.chk_key]:
            ft_l.addWidget(chk)
        inner_l.addWidget(ft_grp)

        # Size limit
        size_grp = QGroupBox("Size Limit")
        size_l = QFormLayout(size_grp)
        self.max_size = QSpinBox(); self.max_size.setRange(1, 10240); self.max_size.setSuffix(" MB")
        size_l.addRow("Maximum file size:", self.max_size)
        inner_l.addWidget(size_grp)

        # Content patterns
        pat_grp = QGroupBox("Content Scanning Patterns")
        pat_l = QVBoxLayout(pat_grp)
        self.pattern_checks = {}
        from secure_dlp.core.dlp import BUILTIN_PATTERNS
        for name, meta in BUILTIN_PATTERNS.items():
            chk = QCheckBox(f"{meta['description']}  [{meta['severity'].upper()}]")
            self.pattern_checks[name] = chk
            pat_l.addWidget(chk)
        inner_l.addWidget(pat_grp)

        # Options
        opt_grp = QGroupBox("Behaviour")
        opt_l = QVBoxLayout(opt_grp)
        self.chk_quarantine = QCheckBox("Auto-quarantine files with RESTRICTED sensitivity")
        self.chk_auto_class = QCheckBox("Auto-classify files by sensitivity level")
        opt_l.addWidget(self.chk_quarantine); opt_l.addWidget(self.chk_auto_class)
        inner_l.addWidget(opt_grp)

        # Test scanner
        test_grp = QGroupBox("Test File Against Current Policy")
        test_l = QHBoxLayout(test_grp)
        self.test_file = QLineEdit(); self.test_file.setPlaceholderText("File path to test…")
        test_br = QPushButton("Browse"); test_br.setFixedWidth(80); test_br.clicked.connect(self._browse_test)
        self.test_btn = QPushButton("🔍 Scan"); self.test_btn.setObjectName("primary"); self.test_btn.setFixedWidth(80)
        self.test_btn.clicked.connect(self._do_test_scan)
        test_l.addWidget(self.test_file); test_l.addWidget(test_br); test_l.addWidget(self.test_btn)
        inner_l.addWidget(test_grp)

        self.scan_result = QTextEdit(); self.scan_result.setReadOnly(True); self.scan_result.setMaximumHeight(140)
        self.scan_result.setStyleSheet(f"font-family: 'Courier New', monospace; font-size: 12px; background: {PALETTE['bg']};")
        inner_l.addWidget(self.scan_result)

        inner_l.addStretch()
        scroll.setWidget(inner)
        layout.addWidget(scroll)

        # Save button
        save_btn = QPushButton("💾  Save Policy"); save_btn.setObjectName("primary")
        save_btn.setFixedHeight(40); save_btn.clicked.connect(self._save_policy)
        layout.addWidget(save_btn)

    def _load_policy(self):
        from secure_dlp.core import DLPPolicy
        p = self.controller.get_policy()
        self.chk_exe.setChecked(p.block_executables)
        self.chk_script.setChecked(p.block_scripts)
        self.chk_archive.setChecked(p.block_archives)
        self.chk_db.setChecked(p.block_databases)
        self.chk_key.setChecked(p.block_key_files)
        self.max_size.setValue(p.max_file_size_mb)
        self.chk_quarantine.setChecked(p.quarantine_on_sensitive)
        self.chk_auto_class.setChecked(p.auto_classify)
        for name, chk in self.pattern_checks.items():
            chk.setChecked(name in p.enabled_patterns)

    def _load_preset(self, method):
        from secure_dlp.core import DLPPolicy
        policy = getattr(DLPPolicy, method)()
        self.controller.set_policy(policy)
        self._load_policy()
        QMessageBox.information(self, "Preset Loaded", f"'{policy.name}' policy applied.")

    def _save_policy(self):
        from secure_dlp.core import DLPPolicy
        p = self.controller.get_policy()
        p.block_executables     = self.chk_exe.isChecked()
        p.block_scripts         = self.chk_script.isChecked()
        p.block_archives        = self.chk_archive.isChecked()
        p.block_databases       = self.chk_db.isChecked()
        p.block_key_files       = self.chk_key.isChecked()
        p.max_file_size_mb      = self.max_size.value()
        p.quarantine_on_sensitive = self.chk_quarantine.isChecked()
        p.auto_classify         = self.chk_auto_class.isChecked()
        p.enabled_patterns      = [n for n, c in self.pattern_checks.items() if c.isChecked()]
        self.controller.set_policy(p)
        QMessageBox.information(self, "Saved", "DLP policy saved successfully.")

    def _browse_test(self):
        f, _ = QFileDialog.getOpenFileName(self, "Select file to scan")
        if f: self.test_file.setText(f)

    def _do_test_scan(self):
        f = self.test_file.text().strip()
        if not f:
            return
        result = self.controller.dlp.evaluate_file(f)
        action_colors = {"allow": "✅", "warn": "⚠", "block": "🚫", "quarantine": "🔒"}
        lines = [
            f"{action_colors.get(result.action.value, '?')} Action: {result.action.value.upper()}",
            f"   Sensitivity: {result.sensitivity.value.upper()}",
            f"   Risk score: {result.risk_score}/100",
            f"   File size: {result.file_size:,} bytes",
        ]
        if result.blocked_reasons:
            lines += [f"   ❌ {r}" for r in result.blocked_reasons]
        if result.content_matches:
            lines.append(f"   📋 Patterns found ({len(result.content_matches)}):")
            for m in result.content_matches:
                lines.append(f"      • {m.description} — {m.match_count} match(es) [{m.severity.upper()}]")
        if result.warnings:
            lines += [f"   ⚠ {w}" for w in result.warnings]

        self.scan_result.setPlainText("\n".join(lines))


# ── Audit tab ─────────────────────────────────────────────────────────────────

class AuditTab(QWidget):
    def __init__(self, controller):
        super().__init__()
        self.controller = controller
        self._build()
        self._refresh()

    def _build(self):
        layout = QVBoxLayout(self)
        layout.setContentsMargins(24, 24, 24, 24)
        layout.setSpacing(16)

        t = QLabel("Audit Log"); t.setObjectName("section-title"); layout.addWidget(t)
        s = QLabel("Tamper-evident SHA-256 hash-chained event log — all operations recorded locally")
        s.setObjectName("section-sub"); layout.addWidget(s)

        d = QFrame(); d.setObjectName("divider"); layout.addWidget(d)

        # Stats row
        self.stats_row = QHBoxLayout()
        self.stat_total   = self._stat_card("Total Events", "0")
        self.stat_today   = self._stat_card("Today",        "0")
        self.stat_blocked = self._stat_card("Blocked",      "0", PALETTE["danger"])
        self.stat_warn    = self._stat_card("Warnings",     "0", PALETTE["warn"])
        self.stat_chain   = self._stat_card("Chain Integrity", "✓ OK", PALETTE["accent"])
        for card in [self.stat_total, self.stat_today, self.stat_blocked, self.stat_warn, self.stat_chain]:
            self.stats_row.addWidget(card)
        layout.addLayout(self.stats_row)

        # Filters
        filter_row = QHBoxLayout()
        self.filter_search = QLineEdit(); self.filter_search.setPlaceholderText("Search file, recipient, details…")
        self.filter_type   = QComboBox()
        self.filter_type.addItem("All Events", None)
        from secure_dlp.core import EventType
        for et in EventType:
            self.filter_type.addItem(et.value, et.value)
        self.filter_severity = QComboBox()
        self.filter_severity.addItems(["All Severities", "info", "warning", "error", "critical"])
        refresh_btn = QPushButton("↻ Refresh"); refresh_btn.clicked.connect(self._refresh)
        export_btn  = QPushButton("⬇ Export JSON"); export_btn.clicked.connect(self._export)
        verify_btn  = QPushButton("🔐 Verify Chain"); verify_btn.clicked.connect(self._verify)

        filter_row.addWidget(QLabel("Search:")); filter_row.addWidget(self.filter_search)
        filter_row.addWidget(QLabel("Type:")); filter_row.addWidget(self.filter_type)
        filter_row.addWidget(QLabel("Severity:")); filter_row.addWidget(self.filter_severity)
        filter_row.addWidget(refresh_btn); filter_row.addWidget(export_btn); filter_row.addWidget(verify_btn)
        self.filter_search.textChanged.connect(self._refresh)
        self.filter_type.currentIndexChanged.connect(self._refresh)
        self.filter_severity.currentIndexChanged.connect(self._refresh)
        layout.addLayout(filter_row)

        # Table
        self.table = QTableWidget()
        self.table.setColumnCount(6)
        self.table.setHorizontalHeaderLabels(["Time", "Event", "Severity", "File", "Recipient", "Details"])
        self.table.horizontalHeader().setSectionResizeMode(5, QHeaderView.Stretch)
        self.table.horizontalHeader().setSectionResizeMode(3, QHeaderView.ResizeToContents)
        self.table.setSelectionBehavior(QAbstractItemView.SelectRows)
        self.table.setEditTriggers(QAbstractItemView.NoEditTriggers)
        layout.addWidget(self.table)

    def _stat_card(self, label, value, color=None) -> QGroupBox:
        grp = QGroupBox()
        grp.setMaximumWidth(160)
        lyt = QVBoxLayout(grp)
        lbl = QLabel(label); lbl.setStyleSheet(f"color: {PALETTE['text2']}; font-size: 11px;")
        val = QLabel(value); val.setObjectName("stat-val")
        c   = color or PALETTE["text"]
        val.setStyleSheet(f"color: {c}; font-size: 22px; font-weight: 700;")
        val.setProperty("_color", c)
        lyt.addWidget(lbl); lyt.addWidget(val)
        grp.setProperty("_val_lbl", val)
        return grp

    def _set_stat(self, card, value):
        lbl = card.property("_val_lbl")
        if lbl: lbl.setText(str(value))

    def _refresh(self):
        search   = self.filter_search.text().strip() or None
        evt_type = self.filter_type.currentData()
        sev      = self.filter_severity.currentText()
        severity = None if sev == "All Severities" else sev

        events = self.controller.get_audit_events(search=search, event_type=evt_type, severity=severity)
        stats  = self.controller.get_stats()

        self._set_stat(self.stat_total,   stats["total"])
        self._set_stat(self.stat_today,   stats["today"])
        self._set_stat(self.stat_blocked, stats["by_type"].get("dlp_blocked", 0))
        self._set_stat(self.stat_warn,    stats["by_severity"].get("warning", 0) + stats["by_severity"].get("error", 0))

        sev_colors = {"info": PALETTE["text2"], "warning": PALETTE["warn"],
                      "error": PALETTE["danger"], "critical": PALETTE["critical"]}

        self.table.setRowCount(len(events))
        for i, ev in enumerate(events):
            dt_str = datetime.fromtimestamp(ev.timestamp).strftime("%m/%d %H:%M:%S")
            items = [
                QTableWidgetItem(dt_str),
                QTableWidgetItem(ev.event_type),
                QTableWidgetItem(ev.severity.upper()),
                QTableWidgetItem(ev.file_name),
                QTableWidgetItem(ev.recipient),
                QTableWidgetItem(str(ev.details)[:80]),
            ]
            color = QColor(sev_colors.get(ev.severity, PALETTE["text2"]))
            items[2].setForeground(QBrush(color))
            for col, item in enumerate(items):
                self.table.setItem(i, col, item)

        self.table.resizeRowsToContents()

    def _verify(self):
        ok, bad_id = self.controller.verify_audit_integrity()
        if ok:
            self._set_stat(self.stat_chain, "✓ OK")
            QMessageBox.information(self, "Integrity Check", "✅  Audit chain integrity verified — no tampering detected.")
        else:
            self._set_stat(self.stat_chain, "✗ FAIL")
            QMessageBox.critical(self, "Integrity FAILED", f"⚠️  Hash chain broken at event ID {bad_id}.\nThe audit log may have been tampered with.")

    def _export(self):
        path, _ = QFileDialog.getSaveFileName(self, "Export Audit Log", "audit_export.json", "JSON Files (*.json)")
        if path:
            with open(path, "w") as f:
                f.write(self.controller.export_audit())
            QMessageBox.information(self, "Exported", f"Audit log exported to:\n{path}")


# ── Main Window ───────────────────────────────────────────────────────────────

class MainWindow(QMainWindow):
    def __init__(self, controller):
        super().__init__()
        self.controller = controller
        self.setWindowTitle("SecureDLP  —  v1.0")
        self.setMinimumSize(980, 700)
        self.setStyleSheet(STYLESHEET)
        self._build()

    def _build(self):
        central = QWidget(); self.setCentralWidget(central)
        root    = QVBoxLayout(central); root.setContentsMargins(0, 0, 0, 0); root.setSpacing(0)

        # Header bar
        header = QWidget(); header.setFixedHeight(56)
        header.setStyleSheet(f"background: {PALETTE['header']}; border-bottom: 1px solid {PALETTE['border']};")
        hlay = QHBoxLayout(header); hlay.setContentsMargins(20, 0, 20, 0)

        logo = QLabel("🛡  SecureDLP")
        logo.setStyleSheet(f"font-size: 16px; font-weight: 700; color: {PALETTE['text']}; letter-spacing: 1px;")
        subtitle = QLabel("Zero-Knowledge File Encryption & DLP")
        subtitle.setStyleSheet(f"font-size: 12px; color: {PALETTE['text2']};")

        self.status_dot = QLabel("●")
        self.status_dot.setStyleSheet(f"color: {PALETTE['accent']}; font-size: 14px;")
        self.status_lbl = QLabel("System ready")
        self.status_lbl.setStyleSheet(f"color: {PALETTE['text2']}; font-size: 12px;")

        hlay.addWidget(logo); hlay.addWidget(subtitle); hlay.addStretch()
        hlay.addWidget(self.status_dot); hlay.addWidget(self.status_lbl)
        root.addWidget(header)

        # Tabs
        self.tabs = QTabWidget()
        self.tabs.setDocumentMode(True)
        self.tabs.addTab(EncryptTab(self.controller), "🔒  Encrypt / Decrypt")
        self.tabs.addTab(SharingTab(self.controller), "🔗  Secure Sharing")
        self.tabs.addTab(DLPTab(self.controller),     "🛡  DLP Policy")
        self.tabs.addTab(AuditTab(self.controller),   "📋  Audit Log")
        root.addWidget(self.tabs)

        # Status bar
        sb = QStatusBar()
        sb.showMessage(f"  Database: {self.controller.DB_PATH}   |   Shares dir: {self.controller.SHARES_DIR}   |   AES-256-GCM  ·  PBKDF2-SHA256  ·  SQLite audit chain")
        self.setStatusBar(sb)

    def closeEvent(self, event):
        self.controller.shutdown()
        event.accept()


# ── Entry point ───────────────────────────────────────────────────────────────

def main():
    import sys
    sys.path.insert(0, str(Path(__file__).parent.parent))

    from secure_dlp.app import AppController

    app = QApplication(sys.argv)
    app.setApplicationName("SecureDLP")
    app.setStyle("Fusion")
    if sys.platform == "win32":
        try:
            import ctypes
            ctypes.windll.shell32.SetCurrentProcessExplicitAppUserModelID("SecureDLP.v1")
        except Exception:
            pass
    palette = QPalette()
    palette.setColor(QPalette.Window,       QColor(PALETTE["bg"]))
    palette.setColor(QPalette.WindowText,   QColor(PALETTE["text"]))
    palette.setColor(QPalette.Base,         QColor(PALETTE["surface"]))
    palette.setColor(QPalette.AlternateBase,QColor(PALETTE["surface2"]))
    palette.setColor(QPalette.Text,         QColor(PALETTE["text"]))
    palette.setColor(QPalette.Button,       QColor(PALETTE["surface2"]))
    palette.setColor(QPalette.ButtonText,   QColor(PALETTE["text"]))
    palette.setColor(QPalette.Highlight,    QColor(PALETTE["accent2"]))
    palette.setColor(QPalette.HighlightedText, QColor("#ffffff"))
    app.setPalette(palette)

    controller = AppController()
    window     = MainWindow(controller)
    icon_path = _resource_path("app_icon.ico")
    if os.path.exists(icon_path):
        icon = QIcon(icon_path)
        app.setWindowIcon(icon)
        window.setWindowIcon(icon)
    window.show()
    sys.exit(app.exec_())


if __name__ == "__main__":
    main()
