"""Settings dialog: API keys, watch folder, cache TTL, MetaDefender quota.

Keys are written to the local settings file only. The dialog never displays a
stored key in full - it shows a masked placeholder and only overwrites the
saved value when the user types something new, so opening and closing the
dialog cannot silently wipe a key.
"""

from __future__ import annotations

from pathlib import Path

from PySide6.QtCore import Qt, Signal
from PySide6.QtWidgets import (
    QCheckBox,
    QDialog,
    QDialogButtonBox,
    QFileDialog,
    QFormLayout,
    QFrame,
    QGroupBox,
    QHBoxLayout,
    QLabel,
    QLineEdit,
    QMessageBox,
    QPushButton,
    QSpinBox,
    QVBoxLayout,
    QWidget,
)

from scanner.config import Settings, default_watch_folder
from ui import theme
from ui.workers import Pool, QuotaCheckWorker

MASK = "\u2022" * 12


class SettingsDialog(QDialog):
    """Modal settings editor."""

    settings_saved = Signal()

    def __init__(self, settings: Settings, pool: Pool, parent: QWidget | None = None) -> None:
        super().__init__(parent)
        self._settings = settings
        self._pool = pool
        self._mb_dirty = False
        self._opswat_dirty = False

        self.setWindowTitle("HybridShield - Settings")
        self.setMinimumWidth(560)
        self.setModal(True)

        self._build()
        self._load()

    # -- construction ------------------------------------------------------ #

    def _build(self) -> None:
        root = QVBoxLayout(self)
        root.setContentsMargins(20, 20, 20, 16)
        root.setSpacing(14)

        title = QLabel("Settings")
        title.setObjectName("Title")
        root.addWidget(title)

        hint = QLabel(
            "Keys are stored locally on this machine only. Only SHA-256 hashes "
            "are ever sent to MalwareBazaar and MetaDefender - never file contents."
        )
        hint.setObjectName("Hint")
        hint.setWordWrap(True)
        root.addWidget(hint)

        root.addWidget(self._build_keys_group())
        root.addWidget(self._build_scanning_group())
        root.addWidget(self._build_storage_group())

        buttons = QDialogButtonBox(
            QDialogButtonBox.StandardButton.Save | QDialogButtonBox.StandardButton.Cancel
        )
        save_btn = buttons.button(QDialogButtonBox.StandardButton.Save)
        save_btn.setObjectName("Primary")
        save_btn.setText("Save")
        buttons.accepted.connect(self._on_save)
        buttons.rejected.connect(self.reject)
        root.addWidget(buttons)

    def _build_keys_group(self) -> QGroupBox:
        group = QGroupBox("API credentials")
        form = QFormLayout(group)
        form.setContentsMargins(14, 18, 14, 12)
        form.setSpacing(10)
        form.setLabelAlignment(Qt.AlignmentFlag.AlignRight | Qt.AlignmentFlag.AlignVCenter)

        # -- MalwareBazaar ------------------------------------------------ #
        self.mb_input = QLineEdit()
        self.mb_input.setEchoMode(QLineEdit.EchoMode.Password)
        self.mb_input.setPlaceholderText("Paste your abuse.ch Auth-Key")
        self.mb_input.textEdited.connect(self._mark_mb_dirty)

        mb_row = QHBoxLayout()
        mb_row.setSpacing(8)
        mb_row.addWidget(self.mb_input, 1)
        self.mb_reveal = QPushButton("Show")
        self.mb_reveal.setObjectName("Ghost")
        self.mb_reveal.setCheckable(True)
        self.mb_reveal.setFixedWidth(64)
        self.mb_reveal.toggled.connect(self._toggle_mb_reveal)
        mb_row.addWidget(self.mb_reveal)
        mb_widget = QWidget()
        mb_widget.setLayout(mb_row)
        mb_row.setContentsMargins(0, 0, 0, 0)
        form.addRow("MalwareBazaar:", mb_widget)

        self.mb_state = QLabel("")
        self.mb_state.setObjectName("Hint")
        form.addRow("", self.mb_state)

        # -- OPSWAT ------------------------------------------------------- #
        self.opswat_input = QLineEdit()
        self.opswat_input.setEchoMode(QLineEdit.EchoMode.Password)
        self.opswat_input.setPlaceholderText("Paste your MetaDefender Cloud API key")
        self.opswat_input.textEdited.connect(self._mark_opswat_dirty)

        op_row = QHBoxLayout()
        op_row.setSpacing(8)
        op_row.addWidget(self.opswat_input, 1)
        self.opswat_reveal = QPushButton("Show")
        self.opswat_reveal.setObjectName("Ghost")
        self.opswat_reveal.setCheckable(True)
        self.opswat_reveal.setFixedWidth(64)
        self.opswat_reveal.toggled.connect(self._toggle_opswat_reveal)
        op_row.addWidget(self.opswat_reveal)
        op_widget = QWidget()
        op_widget.setLayout(op_row)
        op_row.setContentsMargins(0, 0, 0, 0)
        form.addRow("MetaDefender:", op_widget)

        # -- quota readout ------------------------------------------------ #
        quota_row = QHBoxLayout()
        quota_row.setSpacing(8)
        self.quota_label = QLabel("Quota: not checked")
        self.quota_label.setObjectName("Hint")
        quota_row.addWidget(self.quota_label, 1)
        self.quota_btn = QPushButton("Check quota")
        self.quota_btn.setObjectName("Ghost")
        self.quota_btn.clicked.connect(self._check_quota)
        quota_row.addWidget(self.quota_btn)
        quota_widget = QWidget()
        quota_widget.setLayout(quota_row)
        quota_row.setContentsMargins(0, 0, 0, 0)
        form.addRow("", quota_widget)

        return group

    def _build_scanning_group(self) -> QGroupBox:
        group = QGroupBox("Scanning")
        form = QFormLayout(group)
        form.setContentsMargins(14, 18, 14, 12)
        form.setSpacing(10)
        form.setLabelAlignment(Qt.AlignmentFlag.AlignRight | Qt.AlignmentFlag.AlignVCenter)

        # -- watch folder -------------------------------------------------- #
        self.folder_input = QLineEdit()
        self.folder_input.setPlaceholderText(default_watch_folder())
        browse = QPushButton("Browse")
        browse.clicked.connect(self._browse_folder)
        folder_row = QHBoxLayout()
        folder_row.setSpacing(8)
        folder_row.addWidget(self.folder_input, 1)
        folder_row.addWidget(browse)
        folder_widget = QWidget()
        folder_widget.setLayout(folder_row)
        folder_row.setContentsMargins(0, 0, 0, 0)
        form.addRow("Watch folder:", folder_widget)

        # -- cache TTL ----------------------------------------------------- #
        self.ttl_spin = QSpinBox()
        self.ttl_spin.setRange(1, 720)
        self.ttl_spin.setSuffix(" hours")
        self.ttl_spin.setToolTip(
            "How long a cached SHA-256 verdict stays valid. A hit costs no API quota."
        )
        form.addRow("Cache lifetime:", self.ttl_spin)

        # -- concurrency --------------------------------------------------- #
        self.workers_spin = QSpinBox()
        self.workers_spin.setRange(1, 8)
        self.workers_spin.setToolTip("How many files are scanned in parallel.")
        form.addRow("Parallel scans:", self.workers_spin)

        # -- notifications ------------------------------------------------- #
        self.notify_clean = QCheckBox("Also notify when a scan comes back clean")
        form.addRow("", self.notify_clean)

        # -- quarantine ---------------------------------------------------- #
        self.auto_quarantine = QCheckBox(
            "Move malicious files into quarantine automatically"
        )
        self.auto_quarantine.setToolTip(
            "Detected files are moved to a locked folder and renamed .quar so "
            "they cannot be executed. Restore them from the Quarantine dialog."
        )
        form.addRow("Quarantine:", self.auto_quarantine)

        # -- YARA ---------------------------------------------------------- #
        self.yara_enabled = QCheckBox(
            "Match built-in YARA rules against file content"
        )
        self.yara_enabled.setToolTip(
            "Behaviour-based rules for ransomware notes, credential dumping, "
            "download cradles and LOLBin abuse. Runs locally on the file bytes; "
            "nothing is uploaded. Catches new samples no provider has seen yet."
        )
        form.addRow("YARA rules:", self.yara_enabled)

        return group

    def _build_storage_group(self) -> QGroupBox:
        group = QGroupBox("Local data")
        box = QVBoxLayout(group)
        box.setContentsMargins(14, 18, 14, 12)
        box.setSpacing(8)

        self.storage_label = QLabel("")
        self.storage_label.setObjectName("Hint")
        self.storage_label.setWordWrap(True)
        box.addWidget(self.storage_label)

        row = QHBoxLayout()
        row.setSpacing(8)
        clear_cache = QPushButton("Clear hash cache")
        clear_cache.clicked.connect(self._clear_cache)
        clear_history = QPushButton("Clear scan history")
        clear_history.setObjectName("Danger")
        clear_history.clicked.connect(self._clear_history)
        row.addWidget(clear_cache)
        row.addWidget(clear_history)
        row.addStretch(1)
        box.addLayout(row)

        return group

    # -- state ------------------------------------------------------------- #

    def _load(self) -> None:
        s = self._settings

        mb_key = str(s.get("mb_auth_key") or "")
        self.mb_input.setText(MASK if mb_key else "")
        self._mb_dirty = False
        self._update_mb_state(bool(mb_key))

        op_key = str(s.get("opswat_api_key") or "")
        self.opswat_input.setText(MASK if op_key else "")
        self._opswat_dirty = False

        self.folder_input.setText(str(s.get("watch_folder") or ""))
        self.ttl_spin.setValue(int(s.get("cache_ttl_hours") or 24))
        self.workers_spin.setValue(int(s.get("max_scan_workers") or 3))
        self.notify_clean.setChecked(bool(s.get("notify_on_clean")))
        self.auto_quarantine.setChecked(bool(s.get("auto_quarantine", True)))
        self.yara_enabled.setChecked(bool(s.get("yara_enabled", True)))

        self._refresh_storage_label()

    def _refresh_storage_label(self) -> None:
        from scanner.database import ScanDatabase

        db = ScanDatabase()
        try:
            stats = db.stats()
        finally:
            db.close()
        self.storage_label.setText(
            f"Database: {stats['db_path']}\n"
            f"{stats['cache_entries']:,} cached hashes  |  "
            f"{stats['log_entries']:,} history rows  |  "
            f"{stats['malicious_findings']:,} malicious findings  |  "
            f"{stats.get('quarantined', 0):,} quarantined"
        )

    def _mark_mb_dirty(self) -> None:
        self._mb_dirty = True
        self._update_mb_state(bool(self.mb_input.text().strip()))

    def _mark_opswat_dirty(self) -> None:
        self._opswat_dirty = True

    def _update_mb_state(self, has_key: bool) -> None:
        self.mb_state.setText(
            "Key saved locally" if has_key else "No key - layer 2 will be skipped"
        )

    def _toggle_mb_reveal(self, shown: bool) -> None:
        self.mb_input.setEchoMode(
            QLineEdit.EchoMode.Normal if shown else QLineEdit.EchoMode.Password
        )
        self.mb_reveal.setText("Hide" if shown else "Show")

    def _toggle_opswat_reveal(self, shown: bool) -> None:
        self.opswat_input.setEchoMode(
            QLineEdit.EchoMode.Normal if shown else QLineEdit.EchoMode.Password
        )
        self.opswat_reveal.setText("Hide" if shown else "Show")

    # -- actions ----------------------------------------------------------- #

    def _browse_folder(self) -> None:
        start = self.folder_input.text().strip() or default_watch_folder()
        chosen = QFileDialog.getExistingDirectory(self, "Select watch folder", start)
        if chosen:
            self.folder_input.setText(chosen)

    def _check_quota(self) -> None:
        key = self._pending_opswat_key()
        if not key:
            self.quota_label.setText("Quota: add an API key first")
            return

        # Probe with the pending key without persisting it yet.
        probe_settings = Settings.__new__(Settings)
        probe_settings._path = self._settings._path          # noqa: SLF001
        probe_settings._lock = self._settings._lock          # noqa: SLF001
        probe_settings._data = dict(self._settings.as_dict())
        probe_settings._data["opswat_api_key"] = key

        self.quota_btn.setEnabled(False)
        self.quota_label.setText("Quota: checking...")

        worker = QuotaCheckWorker(probe_settings)
        worker.signals.done.connect(self._on_quota)
        self._pool.start(worker)

    def _on_quota(self, remaining: object, error: str) -> None:
        self.quota_btn.setEnabled(True)
        if error:
            self.quota_label.setText(f"Quota: {error}")
            return
        if remaining is None:
            self.quota_label.setText("Quota: unavailable")
            return
        self.quota_label.setText(f"Quota: {int(remaining):,} lookups remaining today")

    def _pending_mb_key(self) -> str:
        if self._mb_dirty:
            text = self.mb_input.text().strip()
            return "" if text == MASK else text
        return str(self._settings.get("mb_auth_key") or "")

    def _pending_opswat_key(self) -> str:
        if self._opswat_dirty:
            text = self.opswat_input.text().strip()
            return "" if text == MASK else text
        return str(self._settings.get("opswat_api_key") or "")

    def _clear_cache(self) -> None:
        from scanner.database import ScanDatabase

        if QMessageBox.question(
            self,
            "Clear hash cache",
            "Delete every cached hash verdict? The next scan of those files will "
            "use API quota again.",
            QMessageBox.StandardButton.Yes | QMessageBox.StandardButton.No,
            QMessageBox.StandardButton.No,
        ) != QMessageBox.StandardButton.Yes:
            return
        db = ScanDatabase()
        try:
            db.clear_cache()
        finally:
            db.close()
        self._refresh_storage_label()

    def _clear_history(self) -> None:
        from scanner.database import ScanDatabase

        if QMessageBox.question(
            self,
            "Clear scan history",
            "Delete the entire scan history table? This cannot be undone.",
            QMessageBox.StandardButton.Yes | QMessageBox.StandardButton.No,
            QMessageBox.StandardButton.No,
        ) != QMessageBox.StandardButton.Yes:
            return
        db = ScanDatabase()
        try:
            db.clear_history()
        finally:
            db.close()
        self._refresh_storage_label()

    def _on_save(self) -> None:
        folder = self.folder_input.text().strip()
        if folder and not Path(folder).is_dir():
            QMessageBox.warning(
                self, "Invalid folder", f"That folder does not exist:\n{folder}"
            )
            return

        self._settings.update(
            {
                "mb_auth_key": self._pending_mb_key(),
                "opswat_api_key": self._pending_opswat_key(),
                "watch_folder": folder,
                "cache_ttl_hours": self.ttl_spin.value(),
                "max_scan_workers": self.workers_spin.value(),
                "notify_on_clean": self.notify_clean.isChecked(),
                "auto_quarantine": self.auto_quarantine.isChecked(),
                "yara_enabled": self.yara_enabled.isChecked(),
            }
        )
        self._settings.save()
        self.settings_saved.emit()
        self.accept()
