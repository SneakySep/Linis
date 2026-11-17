"""Quarantine manager dialog: review, restore, delete.

Restoring is deliberately a two-step action with an explicit warning: putting a
file back on disk is the one operation here that can re-arm a threat.
"""

from __future__ import annotations

import logging
import os
from pathlib import Path

from PySide6.QtCore import Qt
from PySide6.QtGui import QColor
from PySide6.QtWidgets import (
    QAbstractItemView,
    QDialog,
    QHBoxLayout,
    QHeaderView,
    QLabel,
    QMessageBox,
    QPushButton,
    QTableWidget,
    QTableWidgetItem,
    QVBoxLayout,
    QWidget,
)

from scanner.quarantine import QuarantineError, QuarantineManager
from ui import theme
from ui.workers import human_size, short_hash, timestamp_text

log = logging.getLogger(__name__)

COLUMNS = [
    ("Quarantined", 140),
    ("Filename", 200),
    ("Size", 76),
    ("SHA-256", 170),
    ("Threat", 220),
    ("Status", 90),
]

(COL_WHEN, COL_NAME, COL_SIZE, COL_HASH, COL_THREAT, COL_STATUS) = range(6)


class QuarantineDialog(QDialog):
    """Lists quarantined files with restore and delete actions."""

    def __init__(self, manager: QuarantineManager, parent: QWidget | None = None) -> None:
        super().__init__(parent)
        self._manager = manager
        self._records: list = []

        self.setWindowTitle("HybridShield - Quarantine")
        self.setMinimumSize(940, 560)
        self.setModal(True)

        self._build()
        self._reload()

    # -- construction ------------------------------------------------------ #

    def _build(self) -> None:
        root = QVBoxLayout(self)
        root.setContentsMargins(20, 18, 20, 14)
        root.setSpacing(12)

        title = QLabel("Quarantine")
        title.setObjectName("Title")
        root.addWidget(title)

        self.summary = QLabel("")
        self.summary.setObjectName("Hint")
        self.summary.setWordWrap(True)
        root.addWidget(self.summary)

        self.table = QTableWidget(0, len(COLUMNS))
        self.table.setHorizontalHeaderLabels([c[0] for c in COLUMNS])
        self.table.verticalHeader().setVisible(False)
        self.table.setShowGrid(False)
        self.table.setAlternatingRowColors(True)
        self.table.setSelectionBehavior(QAbstractItemView.SelectionBehavior.SelectRows)
        self.table.setSelectionMode(QAbstractItemView.SelectionMode.SingleSelection)
        self.table.setEditTriggers(QAbstractItemView.EditTrigger.NoEditTriggers)
        self.table.setWordWrap(False)
        self.table.verticalHeader().setDefaultSectionSize(32)
        header = self.table.horizontalHeader()
        header.setSectionResizeMode(QHeaderView.ResizeMode.Interactive)
        for index, (_, width) in enumerate(COLUMNS):
            self.table.setColumnWidth(index, width)
        header.setSectionResizeMode(COL_THREAT, QHeaderView.ResizeMode.Stretch)
        self.table.itemSelectionChanged.connect(self._update_buttons)
        root.addWidget(self.table, 1)

        buttons = QHBoxLayout()
        buttons.setSpacing(8)

        self.restore_btn = QPushButton("Restore selected")
        self.restore_btn.clicked.connect(self._restore)
        self.restore_btn.setEnabled(False)
        buttons.addWidget(self.restore_btn)

        self.delete_btn = QPushButton("Delete selected")
        self.delete_btn.setObjectName("Danger")
        self.delete_btn.clicked.connect(self._delete)
        self.delete_btn.setEnabled(False)
        buttons.addWidget(self.delete_btn)

        self.reveal_btn = QPushButton("Show in Explorer")
        self.reveal_btn.setObjectName("Ghost")
        self.reveal_btn.clicked.connect(self._reveal)
        self.reveal_btn.setEnabled(False)
        buttons.addWidget(self.reveal_btn)

        buttons.addStretch(1)

        close_btn = QPushButton("Close")
        close_btn.setObjectName("Primary")
        close_btn.clicked.connect(self.accept)
        buttons.addWidget(close_btn)

        root.addLayout(buttons)

    # -- data -------------------------------------------------------------- #

    def _reload(self) -> None:
        self._records = self._manager.list_records()
        table = self.table
        table.setRowCount(0)

        for record in self._records:
            row = table.rowCount()
            table.insertRow(row)
            values = [
                timestamp_text(record.quarantined_at),
                record.file_name,
                human_size(record.file_size),
                short_hash(record.sha256),
                record.threat_detail or record.verdict,
                "Present" if record.exists else "MISSING",
            ]
            for col, text in enumerate(values):
                item = QTableWidgetItem(str(text))
                if col == COL_SIZE:
                    item.setTextAlignment(Qt.AlignmentFlag.AlignRight
                                          | Qt.AlignmentFlag.AlignVCenter)
                if col == COL_STATUS:
                    if record.exists:
                        item.setForeground(QColor(theme.AMBER))
                    else:
                        item.setForeground(QColor(theme.RED))
                if col == COL_HASH:
                    item.setToolTip(record.sha256 or "no hash")
                if col == COL_NAME:
                    item.setToolTip(record.original_path)
                table.setItem(row, col, item)

        stats = self._manager.stats()
        if stats["count"] == 0:
            self.summary.setText(
                "Nothing is quarantined. Files flagged as malicious are moved "
                "here automatically when auto-quarantine is enabled in Settings."
            )
        else:
            missing = stats["missing"]
            extra = (f"  |  {missing} file(s) missing from the store"
                     if missing else "")
            self.summary.setText(
                f"{stats['count']} file(s) quarantined, "
                f"{human_size(int(stats['total_bytes']))} total{extra}.\n"
                f"Store: {stats['directory']}"
            )

        self._update_buttons()

    def _selected_record(self):
        rows = self.table.selectionModel().selectedRows()
        if not rows:
            return None
        index = rows[0].row()
        if 0 <= index < len(self._records):
            return self._records[index]
        return None

    def _update_buttons(self) -> None:
        record = self._selected_record()
        has = record is not None
        self.restore_btn.setEnabled(has and record.exists)
        self.delete_btn.setEnabled(has)
        self.reveal_btn.setEnabled(has and record.exists)

    # -- actions ----------------------------------------------------------- #

    def _restore(self) -> None:
        record = self._selected_record()
        if record is None:
            return

        confirm = QMessageBox.warning(
            self,
            "Restore quarantined file",
            f"Put this file back on disk?\n\n"
            f"File: {record.file_name}\n"
            f"Threat: {record.threat_detail or record.verdict}\n"
            f"Original location: {record.original_path}\n\n"
            "Restoring re-arms the file. Only do this if you are certain it "
            "was a false positive.",
            QMessageBox.StandardButton.Yes | QMessageBox.StandardButton.Cancel,
            QMessageBox.StandardButton.Cancel,
        )
        if confirm != QMessageBox.StandardButton.Yes:
            return

        try:
            restored = self._manager.restore(record.id)
        except QuarantineError as exc:
            QMessageBox.critical(self, "Restore failed", str(exc))
            return
        except Exception as exc:
            log.exception("Restore crashed")
            QMessageBox.critical(self, "Restore failed", f"Unexpected error: {exc}")
            return

        QMessageBox.information(
            self, "Restored", f"The file was restored to:\n{restored}"
        )
        self._reload()

    def _delete(self) -> None:
        record = self._selected_record()
        if record is None:
            return

        confirm = QMessageBox.warning(
            self,
            "Delete quarantined file",
            f"Permanently delete this file?\n\n"
            f"File: {record.file_name}\n"
            f"Threat: {record.threat_detail or record.verdict}\n\n"
            "This cannot be undone. The bytes are overwritten before removal "
            "(best effort - not a guarantee on SSDs).",
            QMessageBox.StandardButton.Yes | QMessageBox.StandardButton.Cancel,
            QMessageBox.StandardButton.Cancel,
        )
        if confirm != QMessageBox.StandardButton.Yes:
            return

        try:
            self._manager.delete(record.id, shred=True)
        except QuarantineError as exc:
            QMessageBox.critical(self, "Delete failed", str(exc))
            return
        except Exception as exc:
            log.exception("Delete crashed")
            QMessageBox.critical(self, "Delete failed", f"Unexpected error: {exc}")
            return

        self._reload()

    def _reveal(self) -> None:
        record = self._selected_record()
        if record is None or not record.exists:
            return
        try:
            import subprocess

            subprocess.Popen(
                ["explorer", "/select,", os.path.normpath(record.quarantine_path)]
            )
        except OSError as exc:
            QMessageBox.warning(self, "Could not open Explorer", str(exc))
