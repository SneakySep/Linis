"""Main dashboard window.

Layout:
    header          title, subtitle, settings button
    stat strip      files scanned / threats found / cache entries / quota
    drop zone       drag-and-drop target + Select File / Select Folder
    watcher bar     real-time Downloads watcher toggle + folder path
    results table   one row per scan event, colour-coded by verdict
    status bar      current activity + progress

All scanning is delegated to ``ScanWorker`` on a ``QThreadPool``. The window
itself only ever touches widgets from Qt signal slots, which run on the GUI
thread.
"""

from __future__ import annotations

import logging
import os
import time
from pathlib import Path
from typing import Any

from PySide6.QtCore import QSize, Qt, QTimer, Signal
from PySide6.QtGui import QAction, QColor, QFont, QIcon, QPainter, QPixmap
from PySide6.QtWidgets import (
    QAbstractItemView,
    QApplication,
    QCheckBox,
    QFileDialog,
    QFrame,
    QHBoxLayout,
    QHeaderView,
    QLabel,
    QMainWindow,
    QMenu,
    QMessageBox,
    QProgressBar,
    QPushButton,
    QSizePolicy,
    QSystemTrayIcon,
    QTableWidget,
    QTableWidgetItem,
    QVBoxLayout,
    QWidget,
)

from scanner.config import APP_NAME, APP_VERSION, Settings
from scanner.database import ScanDatabase
from scanner.engine import ScanResult, Status, Verdict
from scanner.quarantine import QuarantineManager
from scanner.watcher import FolderWatcher, collect_files
from ui import theme
from ui.quarantine_dialog import QuarantineDialog
from ui.settings_dialog import SettingsDialog
from ui.workers import (
    FolderExpandWorker,
    Pool,
    ScanWorker,
    human_size,
    short_hash,
    timestamp_text,
)

log = logging.getLogger(__name__)

COLUMNS = [
    ("Timestamp", 138),
    ("Filename", 170),
    ("Size", 68),
    ("SHA-256", 150),
    ("AMSI", 78),
    ("YARA", 78),
    ("Defender", 92),
    ("MalwareBazaar", 116),
    ("MetaDefender", 116),
    ("Reputation", 96),
    ("Verdict", 96),
]

(COL_TS, COL_NAME, COL_SIZE, COL_HASH, COL_AMSI, COL_YARA, COL_DEF, COL_MB,
 COL_OP, COL_REP, COL_VERDICT) = range(11)


def _reputation_label(result: ScanResult) -> str:
    """Short reputation cell text."""
    rep = result.reputation
    if rep is None:
        return "-"
    if not rep.flags:
        return "OK"
    if rep.is_suspicious:
        return f"Risk {rep.risk}"
    if rep.signature.status.value == "Valid":
        return "Signed"
    return f"Risk {rep.risk}" if rep.risk else "OK"


def _reputation_color(result: ScanResult) -> tuple[str, str]:
    rep = result.reputation
    if rep is None:
        return theme.TEXT_MUTED, theme.GREY_BG
    if rep.is_suspicious:
        return theme.AMBER, theme.AMBER_BG
    if rep.risk >= 20:
        return theme.TEXT_SECONDARY, theme.GREY_BG
    return theme.GREEN, theme.GREEN_BG


def _reputation_tooltip(result: ScanResult) -> str:
    rep = result.reputation
    if rep is None:
        return "No reputation data"
    lines = [f"Local risk score: {rep.risk}/100"]
    if rep.flags:
        lines.extend(f"  - {flag}" for flag in rep.flags)
    else:
        lines.append("  No local risk signals")
    if rep.motw.present:
        lines.append(f"MOTW zone: {rep.motw.zone_label}")
        if rep.motw.host_url:
            lines.append(f"  from: {rep.motw.host_url}")
    if rep.pe.is_pe:
        lines.append(
            f"PE: {rep.pe.machine} {rep.pe.subsystem}, "
            f"max entropy {rep.pe.max_entropy:.2f}"
        )
    return "\n".join(lines)


class MainWindow(QMainWindow):
    """HybridShield main window."""

    def __init__(self, settings: Settings) -> None:
        super().__init__()
        self.settings = settings
        self.pool = Pool(int(settings.get("max_scan_workers") or 3))
        self.db = ScanDatabase()

        self._active_workers: list[ScanWorker] = []
        self._watcher: FolderWatcher | None = None
        self._pending_expansions = 0
        self._queue_total = 0
        self._queue_done = 0
        self._tray_hint_shown = False

        self.setWindowTitle(f"{APP_NAME} - Hybrid File Scanner")
        self.setMinimumSize(1120, 720)
        self.resize(1280, 800)
        self.setAcceptDrops(True)

        self._build_ui()
        self._build_tray()
        self._load_history()
        self._refresh_stats()
        self._restore_watcher_state()

    # ------------------------------------------------------------------ UI -- #

    def _build_ui(self) -> None:
        central = QWidget()
        root = QVBoxLayout(central)
        root.setContentsMargins(20, 18, 20, 14)
        root.setSpacing(14)

        root.addLayout(self._build_header())
        root.addLayout(self._build_stats())
        root.addWidget(self._build_drop_zone())
        root.addWidget(self._build_watcher_bar())
        root.addWidget(self._build_table(), 1)
        root.addLayout(self._build_footer())

        self.setCentralWidget(central)

    def _build_header(self) -> QHBoxLayout:
        row = QHBoxLayout()
        row.setSpacing(12)

        text_col = QVBoxLayout()
        text_col.setSpacing(2)
        title = QLabel(APP_NAME)
        title.setObjectName("Title")
        subtitle = QLabel(
            "AMSI + YARA + Windows Defender + MalwareBazaar + MetaDefender. "
            "Hashes only, never file contents."
        )
        subtitle.setObjectName("Subtitle")
        text_col.addWidget(title)
        text_col.addWidget(subtitle)
        row.addLayout(text_col, 1)

        self.settings_btn = QPushButton("Settings")
        self.settings_btn.clicked.connect(self._open_settings)
        row.addWidget(self.settings_btn, 0, Qt.AlignmentFlag.AlignTop)

        self.quarantine_btn = QPushButton("Quarantine")
        self.quarantine_btn.clicked.connect(self._open_quarantine)
        row.addWidget(self.quarantine_btn, 0, Qt.AlignmentFlag.AlignTop)

        return row

    def _build_stats(self) -> QHBoxLayout:
        row = QHBoxLayout()
        row.setSpacing(12)

        self.stat_scanned = self._stat_card("Files scanned", "0")
        self.stat_threats = self._stat_card("Threats found", "0")
        self.stat_quarantined = self._stat_card("Quarantined", "0")
        self.stat_cache = self._stat_card("Cached hashes", "0")
        self.stat_quota = self._stat_card("MetaDefender quota", "-")

        for card in (self.stat_scanned, self.stat_threats, self.stat_quarantined,
                     self.stat_cache, self.stat_quota):
            row.addWidget(card, 1)
        return row

    def _stat_card(self, label: str, value: str) -> QFrame:
        card = QFrame()
        card.setObjectName("Card")
        card.setFixedHeight(78)
        box = QVBoxLayout(card)
        box.setContentsMargins(14, 10, 14, 10)
        box.setSpacing(2)

        value_label = QLabel(value)
        value_label.setObjectName("StatValue")
        name_label = QLabel(label)
        name_label.setObjectName("StatLabel")

        box.addWidget(value_label)
        box.addWidget(name_label)
        card.value_label = value_label          # type: ignore[attr-defined]
        return card

    def _build_drop_zone(self) -> QFrame:
        zone = QFrame()
        zone.setObjectName("DropZone")
        zone.setMinimumHeight(132)
        zone.setAcceptDrops(True)
        zone.setProperty("dragActive", False)

        box = QVBoxLayout(zone)
        box.setContentsMargins(20, 16, 20, 16)
        box.setSpacing(6)

        icon = QLabel("\u26e8")
        icon.setAlignment(Qt.AlignmentFlag.AlignCenter)
        icon_font = QFont()
        icon_font.setPointSize(26)
        icon.setFont(icon_font)
        icon.setStyleSheet(f"color: {theme.ACCENT}; background: transparent;")

        title = QLabel("Drop files or a folder here")
        title.setObjectName("DropTitle")
        title.setAlignment(Qt.AlignmentFlag.AlignCenter)

        hint = QLabel("or use the buttons below - folders are scanned recursively")
        hint.setObjectName("DropHint")
        hint.setAlignment(Qt.AlignmentFlag.AlignCenter)

        buttons = QHBoxLayout()
        buttons.setSpacing(10)
        buttons.addStretch(1)
        self.select_file_btn = QPushButton("Select File")
        self.select_file_btn.setObjectName("Primary")
        self.select_file_btn.clicked.connect(self._pick_file)
        self.select_folder_btn = QPushButton("Select Folder")
        self.select_folder_btn.clicked.connect(self._pick_folder)
        buttons.addWidget(self.select_file_btn)
        buttons.addWidget(self.select_folder_btn)
        buttons.addStretch(1)

        box.addWidget(icon)
        box.addWidget(title)
        box.addWidget(hint)
        box.addSpacing(4)
        box.addLayout(buttons)

        self.drop_zone = zone
        return zone

    def _build_watcher_bar(self) -> QFrame:
        bar = QFrame()
        bar.setObjectName("Card")
        box = QHBoxLayout(bar)
        box.setContentsMargins(14, 10, 14, 10)
        box.setSpacing(12)

        col = QVBoxLayout()
        col.setSpacing(1)
        label = QLabel("Real-time Downloads watcher")
        label.setObjectName("SectionTitle")
        self.watcher_path_label = QLabel(self.settings.watch_folder)
        self.watcher_path_label.setObjectName("Hint")
        col.addWidget(label)
        col.addWidget(self.watcher_path_label)
        box.addLayout(col, 1)

        self.watcher_state_label = QLabel("Off")
        self.watcher_state_label.setObjectName("Hint")
        box.addWidget(self.watcher_state_label)

        self.watcher_toggle = ToggleSwitch()
        self.watcher_toggle.toggled.connect(self._on_watcher_toggled)
        box.addWidget(self.watcher_toggle)

        return bar

    def _build_table(self) -> QTableWidget:
        table = QTableWidget(0, len(COLUMNS))
        table.setHorizontalHeaderLabels([c[0] for c in COLUMNS])
        table.verticalHeader().setVisible(False)
        table.setShowGrid(False)
        table.setAlternatingRowColors(True)
        table.setSelectionBehavior(QAbstractItemView.SelectionBehavior.SelectRows)
        table.setSelectionMode(QAbstractItemView.SelectionMode.SingleSelection)
        table.setEditTriggers(QAbstractItemView.EditTrigger.NoEditTriggers)
        table.setSortingEnabled(True)
        table.setWordWrap(False)
        table.setContextMenuPolicy(Qt.ContextMenuPolicy.CustomContextMenu)
        table.customContextMenuRequested.connect(self._table_context_menu)

        header = table.horizontalHeader()
        header.setStretchLastSection(False)
        header.setSectionResizeMode(QHeaderView.ResizeMode.Interactive)
        for index, (_, width) in enumerate(COLUMNS):
            table.setColumnWidth(index, width)
        header.setSectionResizeMode(COL_NAME, QHeaderView.ResizeMode.Stretch)

        table.verticalHeader().setDefaultSectionSize(32)

        self.table = table
        return table

    def _build_footer(self) -> QHBoxLayout:
        row = QHBoxLayout()
        row.setSpacing(10)

        self.status_label = QLabel("Ready")
        self.status_label.setObjectName("StatusBar")
        row.addWidget(self.status_label, 1)

        self.progress = QProgressBar()
        self.progress.setFixedWidth(180)
        self.progress.setFixedHeight(5)
        self.progress.setTextVisible(False)
        self.progress.hide()
        row.addWidget(self.progress)

        self.cancel_btn = QPushButton("Cancel")
        self.cancel_btn.setObjectName("Danger")
        self.cancel_btn.clicked.connect(self._cancel_scans)
        self.cancel_btn.hide()
        row.addWidget(self.cancel_btn)

        self.clear_btn = QPushButton("Clear list")
        self.clear_btn.setObjectName("Ghost")
        self.clear_btn.clicked.connect(self._clear_table)
        row.addWidget(self.clear_btn)

        return row

    # ---------------------------------------------------------------- tray -- #

    def _build_tray(self) -> None:
        self.tray = QSystemTrayIcon(self._tray_icon(), self)
        self.tray.setToolTip(f"{APP_NAME} - hybrid file scanner")

        menu = QMenu()
        show_action = QAction("Show HybridShield", self)
        show_action.triggered.connect(self._restore_from_tray)
        menu.addAction(show_action)

        self.tray_watcher_action = QAction("Real-time watcher", self)
        self.tray_watcher_action.setCheckable(True)
        self.tray_watcher_action.setChecked(bool(self.settings.get("watcher_enabled")))
        self.tray_watcher_action.toggled.connect(self._on_watcher_toggled)
        menu.addAction(self.tray_watcher_action)

        menu.addSeparator()

        scan_action = QAction("Scan a file...", self)
        scan_action.triggered.connect(self._pick_file)
        menu.addAction(scan_action)

        quarantine_action = QAction("Quarantine...", self)
        quarantine_action.triggered.connect(self._open_quarantine)
        menu.addAction(quarantine_action)

        settings_action = QAction("Settings...", self)
        settings_action.triggered.connect(self._open_settings)
        menu.addAction(settings_action)

        menu.addSeparator()

        quit_action = QAction("Quit", self)
        quit_action.triggered.connect(self._quit)
        menu.addAction(quit_action)

        self.tray.setContextMenu(menu)
        self.tray.activated.connect(self._on_tray_activated)
        self.tray.show()

    def _tray_icon(self) -> QIcon:
        """Draw a shield icon at runtime so no asset file is needed."""
        pixmap = QPixmap(64, 64)
        pixmap.fill(Qt.GlobalColor.transparent)
        painter = QPainter(pixmap)
        painter.setRenderHint(QPainter.RenderHint.Antialiasing)

        from PySide6.QtGui import QBrush, QPainterPath, QPen

        path = QPainterPath()
        path.moveTo(32, 6)
        path.lineTo(56, 16)
        path.lineTo(56, 34)
        path.cubicTo(56, 48, 44, 56, 32, 60)
        path.cubicTo(20, 56, 8, 48, 8, 34)
        path.lineTo(8, 16)
        path.closeSubpath()

        painter.setBrush(QBrush(QColor(theme.ACCENT)))
        painter.setPen(QPen(QColor("#ffffff"), 2))
        painter.drawPath(path)

        painter.setPen(QPen(QColor("#ffffff"), 5, Qt.PenStyle.SolidLine,
                            Qt.PenCapStyle.RoundCap, Qt.PenJoinStyle.RoundJoin))
        painter.drawLine(21, 32, 29, 41)
        painter.drawLine(29, 41, 44, 23)
        painter.end()

        return QIcon(pixmap)

    def _on_tray_activated(self, reason: QSystemTrayIcon.ActivationReason) -> None:
        if reason in (
            QSystemTrayIcon.ActivationReason.Trigger,
            QSystemTrayIcon.ActivationReason.DoubleClick,
        ):
            self._restore_from_tray()

    def _restore_from_tray(self) -> None:
        self.showNormal()
        self.raise_()
        self.activateWindow()

    def _notify(self, title: str, message: str,
                icon: QSystemTrayIcon.MessageIcon = QSystemTrayIcon.MessageIcon.Warning) -> None:
        """Native Windows toast via the tray icon."""
        if not QSystemTrayIcon.supportsMessages():
            log.info("Tray notifications unsupported: %s - %s", title, message)
            return
        self.tray.showMessage(title, message, icon, 10000)

    # ------------------------------------------------------------- scanning -- #

    def _pick_file(self) -> None:
        paths, _ = QFileDialog.getOpenFileNames(self, "Select files to scan")
        if paths:
            self._start_scan(paths, source="manual")

    def _pick_folder(self) -> None:
        folder = QFileDialog.getExistingDirectory(
            self, "Select a folder to scan", str(Path.home())
        )
        if folder:
            self._expand_and_scan(folder)

    def _expand_and_scan(self, target: str) -> None:
        self._set_status(f"Scanning folder {target}...")
        self.progress.setRange(0, 0)
        self.progress.show()
        self._pending_expansions += 1

        worker = FolderExpandWorker(target)
        worker.signals.expanded.connect(self._on_folder_expanded)
        worker.signals.failed.connect(self._on_folder_expand_failed)
        self.pool.start(worker)

    def _on_folder_expanded(self, target: str, files: list[str]) -> None:
        self._pending_expansions = max(0, self._pending_expansions - 1)
        if not files:
            self._end_busy()
            self._set_status(f"No scannable files in {target}")
            return
        self._start_scan(files, source="folder")

    def _on_folder_expand_failed(self, error: str) -> None:
        self._pending_expansions = max(0, self._pending_expansions - 1)
        self._end_busy()
        self._set_status(f"Could not read folder: {error}")

    def _start_scan(self, paths: list[str], source: str = "manual") -> None:
        paths = [p for p in paths if p]
        if not paths:
            return

        self._queue_total += len(paths)
        self._queue_done = 0
        self._update_progress()

        worker = ScanWorker(paths, self.settings, source=source)
        worker.signals.progress.connect(self._on_worker_progress)
        worker.signals.result.connect(self._on_scan_result)
        worker.signals.failed.connect(self._on_scan_failed)
        worker.signals.finished.connect(self._on_worker_finished)
        worker.signals.all_done.connect(self._on_worker_all_done)

        self._active_workers.append(worker)
        self.pool.start(worker)

        self.cancel_btn.show()
        self.progress.setRange(0, max(1, self._queue_total))
        self.progress.setValue(0)
        self.progress.show()
        self._set_status(f"Scanning {len(paths)} file(s)...")

    def _on_worker_progress(self, path: str, message: str) -> None:
        self._set_status(f"{Path(path).name}: {message}")

    def _on_scan_result(self, result: ScanResult) -> None:
        self._queue_done += 1
        self._update_progress()
        self._add_result_row(result)
        self._refresh_stats()

        if result.verdict is Verdict.MALICIOUS:
            self._alert_malicious(result)
        elif result.verdict is Verdict.SUSPICIOUS:
            self._notify(
                "Suspicious file detected",
                f"{result.file_name}\n{result.file_path}",
                QSystemTrayIcon.MessageIcon.Warning,
            )
        elif result.verdict is Verdict.CLEAN and bool(self.settings.get("notify_on_clean")):
            self._notify(
                "Scan complete - clean",
                f"{result.file_name} came back clean.",
                QSystemTrayIcon.MessageIcon.Information,
            )

    def _alert_malicious(self, result: ScanResult) -> None:
        layer = ""
        if result.defender.status is Status.MALICIOUS:
            layer = f"Windows Defender: {result.defender.detail}"
        elif result.amsi.status is Status.MALICIOUS:
            layer = f"AMSI: {result.amsi.detail}"
        elif result.yara.status is Status.MALICIOUS:
            layer = f"YARA: {result.yara.detail}"
        elif result.malwarebazaar.status is Status.MALICIOUS:
            layer = f"MalwareBazaar: {result.malwarebazaar.detail}"
        elif result.opswat.status is Status.MALICIOUS:
            layer = f"MetaDefender: {result.opswat.detail}"

        if result.quarantined:
            action = "Moved to quarantine"
        elif result.quarantine_error:
            action = f"NOT quarantined: {result.quarantine_error}"
        else:
            action = "Left on disk (auto-quarantine is off)"

        self._notify(
            "Malicious file detected",
            f"{result.file_name}\n{layer or 'Threat detected'}\n{action}",
            QSystemTrayIcon.MessageIcon.Critical,
        )
        self._set_status(
            f"MALICIOUS: {result.file_name} - {action}"
        )

        # Bring the window forward: a toast alone is easy to miss.
        if self.isMinimized() or not self.isVisible():
            self._restore_from_tray()

    def _on_scan_failed(self, path: str, error: str) -> None:
        self._queue_done += 1
        self._update_progress()
        self._set_status(f"Scan failed for {Path(path).name}: {error}")

    def _on_worker_finished(self, scanned: int, malicious: int) -> None:
        if scanned:
            suffix = f", {malicious} malicious" if malicious else ""
            self._set_status(f"Finished {scanned} file(s){suffix}")

    def _on_worker_all_done(self) -> None:
        self._active_workers = []
        if self._pending_expansions == 0:
            self._end_busy()

    def _end_busy(self) -> None:
        self.progress.hide()
        self.progress.setRange(0, 100)
        self.cancel_btn.hide()
        self._queue_total = 0
        self._queue_done = 0

    def _update_progress(self) -> None:
        if self._queue_total <= 0:
            return
        self.progress.setRange(0, self._queue_total)
        self.progress.setValue(min(self._queue_done, self._queue_total))

    def _cancel_scans(self) -> None:
        for worker in self._active_workers:
            worker.cancel()
        self._set_status("Cancelling...")

    # --------------------------------------------------------------- table -- #

    def _add_result_row(self, result: ScanResult) -> None:
        table = self.table
        table.setSortingEnabled(False)
        row = table.rowCount()
        table.insertRow(row)

        is_malicious = result.verdict is Verdict.MALICIOUS
        values = [
            result.timestamp_text,
            result.file_name or Path(result.file_path).name,
            human_size(result.file_size),
            short_hash(result.sha256),
            result.amsi.status.value,
            result.yara.status.value,
            result.defender.status.value,
            result.malwarebazaar.status.value,
            result.opswat.status.value,
            _reputation_label(result),
            result.verdict.value,
        ]

        for col, text in enumerate(values):
            item = QTableWidgetItem(str(text))
            if col in (COL_SIZE,):
                item.setTextAlignment(Qt.AlignmentFlag.AlignRight | Qt.AlignmentFlag.AlignVCenter)
            else:
                item.setTextAlignment(Qt.AlignmentFlag.AlignLeft | Qt.AlignmentFlag.AlignVCenter)

            if col in (COL_AMSI, COL_YARA, COL_DEF, COL_MB, COL_OP):
                fg, bg = theme.color_for(str(text))
                item.setForeground(QColor(fg))
            elif col == COL_REP:
                fg, bg = _reputation_color(result)
                item.setForeground(QColor(fg))
            elif col == COL_VERDICT:
                fg, bg = theme.color_for(result.verdict.value)
                item.setForeground(QColor(fg))
                item.setBackground(QColor(bg))
                font = item.font()
                font.setBold(True)
                item.setFont(font)

            if is_malicious and col != COL_VERDICT:
                item.setForeground(QColor(theme.RED))

            # Full values live in the tooltip; the cell shows an abbreviation.
            if col == COL_HASH:
                item.setToolTip(result.sha256 or "no hash")
            elif col == COL_NAME:
                item.setToolTip(result.file_path)
            elif col in (COL_AMSI, COL_YARA, COL_DEF, COL_MB, COL_OP):
                layer = {
                    COL_AMSI: result.amsi,
                    COL_YARA: result.yara,
                    COL_DEF: result.defender,
                    COL_MB: result.malwarebazaar,
                    COL_OP: result.opswat,
                }[col]
                item.setToolTip(layer.detail or layer.status.value)
            elif col == COL_REP:
                item.setToolTip(_reputation_tooltip(result))
            elif col == COL_VERDICT:
                bits = [f"Verdict: {result.verdict.value}",
                        f"Risk score: {result.score}/100"]
                if result.reputation is not None and result.reputation.flags:
                    bits.append("Local signals:")
                    bits.extend(f"  - {flag}" for flag in result.reputation.flags)
                if result.from_cache:
                    bits.append("Served from local cache (no API quota used)")
                if result.quarantined:
                    bits.append(f"Quarantined to: {result.quarantine_path}")
                elif result.quarantine_error:
                    bits.append(f"Quarantine failed: {result.quarantine_error}")
                if result.error:
                    bits.append(f"Error: {result.error}")
                item.setToolTip("\n".join(bits))

            table.setItem(row, col, item)

        table.setSortingEnabled(True)
        table.scrollToBottom()

    def _load_history(self) -> None:
        """Populate the table from the persisted scan log at startup."""
        rows = self.db.recent_scans(limit=500)
        if not rows:
            return

        table = self.table
        table.setSortingEnabled(False)
        table.setRowCount(0)

        for record in reversed(rows):
            row = table.rowCount()
            table.insertRow(row)
            values = [
                timestamp_text(record.get("scanned_at")),
                record.get("file_name") or Path(str(record.get("file_path", ""))).name,
                human_size(int(record.get("file_size") or 0)),
                short_hash(str(record.get("sha256") or "")),
                record.get("amsi_status", "Unknown"),
                record.get("yara_status", "Unknown"),
                record.get("defender_status", "Unknown"),
                record.get("mb_status", "Unknown"),
                record.get("opswat_status", "Unknown"),
                "-",  # reputation is not persisted in scan_log
                record.get("verdict", "Unknown"),
            ]
            # The history table has no stored reputation blob, so that cell is a
            # placeholder. Index the verdict by position, not by COL_VERDICT:
            # the two differ because reputation is not persisted in scan_log.
            verdict_text = str(record.get("verdict", "Unknown"))
            for col, text in enumerate(values):
                item = QTableWidgetItem(str(text))
                if col == COL_SIZE:
                    item.setTextAlignment(Qt.AlignmentFlag.AlignRight
                                          | Qt.AlignmentFlag.AlignVCenter)
                if col in (COL_AMSI, COL_YARA, COL_DEF, COL_MB, COL_OP):
                    fg, _ = theme.color_for(str(text))
                    item.setForeground(QColor(fg))
                elif col == COL_VERDICT:
                    fg, bg = theme.color_for(verdict_text)
                    item.setForeground(QColor(fg))
                    item.setBackground(QColor(bg))
                    font = item.font()
                    font.setBold(True)
                    item.setFont(font)
                if col == COL_HASH:
                    item.setToolTip(str(record.get("sha256") or ""))
                elif col == COL_NAME:
                    item.setToolTip(str(record.get("file_path") or ""))
                table.setItem(row, col, item)

        table.setSortingEnabled(True)
        table.scrollToBottom()

    def _clear_table(self) -> None:
        self.table.setRowCount(0)

    def _table_context_menu(self, pos) -> None:
        item = self.table.itemAt(pos)
        if item is None:
            return
        row = item.row()
        name_item = self.table.item(row, COL_NAME)
        hash_item = self.table.item(row, COL_HASH)
        if name_item is None:
            return
        path = name_item.toolTip() or name_item.text()
        sha = hash_item.toolTip() if hash_item else ""

        menu = QMenu(self)
        rescan = QAction("Rescan this file", self)
        rescan.triggered.connect(lambda: self._start_scan([path], source="manual"))
        menu.addAction(rescan)

        reveal = QAction("Show in Explorer", self)
        reveal.triggered.connect(lambda: self._reveal(path))
        menu.addAction(reveal)

        copy_hash = QAction("Copy SHA-256", self)
        copy_hash.triggered.connect(lambda: QApplication.clipboard().setText(sha))
        menu.addAction(copy_hash)

        copy_path = QAction("Copy full path", self)
        copy_path.triggered.connect(lambda: QApplication.clipboard().setText(path))
        menu.addAction(copy_path)

        menu.exec(self.table.viewport().mapToGlobal(pos))

    def _reveal(self, path: str) -> None:
        try:
            if os.path.exists(path):
                import subprocess

                subprocess.Popen(["explorer", "/select,", os.path.normpath(path)])
            else:
                self._set_status("File no longer exists on disk")
        except OSError as exc:
            self._set_status(f"Could not open Explorer: {exc}")

    # ------------------------------------------------------------- watcher -- #

    def _restore_watcher_state(self) -> None:
        enabled = bool(self.settings.get("watcher_enabled"))
        self.watcher_toggle.blockSignals(True)
        self.watcher_toggle.setChecked(enabled)
        self.watcher_toggle.blockSignals(False)
        self.tray_watcher_action.blockSignals(True)
        self.tray_watcher_action.setChecked(enabled)
        self.tray_watcher_action.blockSignals(False)

        if enabled:
            # Start after the window is shown so a failure can be reported.
            QTimer.singleShot(400, lambda: self._set_watcher(True, persist=False))
        else:
            self._update_watcher_labels(False)

    def _on_watcher_toggled(self, enabled: bool) -> None:
        self._set_watcher(enabled, persist=True)

    def _set_watcher(self, enabled: bool, persist: bool = True) -> None:
        if enabled:
            folder = self.settings.watch_folder
            if not Path(folder).is_dir():
                QMessageBox.warning(
                    self,
                    "Folder unavailable",
                    f"The watch folder does not exist:\n{folder}\n\n"
                    "Pick a different folder in Settings.",
                )
                self._sync_toggle_state(False)
                return
            try:
                watcher = FolderWatcher(
                    folder,
                    on_ready=self._on_watched_file,
                    on_error=lambda msg: self._set_status(msg),
                )
                watcher.start()
            except Exception as exc:
                log.exception("Could not start watcher")
                QMessageBox.critical(self, "Watcher error",
                                     f"Could not watch {folder}:\n{exc}")
                self._sync_toggle_state(False)
                return
            self._watcher = watcher
            self._update_watcher_labels(True)
            self._set_status(f"Watching {folder} for new files")
            if not self._tray_hint_shown:
                self._tray_hint_shown = True
                self._notify(
                    "Real-time watcher active",
                    f"New files in {folder} will be scanned automatically.",
                    QSystemTrayIcon.MessageIcon.Information,
                )
        else:
            if self._watcher is not None:
                self._watcher.stop()
                self._watcher = None
            self._update_watcher_labels(False)
            self._set_status("Real-time watcher stopped")

        self._sync_toggle_state(enabled)
        if persist:
            self.settings.set("watcher_enabled", enabled)
            self.settings.save()

    def _sync_toggle_state(self, enabled: bool) -> None:
        self.watcher_toggle.blockSignals(True)
        self.watcher_toggle.setChecked(enabled)
        self.watcher_toggle.blockSignals(False)
        self.tray_watcher_action.blockSignals(True)
        self.tray_watcher_action.setChecked(enabled)
        self.tray_watcher_action.blockSignals(False)

    def _update_watcher_labels(self, enabled: bool) -> None:
        self.watcher_path_label.setText(self.settings.watch_folder)
        self.watcher_state_label.setText("Active" if enabled else "Off")
        color = theme.GREEN if enabled else theme.TEXT_MUTED
        self.watcher_state_label.setStyleSheet(f"color: {color}; background: transparent;")

    def _on_watched_file(self, path: str) -> None:
        """Called from the watcher's worker thread - hop to the GUI thread."""
        QTimer.singleShot(0, lambda: self._start_scan([path], source="watcher"))

    # ------------------------------------------------------------- settings -- #

    def _open_settings(self) -> None:
        dialog = SettingsDialog(self.settings, self.pool, self)
        dialog.settings_saved.connect(self._on_settings_saved)
        dialog.exec()

    def _open_quarantine(self) -> None:
        manager = QuarantineManager(self.db)
        dialog = QuarantineDialog(manager, self)
        dialog.exec()
        self._refresh_stats()

    def _on_settings_saved(self) -> None:
        self.pool.set_max_threads(int(self.settings.get("max_scan_workers") or 3))
        self._update_watcher_labels(self._watcher is not None)

        # A folder change while watching needs the observer restarted.
        if self._watcher is not None:
            new_folder = self.settings.watch_folder
            if os.path.normcase(self._watcher.folder) != os.path.normcase(new_folder):
                self._watcher.set_folder(new_folder)
                self._update_watcher_labels(True)
                self._set_status(f"Now watching {new_folder}")

        self._refresh_stats()
        self._set_status("Settings saved")

    # ---------------------------------------------------------------- stats -- #

    def _refresh_stats(self) -> None:
        try:
            stats = self.db.stats()
        except Exception:
            log.debug("Could not read stats", exc_info=True)
            return
        self.stat_scanned.value_label.setText(f"{stats['log_entries']:,}")   # type: ignore[attr-defined]
        self.stat_threats.value_label.setText(f"{stats['malicious_findings']:,}")  # type: ignore[attr-defined]
        self.stat_quarantined.value_label.setText(f"{stats.get('quarantined', 0):,}")  # type: ignore[attr-defined]
        self.stat_cache.value_label.setText(f"{stats['cache_entries']:,}")   # type: ignore[attr-defined]

    def set_quota(self, remaining: int | None) -> None:
        text = f"{remaining:,}" if isinstance(remaining, int) else "-"
        self.stat_quota.value_label.setText(text)  # type: ignore[attr-defined]

    def _set_status(self, message: str) -> None:
        self.status_label.setText(message)

    # ------------------------------------------------------- drag and drop -- #

    def dragEnterEvent(self, event) -> None:  # noqa: N802 - Qt override
        if event.mimeData().hasUrls():
            event.acceptProposedAction()
            self._set_drag_active(True)
        else:
            event.ignore()

    def dragLeaveEvent(self, event) -> None:  # noqa: N802
        self._set_drag_active(False)
        super().dragLeaveEvent(event)

    def dropEvent(self, event) -> None:  # noqa: N802
        self._set_drag_active(False)
        urls = event.mimeData().urls()
        if not urls:
            return
        event.acceptProposedAction()

        files: list[str] = []
        folders: list[str] = []
        for url in urls:
            path = url.toLocalFile()
            if not path:
                continue
            if os.path.isdir(path):
                folders.append(path)
            elif os.path.isfile(path):
                files.append(path)

        if files:
            self._start_scan(files, source="manual")
        for folder in folders:
            self._expand_and_scan(folder)

    def _set_drag_active(self, active: bool) -> None:
        self.drop_zone.setProperty("dragActive", "true" if active else "false")
        self.drop_zone.style().unpolish(self.drop_zone)
        self.drop_zone.style().polish(self.drop_zone)

    # -------------------------------------------------------------- closing -- #

    def closeEvent(self, event) -> None:  # noqa: N802
        if bool(self.settings.get("minimize_to_tray")) and self.tray.isVisible():
            event.ignore()
            self.hide()
            if not self._tray_hint_shown:
                self._tray_hint_shown = True
                self._notify(
                    "HybridShield is still running",
                    "The app minimised to the system tray. Right-click the tray "
                    "icon to quit.",
                    QSystemTrayIcon.MessageIcon.Information,
                )
            return

        self._shutdown()
        event.accept()

    def _quit(self) -> None:
        self._shutdown()
        QApplication.quit()

    def _shutdown(self) -> None:
        if self._watcher is not None:
            try:
                self._watcher.stop()
            except Exception:
                log.debug("Watcher stop raised", exc_info=True)
            self._watcher = None
        for worker in self._active_workers:
            worker.cancel()
        self.pool.wait(2000)
        try:
            self.db.close()
        except Exception:
            log.debug("DB close raised", exc_info=True)
        self.tray.hide()


class ToggleSwitch(QCheckBox):
    """A small iOS-style switch drawn with paint events.

    Subclassing QCheckBox keeps the ``toggled``/``isChecked`` API, so the rest
    of the window does not care that it is painted rather than styled.
    """

    def __init__(self, parent: QWidget | None = None) -> None:
        super().__init__(parent)
        self.setCursor(Qt.CursorShape.PointingHandCursor)
        self.setFixedSize(QSize(46, 26))
        self.setSizePolicy(QSizePolicy.Policy.Fixed, QSizePolicy.Policy.Fixed)

    def sizeHint(self) -> QSize:  # noqa: N802
        return QSize(46, 26)

    def hitButton(self, pos) -> bool:  # noqa: N802
        return self.rect().contains(pos)

    def paintEvent(self, event) -> None:  # noqa: N802
        from PySide6.QtGui import QBrush, QPainterPath, QPen

        painter = QPainter(self)
        painter.setRenderHint(QPainter.RenderHint.Antialiasing)

        track = QPainterPath()
        track.addRoundedRect(1, 3, 44, 20, 10, 10)

        on = self.isChecked()
        painter.setPen(Qt.PenStyle.NoPen)
        painter.setBrush(QBrush(QColor(theme.ACCENT if on else theme.BORDER_STRONG)))
        painter.drawPath(track)

        knob_x = 26 if on else 4
        painter.setBrush(QBrush(QColor("#ffffff" if on else theme.TEXT_SECONDARY)))
        painter.setPen(QPen(QColor(0, 0, 0, 40), 1))
        painter.drawEllipse(knob_x, 5, 16, 16)
        painter.end()
