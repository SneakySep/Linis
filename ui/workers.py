"""Background workers so the UI thread never blocks.

Every scan runs on a ``QThreadPool`` via ``QRunnable``. Workers communicate
back with Qt signals only, which is what makes cross-thread delivery safe:
Qt queues the signal into the receiver's thread, so slots run on the GUI
thread and may touch widgets directly.

The engine and database are created per worker rather than shared. SQLite
connections are thread-affine and the engine holds no cross-scan state, so
this is both simpler and safer than locking a shared instance.
"""

from __future__ import annotations

import logging
import time
from pathlib import Path
from typing import Iterable

from PySide6.QtCore import QObject, QRunnable, QThreadPool, Signal

from scanner.config import Settings
from scanner.database import ScanDatabase
from scanner.engine import ScanCancelled, ScanEngine, ScanResult, Verdict
from scanner.watcher import collect_files

log = logging.getLogger(__name__)


class WorkerSignals(QObject):
    """Signals emitted by scan workers."""

    started = Signal(str)              # file path
    progress = Signal(str, str)        # file path, message
    result = Signal(object)            # ScanResult
    finished = Signal(int, int)        # scanned count, malicious count
    failed = Signal(str, str)          # file path, error message
    all_done = Signal()


class ScanWorker(QRunnable):
    """Scans a list of files sequentially inside one pool thread."""

    def __init__(
        self,
        paths: Iterable[str],
        settings: Settings,
        *,
        source: str = "manual",
        use_cache: bool = True,
    ) -> None:
        super().__init__()
        self.signals = WorkerSignals()
        self._paths = [str(p) for p in paths]
        self._settings = settings
        self._source = source
        self._use_cache = use_cache
        self._cancelled = False
        self.setAutoDelete(True)

    def cancel(self) -> None:
        self._cancelled = True

    def _is_cancelled(self) -> bool:
        return self._cancelled

    def run(self) -> None:  # noqa: D102 - QRunnable entry point
        scanned = 0
        malicious = 0
        engine = ScanEngine(self._settings, ScanDatabase())
        try:
            for path in self._paths:
                if self._cancelled:
                    break
                self.signals.started.emit(path)
                try:
                    result = engine.scan_file(
                        path,
                        source=self._source,
                        use_cache=self._use_cache,
                        progress=lambda msg, p=path: self.signals.progress.emit(p, msg),
                        cancel=self._is_cancelled,
                    )
                except ScanCancelled:
                    break
                except Exception as exc:
                    log.exception("Scan failed for %s", path)
                    self.signals.failed.emit(path, str(exc))
                    continue

                scanned += 1
                if result.verdict is Verdict.MALICIOUS:
                    malicious += 1
                self.signals.result.emit(result)
        finally:
            engine.db.close()
            self.signals.finished.emit(scanned, malicious)
            self.signals.all_done.emit()


class FolderExpandWorker(QRunnable):
    """Expands a dropped folder into a file list off the GUI thread.

    A folder with 50,000 files takes long enough to walk that doing it inline
    would visibly freeze the window.
    """

    def __init__(self, target: str, limit: int = 5000) -> None:
        super().__init__()
        self.signals = _ExpandSignals()
        self._target = target
        self._limit = limit
        self.setAutoDelete(True)

    def run(self) -> None:  # noqa: D102
        try:
            files = collect_files(self._target, recursive=True, limit=self._limit)
        except Exception as exc:
            log.exception("Folder expansion failed for %s", self._target)
            self.signals.failed.emit(str(exc))
            return
        self.signals.expanded.emit(self._target, files)


class _ExpandSignals(QObject):
    expanded = Signal(str, list)   # target, files
    failed = Signal(str)


class QuotaCheckWorker(QRunnable):
    """Probes MetaDefender with a known-clean hash to read the live quota.

    Uses the SHA-256 of an empty file, which OPSWAT already has on record, so
    the call returns 200 with ``X-RateLimit-Remaining`` instead of a 404 that
    carries no quota header.
    """

    EMPTY_SHA256 = (
        "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
    )

    def __init__(self, settings: Settings) -> None:
        super().__init__()
        self.signals = _QuotaSignals()
        self._settings = settings
        self.setAutoDelete(True)

    def run(self) -> None:  # noqa: D102
        from scanner.engine import OpswatLayer

        layer = OpswatLayer(self._settings)
        if not layer.available():
            self.signals.done.emit(None, "No OPSWAT API key configured")
            return
        try:
            result = layer.scan(self.EMPTY_SHA256)
        except Exception as exc:
            self.signals.done.emit(None, f"Quota check failed: {exc}")
            return

        remaining = layer.quota_remaining
        if remaining is None:
            detail = result.detail or "Quota header not returned"
            self.signals.done.emit(None, detail)
        else:
            self.signals.done.emit(remaining, "")


class _QuotaSignals(QObject):
    done = Signal(object, str)   # remaining (int|None), error text


class Pool:
    """Thin wrapper around QThreadPool with a bounded worker count."""

    def __init__(self, max_threads: int = 3) -> None:
        self._pool = QThreadPool()
        self._pool.setMaxThreadCount(max(1, int(max_threads)))

    def set_max_threads(self, count: int) -> None:
        self._pool.setMaxThreadCount(max(1, int(count)))

    def start(self, runnable: QRunnable) -> None:
        self._pool.start(runnable)

    def wait(self, msecs: int = 100) -> bool:
        return self._pool.waitForDone(msecs)

    def active(self) -> int:
        return self._pool.activeThreadCount()


def human_size(num_bytes: int) -> str:
    """Format a byte count for display."""
    size = float(max(0, num_bytes))
    for unit in ("B", "KB", "MB", "GB", "TB"):
        if size < 1024 or unit == "TB":
            return f"{size:.0f} {unit}" if unit == "B" else f"{size:.1f} {unit}"
        size /= 1024
    return f"{size:.1f} TB"


def short_hash(sha256: str, head: int = 10, tail: int = 6) -> str:
    """Abbreviate a hash for the table while keeping it identifiable."""
    if not sha256:
        return "-"
    if len(sha256) <= head + tail + 3:
        return sha256
    return f"{sha256[:head]}...{sha256[-tail:]}"


def timestamp_text(epoch: float | None = None) -> str:
    return time.strftime("%Y-%m-%d %H:%M:%S", time.localtime(epoch or time.time()))
