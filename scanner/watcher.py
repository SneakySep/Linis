"""Real-time folder watcher with write-completion detection.

A naive watchdog handler fires on the first ``created`` event, which for a
browser download is *before* any bytes are on disk. Scanning then hashes a
partial file, produces a hash that matches nothing, and caches a meaningless
verdict. This module fixes that with two independent gates:

1. **Debounce** - the file must be quiet for ``settle_seconds``. Each new
   write event resets the timer, so a 2 GB download that keeps growing never
   gets scanned mid-flight.
2. **Lock probe** - on Windows, opening the file with exclusive access fails
   while another process still holds a write handle. That is the strongest
   available signal that a download is genuinely finished.

Both must pass before the file is handed to the scanner. A file that never
settles is dropped rather than scanned, and the drop is logged.
"""

from __future__ import annotations

import logging
import os
import sys
import threading
import time
from dataclasses import dataclass
from pathlib import Path
from typing import Callable

from watchdog.events import (
    FileCreatedEvent,
    FileMovedEvent,
    FileSystemEvent,
    FileSystemEventHandler,
)
from watchdog.observers import Observer

log = logging.getLogger(__name__)

# Files that are never worth scanning: partial download artefacts and temp
# names that will be renamed once complete.
IGNORED_SUFFIXES = {
    ".tmp", ".temp", ".part", ".partial", ".crdownload", ".download",
    ".!ut", ".opdownload", ".aria2", ".filepart", ".bc!", ".xltd",
}
IGNORED_PREFIXES = ("~$", ".~lock", "~WRL")
IGNORED_NAMES = {"desktop.ini", "thumbs.db", ".ds_store"}


@dataclass
class PendingFile:
    """A file waiting for its write to finish."""

    path: str
    first_seen: float
    last_event: float
    size_at_last_event: int


class _Handler(FileSystemEventHandler):
    """Feeds file events into the watcher's pending queue."""

    def __init__(self, owner: "FolderWatcher") -> None:
        self._owner = owner

    def on_created(self, event: FileSystemEvent) -> None:
        if isinstance(event, FileCreatedEvent) and not event.is_directory:
            self._owner._note(event.src_path)

    def on_modified(self, event: FileSystemEvent) -> None:
        if not event.is_directory:
            self._owner._note(event.src_path)

    def on_moved(self, event: FileSystemEvent) -> None:
        if isinstance(event, FileMovedEvent) and not event.is_directory:
            # A browser renames .crdownload -> final name when the download
            # completes. The destination is the file worth scanning.
            self._owner._note(event.dest_path)


class FolderWatcher:
    """Watches one folder and calls ``on_ready`` for each settled new file.

    ``on_ready`` is invoked from a background worker thread, never from the
    watchdog observer thread, so a slow scan cannot stall event delivery.
    """

    def __init__(
        self,
        folder: str | Path,
        on_ready: Callable[[str], None],
        *,
        settle_seconds: float = 3.0,
        poll_interval: float = 1.0,
        max_settle_seconds: float = 900.0,
        on_error: Callable[[str], None] | None = None,
    ) -> None:
        self.folder = str(folder)
        self._on_ready = on_ready
        self._on_error = on_error
        self.settle_seconds = max(0.5, float(settle_seconds))
        self.poll_interval = max(0.2, float(poll_interval))
        self.max_settle_seconds = max(self.settle_seconds, float(max_settle_seconds))

        self._observer: Observer | None = None
        self._worker: threading.Thread | None = None
        self._stop = threading.Event()
        self._lock = threading.Lock()
        self._pending: dict[str, PendingFile] = {}
        # path -> monotonic time it was dispatched. Bounded so a tray app that
        # runs for weeks cannot grow this without limit, and TTL-expired so a
        # file re-downloaded to the same path is scanned again.
        self._seen: dict[str, float] = {}
        self._seen_ttl = 3600.0
        self._seen_max = 20_000
        self._running = False

    # -- lifecycle --------------------------------------------------------- #

    @property
    def running(self) -> bool:
        return self._running

    def start(self) -> None:
        if self._running:
            return
        folder = Path(self.folder)
        if not folder.is_dir():
            raise NotADirectoryError(f"Watch folder does not exist: {folder}")

        self._stop.clear()
        observer = Observer()
        # recursive=True so subfolders of Downloads are covered too; a browser
        # writing into Downloads\Sub would otherwise be invisible.
        observer.schedule(_Handler(self), str(folder), recursive=True)
        observer.daemon = True
        observer.start()
        self._observer = observer

        worker = threading.Thread(target=self._settle_loop, name="watchdog-settler",
                                  daemon=True)
        worker.start()
        self._worker = worker
        self._running = True
        log.info("Watching %s (settle=%.1fs)", folder, self.settle_seconds)

    def stop(self) -> None:
        if not self._running:
            return
        self._stop.set()
        if self._observer is not None:
            try:
                self._observer.stop()
                self._observer.join(timeout=5)
            except Exception:
                log.debug("Observer shutdown raised", exc_info=True)
            self._observer = None
        if self._worker is not None:
            self._worker.join(timeout=5)
            self._worker = None
        self._running = False
        with self._lock:
            self._pending.clear()
        log.info("Stopped watching %s", self.folder)

    def set_folder(self, folder: str | Path) -> None:
        """Point the watcher at a new folder, restarting if it was running."""
        was_running = self._running
        if was_running:
            self.stop()
        self.folder = str(folder)
        if was_running:
            self.start()

    # -- event intake ------------------------------------------------------ #

    def _note(self, raw_path: str) -> None:
        path = os.path.abspath(raw_path)
        if not _is_candidate(path):
            return
        now = time.time()
        try:
            size = os.path.getsize(path)
        except OSError:
            # File vanished between event and stat (temp file cleanup).
            return
        with self._lock:
            existing = self._pending.get(path)
            if existing is None:
                self._pending[path] = PendingFile(path, now, now, size)
            else:
                existing.last_event = now
                existing.size_at_last_event = size

    # -- settle loop ------------------------------------------------------- #

    def _settle_loop(self) -> None:
        while not self._stop.is_set():
            self._stop.wait(self.poll_interval)
            if self._stop.is_set():
                break
            for path in self._collect_ready():
                try:
                    self._on_ready(path)
                except Exception as exc:
                    log.exception("on_ready callback failed for %s", path)
                    self._report(f"Scan dispatch failed for {Path(path).name}: {exc}")

    def _collect_ready(self) -> list[str]:
        """Return paths whose write has finished, pruning the rest."""
        now = time.time()
        ready: list[str] = []
        with self._lock:
            for path, pending in list(self._pending.items()):
                quiet_for = now - pending.last_event
                age = now - pending.first_seen

                if not os.path.exists(path):
                    self._pending.pop(path, None)
                    continue

                if age > self.max_settle_seconds:
                    self._pending.pop(path, None)
                    log.warning("Dropped %s: never settled after %.0fs", path, age)
                    self._report(
                        f"{Path(path).name} never finished writing; scan skipped"
                    )
                    continue

                if quiet_for < self.settle_seconds:
                    continue

                # Quiet long enough. Confirm the handle is actually free.
                if not is_file_unlocked(path):
                    continue

                try:
                    current = os.path.getsize(path)
                except OSError:
                    self._pending.pop(path, None)
                    continue
                if current != pending.size_at_last_event:
                    # Grew while we were checking: still being written.
                    pending.last_event = now
                    pending.size_at_last_event = current
                    continue

                self._pending.pop(path, None)
                if self._already_seen(path, now):
                    continue
                self._seen[path] = now
                ready.append(path)
        if len(self._seen) > self._seen_max:
            self._prune_seen(now)
        return ready

    def _already_seen(self, path: str, now: float) -> bool:
        """True if this path was dispatched recently enough to skip."""
        stamp = self._seen.get(path)
        if stamp is None:
            return False
        if now - stamp > self._seen_ttl:
            # Expired: allow a rescan of the same path (re-download, overwrite).
            self._seen.pop(path, None)
            return False
        return True

    def _prune_seen(self, now: float) -> None:
        """Drop expired entries, then the oldest if still over the cap."""
        expired = [p for p, t in self._seen.items() if now - t > self._seen_ttl]
        for path in expired:
            self._seen.pop(path, None)
        overflow = len(self._seen) - self._seen_max
        if overflow > 0:
            oldest = sorted(self._seen.items(), key=lambda kv: kv[1])[:overflow]
            for path, _ in oldest:
                self._seen.pop(path, None)

    def _report(self, message: str) -> None:
        if self._on_error is not None:
            try:
                self._on_error(message)
            except Exception:
                log.debug("on_error callback raised", exc_info=True)

    # -- introspection ----------------------------------------------------- #

    def pending_count(self) -> int:
        with self._lock:
            return len(self._pending)

    def pending_paths(self) -> list[str]:
        with self._lock:
            return sorted(self._pending)


# --------------------------------------------------------------------------- #
# Helpers
# --------------------------------------------------------------------------- #

def _is_candidate(path: str) -> bool:
    name = os.path.basename(path)
    if not name:
        return False
    lowered = name.lower()
    if lowered in IGNORED_NAMES:
        return False
    if lowered.startswith(IGNORED_PREFIXES):
        return False
    if os.path.splitext(lowered)[1] in IGNORED_SUFFIXES:
        return False
    try:
        return os.path.isfile(path)
    except OSError:
        return False


# Windows constants for the exclusive-share probe.
_GENERIC_READ = 0x80000000
_OPEN_EXISTING = 3
_FILE_ATTRIBUTE_NORMAL = 0x80
_ERROR_SHARING_VIOLATION = 32
_ERROR_LOCK_VIOLATION = 33
_ERROR_ACCESS_DENIED = 5


def is_file_unlocked(path: str) -> bool:
    """True when no other handle has the file open.

    Windows: request exclusive sharing (``dwShareMode = 0``) via
    ``CreateFileW``. If any other handle - a browser writing the download, an
    archiver, another scanner - has the file open, Windows refuses with
    ERROR_SHARING_VIOLATION. That is the definitive "still in use" signal, and
    it is far more reliable than trying to lock a byte range, which succeeds
    against a plain open handle.

    POSIX: try an exclusive advisory lock via ``fcntl`` when available.
    """
    if sys.platform == "win32":
        return _win_file_unlocked(path)

    try:
        import fcntl

        with open(path, "rb") as handle:
            try:
                fcntl.flock(handle.fileno(), fcntl.LOCK_EX | fcntl.LOCK_NB)
                fcntl.flock(handle.fileno(), fcntl.LOCK_UN)
                return True
            except OSError:
                return False
    except ImportError:
        # No locking primitive available: fall back to readability.
        try:
            with open(path, "rb"):
                return True
        except OSError:
            return False


def _win_file_unlocked(path: str) -> bool:
    """Exclusive-share open probe using the Win32 API."""
    import ctypes
    from ctypes import wintypes

    kernel32 = ctypes.WinDLL("kernel32", use_last_error=True)
    kernel32.CreateFileW.restype = wintypes.HANDLE
    kernel32.CreateFileW.argtypes = [
        wintypes.LPCWSTR,   # lpFileName
        wintypes.DWORD,     # dwDesiredAccess
        wintypes.DWORD,     # dwShareMode
        wintypes.LPVOID,    # lpSecurityAttributes
        wintypes.DWORD,     # dwCreationDisposition
        wintypes.DWORD,     # dwFlagsAndAttributes
        wintypes.HANDLE,    # hTemplateFile
    ]
    kernel32.CloseHandle.argtypes = [wintypes.HANDLE]

    invalid = wintypes.HANDLE(-1).value
    handle = kernel32.CreateFileW(
        str(path),
        _GENERIC_READ,
        0,                      # share mode 0 -> exclusive
        None,
        _OPEN_EXISTING,
        _FILE_ATTRIBUTE_NORMAL,
        None,
    )

    if handle == invalid or handle is None:
        error = ctypes.get_last_error()
        # Sharing/lock violation: another handle is open, keep waiting.
        # Access denied: we cannot read it either, so it is not scannable yet.
        if error in (_ERROR_SHARING_VIOLATION, _ERROR_LOCK_VIOLATION,
                     _ERROR_ACCESS_DENIED):
            return False
        # Any other failure (deleted mid-probe, path gone) - do not scan.
        return False

    kernel32.CloseHandle(handle)
    return True


def collect_files(target: str | Path, recursive: bool = True,
                  limit: int = 5000,
                  max_size_bytes: int = 0) -> list[str]:
    """Expand a file-or-folder path into a list of files to scan.

    Reparse points (junctions, symlinks) are skipped. Without that guard a
    junction inside the target - ``Downloads\\link -> C:\\Windows`` - makes
    ``rglob`` walk the entire system, which is both a huge time sink and a way
    to scan files the user never asked about.

    ``max_size_bytes`` of 0 means no cap.
    """
    path = Path(target)
    if path.is_file():
        if max_size_bytes and _size_of(path) > max_size_bytes:
            return []
        return [str(path)]
    if not path.is_dir():
        return []

    found: list[str] = []
    for entry in _walk(path, recursive):
        try:
            if not entry.is_file():
                continue
            if _is_ignored_scan_target(entry.name):
                continue
            if max_size_bytes and _size_of(entry) > max_size_bytes:
                continue
            found.append(str(entry))
            if len(found) >= limit:
                break
        except OSError:
            continue
    return found


def _walk(root: Path, recursive: bool):
    """Yield entries under ``root`` without descending into reparse points."""
    if not recursive:
        yield from root.glob("*")
        return

    stack = [root]
    while stack:
        current = stack.pop()
        try:
            entries = list(current.iterdir())
        except OSError:
            continue
        for entry in entries:
            try:
                if entry.is_symlink() or _is_reparse_point(entry):
                    continue
                if entry.is_dir():
                    stack.append(entry)
                else:
                    yield entry
            except OSError:
                continue


def _is_reparse_point(path: Path) -> bool:
    """True for NTFS junctions and other reparse points."""
    if sys.platform != "win32":
        return False
    try:
        st = path.lstat()
    except OSError:
        return True  # unreadable: treat as unsafe to descend
    attrs = getattr(st, "st_file_attributes", 0)
    reparse_flag = getattr(__import__("stat"), "FILE_ATTRIBUTE_REPARSE_POINT", 0x400)
    return bool(attrs & reparse_flag)


def _size_of(path: Path) -> int:
    try:
        return path.stat().st_size
    except OSError:
        return 0


def _is_ignored_scan_target(name: str) -> bool:
    lowered = name.lower()
    return lowered in IGNORED_NAMES or lowered.startswith(IGNORED_PREFIXES)
