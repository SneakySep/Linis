"""Quarantine: move detected files somewhere they cannot be executed.

A scanner that finds malware and leaves it double-clickable on the desktop is a
report, not a defence. This module closes that gap.

Design
------
* The file is **moved** into ``%LOCALAPPDATA%\\HybridShield\\Quarantine``, which
  is ACL-locked to the current user.
* The extension is rewritten to ``.quar``, so Windows has no handler for it and
  a double-click cannot execute it. This is the single most effective step:
  even a restored-by-hand file is inert until it is renamed.
* The file is marked read-only, so casual tampering fails.
* The original path, hash, size, verdict and threat detail are recorded in
  SQLite before the move is considered complete.

Restore verifies the hash of the quarantined bytes against the hash recorded at
quarantine time. If they differ, the file is refused: something modified the
quarantine store, and restoring it would launder a different payload back onto
disk under a trusted name.

Failure handling
----------------
A file that Windows Defender has already quarantined cannot be opened at all
(``ERROR_VIRUS_INFECTED``), so it also cannot be moved. That is reported as a
distinct outcome rather than a generic error - the file is already handled, just
not by us.
"""

from __future__ import annotations

import logging
import os
import shutil
import stat
import sys
import time
from dataclasses import dataclass
from pathlib import Path

from .config import DATA_DIR
from .database import ScanDatabase

log = logging.getLogger(__name__)

QUARANTINE_DIR = DATA_DIR / "Quarantine"
QUARANTINE_SUFFIX = ".quar"


class QuarantineError(Exception):
    """Quarantine operation failed."""


class FileAlreadyHandled(QuarantineError):
    """The file is gone or blocked by antivirus before we could move it.

    Not a failure of ours: Defender got there first. Reported separately so the
    UI does not present it as an error.
    """


@dataclass
class QuarantineRecord:
    """One quarantined file."""

    id: int
    sha256: str
    original_path: str
    quarantine_path: str
    file_name: str
    file_size: int
    quarantined_at: float
    verdict: str
    score: int
    threat_detail: str
    restored_at: float | None
    status: str

    @property
    def quarantined_text(self) -> str:
        return time.strftime("%Y-%m-%d %H:%M:%S",
                             time.localtime(self.quarantined_at))

    @property
    def exists(self) -> bool:
        return Path(self.quarantine_path).is_file()


class QuarantineManager:
    """Moves detections out of harm's way and puts them back on request."""

    def __init__(self, database: ScanDatabase | None = None,
                 directory: Path | None = None) -> None:
        self._owns_db = database is None
        self.db = database or ScanDatabase()
        self.directory = Path(directory or QUARANTINE_DIR)
        self._ensure_directory()

    def close(self) -> None:
        if self._owns_db:
            self.db.close()

    def __enter__(self) -> "QuarantineManager":
        return self

    def __exit__(self, *exc_info: object) -> None:
        self.close()

    # -- setup ------------------------------------------------------------- #

    def _ensure_directory(self) -> None:
        self.directory.mkdir(parents=True, exist_ok=True)
        _harden_directory(self.directory)

    # -- quarantine -------------------------------------------------------- #

    def quarantine(
        self,
        path: str | Path,
        *,
        sha256: str = "",
        verdict: str = "Malicious",
        score: int = 100,
        threat_detail: str = "",
    ) -> QuarantineRecord:
        """Move a file into quarantine and record it.

        Raises :class:`FileAlreadyHandled` if the file vanished or antivirus
        blocked access, and :class:`QuarantineError` for anything else.
        """
        source = Path(path)

        if not source.exists():
            raise FileAlreadyHandled(
                f"{source.name} is no longer on disk (antivirus may have "
                "already removed it)"
            )

        try:
            size = source.stat().st_size
        except OSError as exc:
            raise FileAlreadyHandled(f"Cannot stat {source.name}: {exc}") from exc

        # Build a collision-free destination. The hash prefix keeps related
        # samples together and makes the store auditable by eye.
        stem = sha256[:16] if sha256 else f"{int(time.time() * 1000)}"
        destination = self.directory / f"{stem}{QUARANTINE_SUFFIX}"
        counter = 1
        while destination.exists():
            destination = self.directory / f"{stem}_{counter}{QUARANTINE_SUFFIX}"
            counter += 1

        # Record first, so a crash mid-move still leaves an audit trail.
        record_id = self.db.add_quarantine(
            sha256=sha256,
            original_path=str(source.resolve()),
            quarantine_path=str(destination),
            file_name=source.name,
            file_size=size,
            verdict=verdict,
            score=score,
            threat_detail=threat_detail,
        )

        try:
            self._move_into_store(source, destination)
        except FileAlreadyHandled:
            self.db.mark_quarantine_status(record_id, "failed")
            raise
        except Exception as exc:
            self.db.mark_quarantine_status(record_id, "failed")
            raise QuarantineError(f"Could not quarantine {source.name}: {exc}") from exc

        log.info("Quarantined %s -> %s", source, destination)
        record = self.db.get_quarantine(record_id)
        if record is None:
            raise QuarantineError("Quarantine record vanished after write")
        return record

    def _move_into_store(self, source: Path, destination: Path) -> None:
        """Move the file and make it inert."""
        try:
            shutil.move(str(source), str(destination))
        except PermissionError as exc:
            # Defender holding the file, or another process with an open handle.
            raise FileAlreadyHandled(
                f"{source.name} is locked by another process "
                f"(antivirus or an open handle): {exc}"
            ) from exc
        except OSError as exc:
            if getattr(exc, "winerror", None) in (32, 33, 225) or exc.errno in (13, 32, 33):
                raise FileAlreadyHandled(
                    f"{source.name} could not be moved: {exc}"
                ) from exc
            raise

        # Strip the executable bit and mark read-only. On Windows the rename to
        # .quar is what actually prevents execution; read-only stops casual
        # edits. On POSIX chmod removes the execute bit outright.
        try:
            os.chmod(destination, stat.S_IREAD)
        except OSError:
            log.debug("Could not set read-only on %s", destination, exc_info=True)

        _harden_file(destination)

    # -- restore ----------------------------------------------------------- #

    def restore(self, record_id: int, target: str | Path | None = None) -> Path:
        """Put a quarantined file back, verifying its hash first."""
        record = self.db.get_quarantine(record_id)
        if record is None:
            raise QuarantineError(f"No quarantine record with id {record_id}")
        if record.status != "quarantined":
            raise QuarantineError(
                f"Record {record_id} is '{record.status}', not quarantined"
            )

        stored = Path(record.quarantine_path)
        if not stored.is_file():
            raise QuarantineError(
                f"Quarantined file is missing from the store: {stored}"
            )

        # Integrity check: never restore bytes that are not the bytes we took.
        if record.sha256:
            from .engine import compute_sha256

            actual = compute_sha256(stored)
            if actual != record.sha256:
                raise QuarantineError(
                    "Quarantined file has been modified since it was stored "
                    f"(expected {record.sha256[:16]}..., found {actual[:16]}...). "
                    "Refusing to restore."
                )

        destination = Path(target) if target else Path(record.original_path)
        destination = self._free_destination(destination)
        destination.parent.mkdir(parents=True, exist_ok=True)

        try:
            shutil.move(str(stored), str(destination))
        except OSError as exc:
            raise QuarantineError(f"Could not restore {record.file_name}: {exc}") from exc

        # Clear read-only so the file is usable again.
        try:
            os.chmod(destination, stat.S_IWRITE | stat.S_IREAD)
        except OSError:
            log.debug("Could not clear read-only on %s", destination, exc_info=True)

        self.db.mark_quarantine_restored(record_id)
        log.info("Restored %s -> %s", stored, destination)
        return destination

    def _free_destination(self, desired: Path) -> Path:
        """Avoid overwriting an existing file at the restore target."""
        if not desired.exists():
            return desired
        stem, suffix = desired.stem, desired.suffix
        for counter in range(1, 1000):
            candidate = desired.with_name(f"{stem} (restored {counter}){suffix}")
            if not candidate.exists():
                return candidate
        raise QuarantineError(f"Could not find a free name next to {desired}")

    # -- delete ------------------------------------------------------------ #

    def delete(self, record_id: int, *, shred: bool = False) -> None:
        """Permanently remove a quarantined file.

        ``shred`` overwrites the bytes before unlinking. This is best-effort on
        SSDs (wear levelling means the original blocks may survive), so it is
        not presented as a guarantee.
        """
        record = self.db.get_quarantine(record_id)
        if record is None:
            raise QuarantineError(f"No quarantine record with id {record_id}")

        stored = Path(record.quarantine_path)
        if stored.is_file():
            if shred:
                _overwrite(stored)
            try:
                os.chmod(stored, stat.S_IWRITE | stat.S_IREAD)
            except OSError:
                pass
            try:
                stored.unlink()
            except OSError as exc:
                raise QuarantineError(f"Could not delete {stored}: {exc}") from exc

        self.db.mark_quarantine_status(record_id, "deleted")
        log.info("Deleted quarantined file %s", stored)

    # -- listing ----------------------------------------------------------- #

    def list_records(self, status: str = "quarantined") -> list[QuarantineRecord]:
        return self.db.list_quarantine(status=status)

    def stats(self) -> dict[str, object]:
        records = self.list_records()
        total_bytes = sum(r.file_size for r in records)
        return {
            "count": len(records),
            "total_bytes": total_bytes,
            "directory": str(self.directory),
            "missing": sum(1 for r in records if not r.exists),
        }


# --------------------------------------------------------------------------- #
# Hardening helpers
# --------------------------------------------------------------------------- #

def _harden_directory(path: Path) -> None:
    """Restrict a directory to the current user.

    Best-effort: if icacls is unavailable the directory still lives under the
    user's own profile, which is already user-scoped by default.
    """
    if sys.platform != "win32":
        try:
            path.chmod(0o700)
        except OSError:
            pass
        return

    import subprocess

    user = os.environ.get("USERNAME")
    if not user:
        return
    try:
        subprocess.run(
            ["icacls", str(path),
             "/inheritance:r",
             "/grant:r", f"{user}:(OI)(CI)F",
             "/remove:g", "Everyone", "Users", "Authenticated Users"],
            capture_output=True, timeout=20, check=False,
            creationflags=getattr(subprocess, "CREATE_NO_WINDOW", 0),
        )
    except (OSError, subprocess.SubprocessError):
        log.debug("Could not harden quarantine directory ACL", exc_info=True)


def _harden_file(path: Path) -> None:
    """Deny execute on a single quarantined file."""
    if sys.platform != "win32":
        return
    import subprocess

    user = os.environ.get("USERNAME")
    if not user:
        return
    try:
        subprocess.run(
            ["icacls", str(path), "/inheritance:r", "/grant:r", f"{user}:R"],
            capture_output=True, timeout=15, check=False,
            creationflags=getattr(subprocess, "CREATE_NO_WINDOW", 0),
        )
    except (OSError, subprocess.SubprocessError):
        log.debug("Could not harden quarantined file ACL", exc_info=True)


def _overwrite(path: Path, passes: int = 1) -> None:
    """Overwrite a file's contents before deletion (best effort)."""
    try:
        size = path.stat().st_size
    except OSError:
        return
    try:
        os.chmod(path, stat.S_IWRITE | stat.S_IREAD)
    except OSError:
        pass
    try:
        with open(path, "r+b") as handle:
            for _ in range(passes):
                handle.seek(0)
                remaining = size
                while remaining > 0:
                    chunk = min(1024 * 1024, remaining)
                    handle.write(b"\x00" * chunk)
                    remaining -= chunk
                handle.flush()
                os.fsync(handle.fileno())
    except OSError:
        log.debug("Could not overwrite %s", path, exc_info=True)
