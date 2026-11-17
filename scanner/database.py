"""SQLite persistence: the 24-hour hash cache and the scan history log.

Two tables:

* ``scan_cache``  - one row per SHA-256, holding the last verdict for that
  exact file content. This is what the engine reads first so a repeat scan of
  an already-known hash costs zero API quota.
* ``scan_log``    - append-only history of every scan event shown in the UI
  table, including cache hits, so the user can audit what was scanned when.

Connections are per-thread (``threading.local``) because scans run on a
QThreadPool and SQLite connections are not safe to share across threads.
WAL mode lets the UI read while workers write.
"""

from __future__ import annotations

import json
import sqlite3
import threading
import time
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

from .config import DB_PATH

SCHEMA = """
CREATE TABLE IF NOT EXISTS scan_cache (
    sha256          TEXT PRIMARY KEY,
    file_name       TEXT NOT NULL DEFAULT '',
    file_size       INTEGER NOT NULL DEFAULT 0,
    scanned_at      REAL NOT NULL,
    defender_status TEXT NOT NULL DEFAULT 'Unknown',
    amsi_status     TEXT NOT NULL DEFAULT 'Unknown',
    yara_status     TEXT NOT NULL DEFAULT 'Unknown',
    mb_status       TEXT NOT NULL DEFAULT 'Unknown',
    opswat_status   TEXT NOT NULL DEFAULT 'Unknown',
    verdict         TEXT NOT NULL DEFAULT 'Unknown',
    score           INTEGER NOT NULL DEFAULT 0,
    details         TEXT NOT NULL DEFAULT '{}'
);

CREATE INDEX IF NOT EXISTS idx_scan_cache_scanned_at
    ON scan_cache (scanned_at);

CREATE TABLE IF NOT EXISTS scan_log (
    id              INTEGER PRIMARY KEY AUTOINCREMENT,
    sha256          TEXT NOT NULL,
    file_path       TEXT NOT NULL DEFAULT '',
    file_name       TEXT NOT NULL DEFAULT '',
    file_size       INTEGER NOT NULL DEFAULT 0,
    scanned_at      REAL NOT NULL,
    defender_status TEXT NOT NULL DEFAULT 'Unknown',
    amsi_status     TEXT NOT NULL DEFAULT 'Unknown',
    yara_status     TEXT NOT NULL DEFAULT 'Unknown',
    mb_status       TEXT NOT NULL DEFAULT 'Unknown',
    opswat_status   TEXT NOT NULL DEFAULT 'Unknown',
    verdict         TEXT NOT NULL DEFAULT 'Unknown',
    score           INTEGER NOT NULL DEFAULT 0,
    source          TEXT NOT NULL DEFAULT 'manual',
    from_cache      INTEGER NOT NULL DEFAULT 0,
    details         TEXT NOT NULL DEFAULT '{}'
);

CREATE INDEX IF NOT EXISTS idx_scan_log_scanned_at
    ON scan_log (scanned_at DESC);

CREATE INDEX IF NOT EXISTS idx_scan_log_verdict
    ON scan_log (verdict);

CREATE TABLE IF NOT EXISTS quarantine (
    id              INTEGER PRIMARY KEY AUTOINCREMENT,
    sha256          TEXT NOT NULL DEFAULT '',
    original_path   TEXT NOT NULL,
    quarantine_path TEXT NOT NULL,
    file_name       TEXT NOT NULL DEFAULT '',
    file_size       INTEGER NOT NULL DEFAULT 0,
    quarantined_at  REAL NOT NULL,
    verdict         TEXT NOT NULL DEFAULT 'Malicious',
    score           INTEGER NOT NULL DEFAULT 100,
    threat_detail   TEXT NOT NULL DEFAULT '',
    restored_at     REAL,
    status          TEXT NOT NULL DEFAULT 'quarantined'
);

CREATE INDEX IF NOT EXISTS idx_quarantine_status
    ON quarantine (status, quarantined_at DESC);

CREATE INDEX IF NOT EXISTS idx_quarantine_sha
    ON quarantine (sha256);
"""


@dataclass
class CachedResult:
    """A cached verdict for one SHA-256."""

    sha256: str
    file_name: str
    file_size: int
    scanned_at: float
    defender_status: str
    mb_status: str
    opswat_status: str
    verdict: str
    score: int
    details: dict[str, Any] = field(default_factory=dict)
    amsi_status: str = "Unknown"
    yara_status: str = "Unknown"

    @property
    def age_seconds(self) -> float:
        return max(0.0, time.time() - self.scanned_at)


class ScanDatabase:
    """Thread-safe facade over the SQLite file."""

    def __init__(self, path: Path | str = DB_PATH) -> None:
        self._path = Path(path)
        self._local = threading.local()
        self._write_lock = threading.Lock()
        self._path.parent.mkdir(parents=True, exist_ok=True)
        self._init_schema()

    # -- connection handling ----------------------------------------------- #

    def _conn(self) -> sqlite3.Connection:
        conn = getattr(self._local, "conn", None)
        if conn is None:
            conn = sqlite3.connect(str(self._path), timeout=30.0)
            conn.row_factory = sqlite3.Row
            conn.execute("PRAGMA journal_mode=WAL")
            conn.execute("PRAGMA synchronous=NORMAL")
            conn.execute("PRAGMA busy_timeout=30000")
            self._local.conn = conn
        return conn

    def _init_schema(self) -> None:
        with self._write_lock:
            conn = self._conn()
            conn.executescript(SCHEMA)
            self._migrate(conn)
            conn.commit()

    @staticmethod
    def _migrate(conn: sqlite3.Connection) -> None:
        """Add columns introduced after a database was first created.

        ``CREATE TABLE IF NOT EXISTS`` silently does nothing on an existing
        database, so a new column has to be added explicitly or every query
        that names it fails on upgrade.
        """
        additions = {
            "scan_cache": ("yara_status", "TEXT NOT NULL DEFAULT 'Unknown'"),
            "scan_log": ("yara_status", "TEXT NOT NULL DEFAULT 'Unknown'"),
        }
        for table, (column, decl) in additions.items():
            existing = {
                row[1] for row in conn.execute(f"PRAGMA table_info({table})")
            }
            if column not in existing:
                conn.execute(f"ALTER TABLE {table} ADD COLUMN {column} {decl}")

    def close(self) -> None:
        conn = getattr(self._local, "conn", None)
        if conn is not None:
            try:
                conn.close()
            finally:
                self._local.conn = None

    # -- cache ------------------------------------------------------------- #

    def get_cached(self, sha256: str, ttl_hours: float = 24.0) -> CachedResult | None:
        """Return the cached result for ``sha256`` if it is younger than TTL."""
        cutoff = time.time() - (ttl_hours * 3600)
        row = self._conn().execute(
            "SELECT * FROM scan_cache WHERE sha256 = ? AND scanned_at >= ?",
            (sha256, cutoff),
        ).fetchone()
        if row is None:
            return None
        return _row_to_cached(row)

    def put_cached(self, result: CachedResult) -> None:
        with self._write_lock:
            conn = self._conn()
            conn.execute(
                """
                INSERT INTO scan_cache (
                    sha256, file_name, file_size, scanned_at, defender_status,
                    amsi_status, yara_status, mb_status, opswat_status, verdict,
                    score, details
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                ON CONFLICT(sha256) DO UPDATE SET
                    file_name       = excluded.file_name,
                    file_size       = excluded.file_size,
                    scanned_at      = excluded.scanned_at,
                    defender_status = excluded.defender_status,
                    amsi_status     = excluded.amsi_status,
                    yara_status     = excluded.yara_status,
                    mb_status       = excluded.mb_status,
                    opswat_status   = excluded.opswat_status,
                    verdict         = excluded.verdict,
                    score           = excluded.score,
                    details         = excluded.details
                """,
                (
                    result.sha256,
                    result.file_name,
                    result.file_size,
                    result.scanned_at,
                    result.defender_status,
                    result.amsi_status,
                    result.yara_status,
                    result.mb_status,
                    result.opswat_status,
                    result.verdict,
                    result.score,
                    json.dumps(result.details, ensure_ascii=False),
                ),
            )
            conn.commit()

    # -- history log ------------------------------------------------------- #

    def log_scan(
        self,
        *,
        sha256: str,
        file_path: str,
        file_name: str,
        file_size: int,
        defender_status: str,
        mb_status: str,
        opswat_status: str,
        verdict: str,
        score: int,
        source: str = "manual",
        from_cache: bool = False,
        details: dict[str, Any] | None = None,
        scanned_at: float | None = None,
        amsi_status: str = "Unknown",
        yara_status: str = "Unknown",
    ) -> int:
        with self._write_lock:
            conn = self._conn()
            cur = conn.execute(
                """
                INSERT INTO scan_log (
                    sha256, file_path, file_name, file_size, scanned_at,
                    defender_status, amsi_status, yara_status, mb_status,
                    opswat_status, verdict, score, source, from_cache, details
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    sha256,
                    file_path,
                    file_name,
                    file_size,
                    scanned_at if scanned_at is not None else time.time(),
                    defender_status,
                    amsi_status,
                    yara_status,
                    mb_status,
                    opswat_status,
                    verdict,
                    score,
                    source,
                    1 if from_cache else 0,
                    json.dumps(details or {}, ensure_ascii=False),
                ),
            )
            conn.commit()
            return int(cur.lastrowid or 0)

    def recent_scans(self, limit: int = 500) -> list[dict[str, Any]]:
        rows = self._conn().execute(
            "SELECT * FROM scan_log ORDER BY scanned_at DESC, id DESC LIMIT ?",
            (limit,),
        ).fetchall()
        return [_row_to_dict(r) for r in rows]

    def clear_history(self) -> None:
        with self._write_lock:
            conn = self._conn()
            conn.execute("DELETE FROM scan_log")
            conn.commit()

    def clear_cache(self) -> None:
        with self._write_lock:
            conn = self._conn()
            conn.execute("DELETE FROM scan_cache")
            conn.commit()

    # -- maintenance ------------------------------------------------------- #

    def purge_expired_cache(self, ttl_hours: float = 24.0) -> int:
        """Delete cache rows older than TTL. Returns rows removed."""
        cutoff = time.time() - (ttl_hours * 3600)
        with self._write_lock:
            conn = self._conn()
            cur = conn.execute("DELETE FROM scan_cache WHERE scanned_at < ?", (cutoff,))
            conn.commit()
            return cur.rowcount or 0

    def stats(self) -> dict[str, Any]:
        conn = self._conn()
        cache_rows = conn.execute("SELECT COUNT(*) FROM scan_cache").fetchone()[0]
        log_rows = conn.execute("SELECT COUNT(*) FROM scan_log").fetchone()[0]
        malicious = conn.execute(
            "SELECT COUNT(*) FROM scan_log WHERE verdict = 'Malicious'"
        ).fetchone()[0]
        quarantined = conn.execute(
            "SELECT COUNT(*) FROM quarantine WHERE status = 'quarantined'"
        ).fetchone()[0]
        return {
            "cache_entries": int(cache_rows),
            "log_entries": int(log_rows),
            "malicious_findings": int(malicious),
            "quarantined": int(quarantined),
            "db_path": str(self._path),
        }

    # -- quarantine -------------------------------------------------------- #

    def add_quarantine(
        self,
        *,
        sha256: str,
        original_path: str,
        quarantine_path: str,
        file_name: str,
        file_size: int,
        verdict: str = "Malicious",
        score: int = 100,
        threat_detail: str = "",
    ) -> int:
        """Insert a quarantine record and return its id."""
        with self._write_lock:
            conn = self._conn()
            cur = conn.execute(
                """
                INSERT INTO quarantine (
                    sha256, original_path, quarantine_path, file_name,
                    file_size, quarantined_at, verdict, score, threat_detail,
                    status
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, 'quarantined')
                """,
                (
                    sha256, original_path, quarantine_path, file_name,
                    file_size, time.time(), verdict, score, threat_detail,
                ),
            )
            conn.commit()
            return int(cur.lastrowid or 0)

    def get_quarantine(self, record_id: int):
        row = self._conn().execute(
            "SELECT * FROM quarantine WHERE id = ?", (record_id,)
        ).fetchone()
        return _row_to_quarantine(row) if row is not None else None

    def list_quarantine(self, status: str | None = "quarantined",
                        limit: int = 1000):
        conn = self._conn()
        if status is None:
            rows = conn.execute(
                "SELECT * FROM quarantine ORDER BY quarantined_at DESC LIMIT ?",
                (limit,),
            ).fetchall()
        else:
            rows = conn.execute(
                "SELECT * FROM quarantine WHERE status = ? "
                "ORDER BY quarantined_at DESC LIMIT ?",
                (status, limit),
            ).fetchall()
        return [_row_to_quarantine(r) for r in rows]

    def mark_quarantine_status(self, record_id: int, status: str) -> None:
        with self._write_lock:
            conn = self._conn()
            conn.execute(
                "UPDATE quarantine SET status = ? WHERE id = ?",
                (status, record_id),
            )
            conn.commit()

    def mark_quarantine_restored(self, record_id: int) -> None:
        with self._write_lock:
            conn = self._conn()
            conn.execute(
                "UPDATE quarantine SET status = 'restored', restored_at = ? "
                "WHERE id = ?",
                (time.time(), record_id),
            )
            conn.commit()

    def is_quarantined_hash(self, sha256: str) -> bool:
        """True when this hash is currently sitting in quarantine."""
        if not sha256:
            return False
        row = self._conn().execute(
            "SELECT 1 FROM quarantine WHERE sha256 = ? AND status = 'quarantined' "
            "LIMIT 1",
            (sha256,),
        ).fetchone()
        return row is not None


# --------------------------------------------------------------------------- #
# Row helpers
# --------------------------------------------------------------------------- #

def _row_to_dict(row: sqlite3.Row) -> dict[str, Any]:
    data = dict(row)
    raw_details = data.get("details")
    if isinstance(raw_details, str):
        try:
            data["details"] = json.loads(raw_details)
        except json.JSONDecodeError:
            data["details"] = {}
    return data


def _row_to_cached(row: sqlite3.Row) -> CachedResult:
    data = _row_to_dict(row)
    return CachedResult(
        sha256=data["sha256"],
        file_name=data.get("file_name", ""),
        file_size=int(data.get("file_size") or 0),
        scanned_at=float(data.get("scanned_at") or 0.0),
        defender_status=data.get("defender_status", "Unknown"),
        amsi_status=data.get("amsi_status", "Unknown"),
        yara_status=data.get("yara_status", "Unknown"),
        mb_status=data.get("mb_status", "Unknown"),
        opswat_status=data.get("opswat_status", "Unknown"),
        verdict=data.get("verdict", "Unknown"),
        score=int(data.get("score") or 0),
        details=data.get("details") or {},
    )


def _row_to_quarantine(row: sqlite3.Row):
    """Build a QuarantineRecord from a row.

    Imported lazily to avoid a circular import: scanner.quarantine imports
    scanner.database for the ScanDatabase type.
    """
    from .quarantine import QuarantineRecord

    data = dict(row)
    return QuarantineRecord(
        id=int(data["id"]),
        sha256=data.get("sha256", "") or "",
        original_path=data.get("original_path", "") or "",
        quarantine_path=data.get("quarantine_path", "") or "",
        file_name=data.get("file_name", "") or "",
        file_size=int(data.get("file_size") or 0),
        quarantined_at=float(data.get("quarantined_at") or 0.0),
        verdict=data.get("verdict", "Malicious") or "Malicious",
        score=int(data.get("score") or 0),
        threat_detail=data.get("threat_detail", "") or "",
        restored_at=data.get("restored_at"),
        status=data.get("status", "quarantined") or "quarantined",
    )
