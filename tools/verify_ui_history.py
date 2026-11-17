"""Verify the UI history path and the schema migration.

Two things this proves that the smoke test does not:

  1. ``_load_history`` populates the table without an IndexError. The old code
     built 9 values and indexed ``values[COL_VERDICT]`` (== 9), so any history
     at all crashed startup.
  2. A database created by the previous schema gains the ``yara_status`` column
     on open, instead of every query naming it failing.

Run:  python tools\\verify_ui_history.py
"""

from __future__ import annotations

import os
import sqlite3
import sys
import tempfile
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

os.environ.setdefault("QT_QPA_PLATFORM", "offscreen")

PASS = 0
FAIL = 0


def check(label: str, condition: bool, detail: str = "") -> None:
    global PASS, FAIL
    if condition:
        PASS += 1
        print(f"  PASS  {label}")
    else:
        FAIL += 1
        print(f"  FAIL  {label}" + (f"\n        {detail}" if detail else ""))


# --------------------------------------------------------------------------- #
# 1. Migration of a pre-YARA database
# --------------------------------------------------------------------------- #

print("\nSchema migration")
tmp = Path(tempfile.mkdtemp(prefix="hs_mig_"))
legacy = tmp / "legacy.db"

# Build a database with exactly the old schema (no yara_status anywhere).
old_schema = """
CREATE TABLE scan_cache (
    sha256 TEXT PRIMARY KEY, file_name TEXT NOT NULL DEFAULT '',
    file_size INTEGER NOT NULL DEFAULT 0, scanned_at REAL NOT NULL,
    defender_status TEXT NOT NULL DEFAULT 'Unknown',
    amsi_status TEXT NOT NULL DEFAULT 'Unknown',
    mb_status TEXT NOT NULL DEFAULT 'Unknown',
    opswat_status TEXT NOT NULL DEFAULT 'Unknown',
    verdict TEXT NOT NULL DEFAULT 'Unknown',
    score INTEGER NOT NULL DEFAULT 0,
    details TEXT NOT NULL DEFAULT '{}'
);
CREATE TABLE scan_log (
    id INTEGER PRIMARY KEY AUTOINCREMENT, sha256 TEXT NOT NULL,
    file_path TEXT NOT NULL DEFAULT '', file_name TEXT NOT NULL DEFAULT '',
    file_size INTEGER NOT NULL DEFAULT 0, scanned_at REAL NOT NULL,
    defender_status TEXT NOT NULL DEFAULT 'Unknown',
    amsi_status TEXT NOT NULL DEFAULT 'Unknown',
    mb_status TEXT NOT NULL DEFAULT 'Unknown',
    opswat_status TEXT NOT NULL DEFAULT 'Unknown',
    verdict TEXT NOT NULL DEFAULT 'Unknown',
    score INTEGER NOT NULL DEFAULT 0, source TEXT NOT NULL DEFAULT 'manual',
    from_cache INTEGER NOT NULL DEFAULT 0, details TEXT NOT NULL DEFAULT '{}'
);
"""
conn = sqlite3.connect(str(legacy))
conn.executescript(old_schema)
conn.execute(
    "INSERT INTO scan_log (sha256, file_path, file_name, file_size, scanned_at,"
    " defender_status, amsi_status, mb_status, opswat_status, verdict, score)"
    " VALUES ('abc', 'C:/x.txt', 'x.txt', 10, 1.0, 'Clean', 'Clean',"
    " 'Skipped', 'Skipped', 'Clean', 0)"
)
conn.commit()
conn.close()

from scanner.database import ScanDatabase  # noqa: E402

db = ScanDatabase(legacy)
cols_cache = {r[1] for r in db._conn().execute("PRAGMA table_info(scan_cache)")}
cols_log = {r[1] for r in db._conn().execute("PRAGMA table_info(scan_log)")}
check("scan_cache gains yara_status", "yara_status" in cols_cache, str(cols_cache))
check("scan_log gains yara_status", "yara_status" in cols_log, str(cols_log))

rows = db.recent_scans(limit=10)
check("legacy row still readable", len(rows) == 1, f"got {len(rows)}")
check("legacy row defaults yara_status",
      rows and rows[0].get("yara_status") == "Unknown",
      str(rows[0].get("yara_status")) if rows else "no row")

# Re-opening must be idempotent (no duplicate-column error).
try:
    ScanDatabase(legacy)
    check("migration is idempotent", True)
except Exception as exc:
    check("migration is idempotent", False, f"{type(exc).__name__}: {exc}")


# --------------------------------------------------------------------------- #
# 2. The history table renders
# --------------------------------------------------------------------------- #

print("\nHistory table rendering")
try:
    from PySide6.QtWidgets import QApplication  # noqa: E402

    from scanner.config import Settings  # noqa: E402
    from ui.main_window import COL_VERDICT, COLUMNS, MainWindow  # noqa: E402

    app = QApplication.instance() or QApplication([])

    # Point the window at a database that has history in it.
    import scanner.database as dbmod

    history_db = tmp / "history.db"
    seed = ScanDatabase(history_db)
    seed.log_scan(
        sha256="deadbeef", file_path="C:/Downloads/a.txt", file_name="a.txt",
        file_size=42, defender_status="Clean", mb_status="Skipped",
        opswat_status="Skipped", verdict="Clean", score=0,
        amsi_status="Clean", yara_status="Clean",
    )
    seed.log_scan(
        sha256="cafebabe", file_path="C:/Downloads/b.txt", file_name="b.txt",
        file_size=99, defender_status="Clean", mb_status="Skipped",
        opswat_status="Skipped", verdict="Malicious", score=100,
        amsi_status="Clean", yara_status="Malicious",
    )

    original = dbmod.ScanDatabase
    dbmod.ScanDatabase = lambda *a, **k: original(history_db)
    # ui.main_window imported ScanDatabase by name, so the module attribute on
    # scanner.database is not the reference it calls. Patch the one it uses.
    import ui.main_window as mw
    original_ui = mw.ScanDatabase
    mw.ScanDatabase = lambda *a, **k: original(history_db)
    try:
        window = MainWindow(Settings(tmp / "ui_settings.json"))
        table = window.table
        check("table has one column per COLUMNS entry",
              table.columnCount() == len(COLUMNS),
              f"{table.columnCount()} vs {len(COLUMNS)}")
        check("history rows loaded", table.rowCount() == 2,
              f"got {table.rowCount()}")
        if table.rowCount() == 2:
            verdict_cell = table.item(0, COL_VERDICT)
            check("verdict cell populated", verdict_cell is not None)
            check("verdict cell holds a real verdict",
                  verdict_cell is not None
                  and verdict_cell.text() in {"Clean", "Malicious"},
                  verdict_cell.text() if verdict_cell else "none")
            yara_cell = table.item(0, 5)
            check("YARA column populated",
                  yara_cell is not None and yara_cell.text() in {"Clean", "Malicious"},
                  yara_cell.text() if yara_cell else "none")
        window.close()
    finally:
        dbmod.ScanDatabase = original
        mw.ScanDatabase = original_ui
except Exception as exc:
    import traceback
    traceback.print_exc()
    check("history table renders", False, f"{type(exc).__name__}: {exc}")


print("\n" + "=" * 60)
print(f"PASSED: {PASS}   FAILED: {FAIL}")
print("=" * 60)
sys.exit(0 if FAIL == 0 else 1)
