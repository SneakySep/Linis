"""Verify quarantine: move, inert, restore, tamper-refusal, delete."""

import sys
import tempfile
import time
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from scanner.database import ScanDatabase
from scanner.engine import compute_sha256
from scanner.quarantine import (
    QUARANTINE_SUFFIX,
    FileAlreadyHandled,
    QuarantineError,
    QuarantineManager,
)

PASSED, FAILED = [], []


def check(name, ok, detail=""):
    (PASSED if ok else FAILED).append(name if ok else f"{name}: {detail}")
    print(f"  {'PASS' if ok else 'FAIL'}  {name}" + (f"  {detail}" if detail and not ok else ""))


def main() -> int:
    print("Quarantine verification")
    print("=" * 64)

    with tempfile.TemporaryDirectory(prefix="quar_verify_") as raw:
        tmp = Path(raw)
        store = tmp / "Quarantine"
        db = ScanDatabase(tmp / "quar.db")
        mgr = QuarantineManager(db, store)

        try:
            # -- quarantine a "malicious" file ---------------------------- #
            victim = tmp / "evil.exe"
            victim.write_bytes(b"MZ fake malware payload" * 100)
            original_hash = compute_sha256(victim)
            original_size = victim.stat().st_size

            rec = mgr.quarantine(
                victim, sha256=original_hash, verdict="Malicious",
                score=100, threat_detail="Trojan:Win32/Test",
            )
            check("quarantine returns a record", rec is not None)
            check("original file is gone from its location", not victim.exists())
            check("file exists in the quarantine store", Path(rec.quarantine_path).is_file())
            check("stored file uses the .quar extension",
                  rec.quarantine_path.endswith(QUARANTINE_SUFFIX),
                  rec.quarantine_path)
            check("record preserves the original path",
                  rec.original_path == str(victim.resolve()), rec.original_path)
            check("record preserves the hash", rec.sha256 == original_hash)
            check("record preserves the size", rec.file_size == original_size)
            check("record preserves the threat detail",
                  rec.threat_detail == "Trojan:Win32/Test")
            check("record status is quarantined", rec.status == "quarantined")

            stored = Path(rec.quarantine_path)
            check("stored bytes are unchanged",
                  compute_sha256(stored) == original_hash)
            check("stored file is read-only",
                  not (stored.stat().st_mode & 0o222), oct(stored.stat().st_mode))

            # -- listing --------------------------------------------------- #
            records = mgr.list_records()
            check("listing returns the record", len(records) == 1)
            check("listing reports the file exists", records[0].exists)
            stats = mgr.stats()
            check("stats count the quarantined file", stats["count"] == 1)
            check("stats report no missing files", stats["missing"] == 0)
            check("db stats include the quarantine count",
                  db.stats()["quarantined"] == 1)

            # -- hash lookup ----------------------------------------------- #
            check("a quarantined hash is reported as quarantined",
                  db.is_quarantined_hash(original_hash))
            check("an unknown hash is not reported as quarantined",
                  not db.is_quarantined_hash("0" * 64))

            # -- restore ---------------------------------------------------- #
            restored = mgr.restore(rec.id)
            check("restore puts the file back at the original path",
                  restored == victim, str(restored))
            check("restored file exists", victim.is_file())
            check("restored bytes match the original hash",
                  compute_sha256(victim) == original_hash)
            check("restored file is writable again",
                  bool(victim.stat().st_mode & 0o200))
            check("quarantine store is now empty of that file", not stored.exists())
            check("record status is restored",
                  mgr.db.get_quarantine(rec.id).status == "restored")
            check("restored hash is no longer reported as quarantined",
                  not db.is_quarantined_hash(original_hash))

            # -- restore refuses tampered bytes ---------------------------- #
            victim2 = tmp / "evil2.exe"
            victim2.write_bytes(b"second payload")
            hash2 = compute_sha256(victim2)
            rec2 = mgr.quarantine(victim2, sha256=hash2, threat_detail="Test2")

            # Tamper with the stored file, then try to restore it.
            stored2 = Path(rec2.quarantine_path)
            import os
            import stat as stat_mod
            os.chmod(stored2, stat_mod.S_IWRITE | stat_mod.S_IREAD)
            stored2.write_bytes(b"TAMPERED CONTENT")

            refused = False
            try:
                mgr.restore(rec2.id)
            except QuarantineError as exc:
                refused = "modified" in str(exc).lower()
            check("restore refuses a tampered quarantine file", refused)
            check("tampered file was not restored to disk", not victim2.exists())

            # -- delete ----------------------------------------------------- #
            mgr.delete(rec2.id, shred=True)
            check("delete removes the stored file", not stored2.exists())
            check("delete marks the record deleted",
                  mgr.db.get_quarantine(rec2.id).status == "deleted")

            # -- missing source --------------------------------------------- #
            gone = tmp / "already_gone.exe"
            handled = False
            try:
                mgr.quarantine(gone, sha256="a" * 64)
            except FileAlreadyHandled:
                handled = True
            check("quarantining a missing file raises FileAlreadyHandled", handled)

            # -- collision handling ----------------------------------------- #
            a = tmp / "dup_a.exe"
            b = tmp / "dup_b.exe"
            a.write_bytes(b"same bytes")
            b.write_bytes(b"same bytes")
            same_hash = compute_sha256(a)
            r_a = mgr.quarantine(a, sha256=same_hash)
            r_b = mgr.quarantine(b, sha256=same_hash)
            check("two files with the same hash get distinct store paths",
                  r_a.quarantine_path != r_b.quarantine_path,
                  f"{r_a.quarantine_path} vs {r_b.quarantine_path}")
            check("both collisions still exist in the store",
                  Path(r_a.quarantine_path).is_file()
                  and Path(r_b.quarantine_path).is_file())

            # -- restore avoids overwriting --------------------------------- #
            target = tmp / "occupied.exe"
            target.write_bytes(b"i was here first")
            dup_c = _make(tmp, "dup_c.exe")
            r_c = mgr.quarantine(dup_c, sha256=compute_sha256(dup_c))
            restored_c = mgr.restore(r_c.id, target=target)
            check("restore does not overwrite an existing file",
                  target.read_bytes() == b"i was here first")
            check("restore picks a free name instead",
                  restored_c != target and restored_c.is_file(),
                  str(restored_c))
        finally:
            db.close()

    print("\n" + "=" * 64)
    print(f"PASSED: {len(PASSED)}   FAILED: {len(FAILED)}")
    for f in FAILED:
        print(f"  - {f}")
    return 0 if not FAILED else 1


def _make(tmp: Path, name: str) -> Path:
    p = tmp / name
    p.write_bytes(b"payload " + name.encode())
    return p


if __name__ == "__main__":
    sys.exit(main())
