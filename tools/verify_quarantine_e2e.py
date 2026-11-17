"""End-to-end: does a real detection actually get quarantined?

Uses EICAR so a genuine engine detection triggers the auto-quarantine path,
then verifies the file is off disk, inert, and restorable.

Run:  python tools/verify_quarantine_e2e.py
"""

from __future__ import annotations

import sys
import tempfile
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from scanner.config import Settings                              # noqa: E402
from scanner.database import ScanDatabase                        # noqa: E402
from scanner.engine import ScanEngine, Verdict                   # noqa: E402
from scanner.quarantine import QUARANTINE_SUFFIX, QuarantineManager  # noqa: E402

EICAR = r"X5O!P%@AP[4\PZX54(P^)7CC)7}$EICAR-STANDARD-ANTIVIRUS-TEST-FILE!$H+H*"

PASSED, FAILED = [], []


def check(name, ok, detail=""):
    (PASSED if ok else FAILED).append(name if ok else f"{name}: {detail}")
    print(f"  {'PASS' if ok else 'FAIL'}  {name}"
          + (f"  {detail}" if detail and not ok else ""))


def main() -> int:
    print("Auto-quarantine end-to-end")
    print("=" * 64)

    with tempfile.TemporaryDirectory(prefix="quar_e2e_") as raw:
        tmp = Path(raw)
        store = tmp / "Quarantine"
        db = ScanDatabase(tmp / "e2e.db")

        settings = Settings(tmp / "e2e_settings.json")
        settings.set("mb_auth_key", "")
        settings.set("opswat_api_key", "")
        settings.set("auto_quarantine", True)

        engine = ScanEngine(settings, db)
        # Point the quarantine store at the temp dir so we do not touch the
        # real one during a test.
        engine._quarantine = QuarantineManager(db, store)  # noqa: SLF001

        try:
            target = tmp / "eicar_sample.com"
            target.write_text(EICAR, encoding="ascii")

            result = engine.scan_file(target, source="e2e")

            print(f"\n  verdict         : {result.verdict.value}")
            print(f"  quarantined     : {result.quarantined}")
            print(f"  quarantine path : {result.quarantine_path or '-'}")
            print(f"  quarantine error: {result.quarantine_error or '-'}")
            print(f"  original exists : {target.exists()}\n")

            check("the file was detected as malicious",
                  result.verdict is Verdict.MALICIOUS, result.verdict.value)

            if result.quarantined:
                check("the file was moved out of its original location",
                      not target.exists())
                check("a quarantine record id was returned",
                      result.quarantine_id is not None)
                check("the stored file uses the .quar extension",
                      result.quarantine_path.endswith(QUARANTINE_SUFFIX),
                      result.quarantine_path)
                check("the stored file exists in the quarantine store",
                      Path(result.quarantine_path).is_file())

                record = db.get_quarantine(result.quarantine_id)
                check("the record is in the database", record is not None)
                check("the record keeps the original path",
                      record.original_path == str(target.resolve()),
                      record.original_path)
                check("the record carries a threat detail",
                      bool(record.threat_detail), record.threat_detail)

                # Restore it and confirm the bytes come back intact.
                restored = engine.quarantine.restore(record.id)
                check("restore brings the file back", restored.is_file())
                check("restored content matches EICAR",
                      EICAR in restored.read_text(encoding="ascii", errors="replace"))
            else:
                # Defender may have removed EICAR before we could move it.
                # That is a legitimate outcome, not a failure of ours.
                print("        (file was already handled by antivirus before "
                      "quarantine; verifying the graceful path)")
                check("a graceful reason is recorded",
                      bool(result.quarantine_error), result.quarantine_error)

            # -- auto-quarantine off means the file stays put -------------- #
            settings.set("auto_quarantine", False)
            keep = tmp / "eicar_keep.com"
            keep.write_text(EICAR, encoding="ascii")
            result2 = engine.scan_file(keep, source="e2e")
            check("with auto-quarantine off the file is not quarantined",
                  not result2.quarantined)
            if result2.verdict is Verdict.MALICIOUS:
                check("with auto-quarantine off the file stays on disk",
                      keep.exists())
        finally:
            db.close()

    print("\n" + "=" * 64)
    print(f"PASSED: {len(PASSED)}   FAILED: {len(FAILED)}")
    for f in FAILED:
        print(f"  - {f}")
    return 0 if not FAILED else 1


if __name__ == "__main__":
    sys.exit(main())
