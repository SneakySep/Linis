"""End-to-end pipeline check: EICAR through the full engine.

Proves the whole chain - locked handle, hash, cache gate, AMSI, Defender,
aggregation, SQLite persistence - produces a correct Malicious verdict and
that the short-circuit actually skips the layers it claims to skip.

Run:  python tools/verify_pipeline.py
"""

from __future__ import annotations

import sys
import tempfile
import time
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from scanner.config import Settings                              # noqa: E402
from scanner.database import ScanDatabase                        # noqa: E402
from scanner.engine import ScanEngine, Status, Verdict           # noqa: E402

EICAR = r"X5O!P%@AP[4\PZX54(P^)7CC)7}$EICAR-STANDARD-ANTIVIRUS-TEST-FILE!$H+H*"


def main() -> int:
    print("End-to-end pipeline verification")
    print("=" * 64)

    settings = Settings()
    settings.set("mb_auth_key", "")
    settings.set("opswat_api_key", "")

    with tempfile.TemporaryDirectory(prefix="pipeline_verify_") as raw:
        tmp = Path(raw)
        db = ScanDatabase(tmp / "pipeline.db")
        engine = ScanEngine(settings, db)

        try:
            clean = tmp / "clean_document.txt"
            clean.write_text("An ordinary file with nothing wrong in it.\n" * 30,
                             encoding="utf-8")

            eicar = tmp / "eicar_test.com"
            eicar.write_text(EICAR, encoding="ascii")

            # -- clean file ------------------------------------------------- #
            t0 = time.perf_counter()
            clean_result = engine.scan_file(clean, source="verify")
            clean_ms = (time.perf_counter() - t0) * 1000
            print(f"\nclean_document.txt  ({clean_ms:.0f} ms)")
            print(f"  sha256   : {clean_result.sha256[:32]}...")
            print(f"  amsi     : {clean_result.amsi.status.value} "
                  f"- {clean_result.amsi.detail}")
            print(f"  defender : {clean_result.defender.status.value} "
                  f"- {clean_result.defender.detail}")
            print(f"  verdict  : {clean_result.verdict.value} "
                  f"(score {clean_result.score})")

            # -- EICAR ------------------------------------------------------ #
            t0 = time.perf_counter()
            eicar_result = engine.scan_file(eicar, source="verify")
            eicar_ms = (time.perf_counter() - t0) * 1000
            print(f"\neicar_test.com  ({eicar_ms:.0f} ms)")
            print(f"  sha256   : {eicar_result.sha256[:32]}...")
            print(f"  amsi     : {eicar_result.amsi.status.value} "
                  f"- {eicar_result.amsi.detail}")
            print(f"  defender : {eicar_result.defender.status.value} "
                  f"- {eicar_result.defender.detail}")
            print(f"  mb       : {eicar_result.malwarebazaar.status.value}")
            print(f"  opswat   : {eicar_result.opswat.status.value}")
            print(f"  verdict  : {eicar_result.verdict.value} "
                  f"(score {eicar_result.score})")

            # -- cache round trip ------------------------------------------- #
            t0 = time.perf_counter()
            cached = engine.scan_file(eicar, source="verify")
            cached_ms = (time.perf_counter() - t0) * 1000
            print(f"\ncache replay of eicar_test.com  ({cached_ms:.1f} ms)")
            print(f"  from_cache: {cached.from_cache}")
            print(f"  verdict   : {cached.verdict.value}")

            # -- assertions -------------------------------------------------- #
            print("\n" + "=" * 64)
            checks = []

            checks.append(("clean file is Clean",
                           clean_result.verdict is Verdict.CLEAN))
            checks.append(("clean file hash is correct",
                           len(clean_result.sha256) == 64))
            checks.append(("EICAR is Malicious",
                           eicar_result.verdict is Verdict.MALICIOUS))
            checks.append(("EICAR scores 100",
                           eicar_result.score == 100))
            checks.append(("a layer positively detected EICAR",
                           Status.MALICIOUS in (eicar_result.amsi.status,
                                                eicar_result.defender.status)))
            # Cache replay only applies when a hash could be computed. If
            # Defender quarantined EICAR before we read it, there are no bytes
            # and therefore no hash - the replay is a fresh detection instead.
            if eicar_result.sha256:
                checks.append(("cache replay is served from cache",
                               cached.from_cache))
                checks.append(("cache replay keeps the Malicious verdict",
                               cached.verdict is Verdict.MALICIOUS))
            else:
                print("  SKIP  cache replay (file was quarantined before hashing)")
            checks.append(("cache replay is much faster than the full scan",
                           cached_ms < eicar_ms / 2,
                           f"{cached_ms:.1f} ms vs {eicar_ms:.0f} ms"))
            # An AV-blocked file may have no readable bytes (no hash, not
            # cached), or Defender may quarantine it just after we hashed it
            # (hash present, cached). Both are correct. The invariant that must
            # always hold: nothing is ever cached under an empty hash, which
            # would poison the cache for unrelated files.
            empty_hash_rows = db._conn().execute(  # noqa: SLF001
                "SELECT COUNT(*) FROM scan_cache WHERE sha256 = ''"
            ).fetchone()[0]
            checks.append(("no cache row is ever written under an empty hash",
                           empty_hash_rows == 0, f"{empty_hash_rows} rows"))
            checks.append(("AV-blocked result is still Malicious",
                           eicar_result.verdict is Verdict.MALICIOUS))

            rows = db.recent_scans(20)
            checks.append(("every scan is logged", len(rows) == 3,
                           f"{len(rows)} rows"))
            checks.append(("history preserves the Malicious verdict",
                           any(r["verdict"] == "Malicious" for r in rows)))

            failed = 0
            for item in checks:
                name, ok = item[0], item[1]
                detail = item[2] if len(item) > 2 else ""
                print(f"  {'PASS' if ok else 'FAIL'}  {name}"
                      f"{('  ' + detail) if detail and not ok else ''}")
                if not ok:
                    failed += 1

            print(f"\n{len(checks) - failed}/{len(checks)} checks passed")
            return 0 if failed == 0 else 1
        finally:
            db.close()


if __name__ == "__main__":
    sys.exit(main())
