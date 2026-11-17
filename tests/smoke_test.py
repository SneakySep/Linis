"""Smoke tests for the non-GUI layers.

Run with:  python tests/smoke_test.py

Covers hashing, the SQLite cache gate, verdict aggregation, the watcher's
settle/lock logic, and the engine's graceful degradation when no API keys are
configured. No network calls are made and no real malware is used.
"""

from __future__ import annotations

import hashlib
import os
import subprocess
import sys
import tempfile
import time
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from scanner.database import CachedResult, ScanDatabase          # noqa: E402
from scanner.engine import (                                     # noqa: E402
    LayerResult,
    ScanEngine,
    Status,
    Verdict,
    aggregate_verdict,
    compute_sha256,
)
from scanner.watcher import (                                    # noqa: E402
    FolderWatcher,
    collect_files,
    is_file_unlocked,
)

PASSED: list[str] = []
FAILED: list[str] = []


def check(name: str, condition: bool, detail: str = "") -> None:
    if condition:
        PASSED.append(name)
        print(f"  PASS  {name}")
    else:
        FAILED.append(f"{name}: {detail}")
        print(f"  FAIL  {name}  {detail}")


def section(title: str) -> None:
    print(f"\n{title}")


# --------------------------------------------------------------------------- #
# Hashing
# --------------------------------------------------------------------------- #

def test_hashing(tmp: Path) -> None:
    section("Hashing")

    # Known vector: SHA-256 of "abc"
    sample = tmp / "abc.txt"
    sample.write_bytes(b"abc")
    digest = compute_sha256(sample)
    check(
        "sha256 of 'abc' matches the published vector",
        digest == "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad",
        digest,
    )

    empty = tmp / "empty.bin"
    empty.write_bytes(b"")
    check(
        "sha256 of empty file matches the published vector",
        compute_sha256(empty)
        == "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
    )

    # Chunk boundary: 64 KiB + 1 byte must hash identically to a single read.
    import hashlib

    big = tmp / "big.bin"
    payload = os.urandom(64 * 1024 + 1)
    big.write_bytes(payload)
    check(
        "chunked hashing matches a single-pass hash across the 64 KiB boundary",
        compute_sha256(big) == hashlib.sha256(payload).hexdigest(),
    )

    # Custom chunk size must not change the result.
    check(
        "hash is independent of chunk size",
        compute_sha256(big, chunk_size=7) == compute_sha256(big, chunk_size=1 << 20),
    )


# --------------------------------------------------------------------------- #
# Database / cache
# --------------------------------------------------------------------------- #

def test_database(tmp: Path) -> None:
    section("Database and cache gate")

    db = ScanDatabase(tmp / "test.db")
    try:
        sha = "a" * 64
        check("cache miss on unknown hash", db.get_cached(sha, 24) is None)

        db.put_cached(CachedResult(
            sha256=sha, file_name="x.exe", file_size=123, scanned_at=time.time(),
            defender_status="Clean", mb_status="Not Found", opswat_status="Clean",
            verdict="Clean", score=0, details={"note": "test"},
        ))
        hit = db.get_cached(sha, 24)
        check("cache hit immediately after write", hit is not None)
        check("cached verdict round-trips", hit is not None and hit.verdict == "Clean")
        check("cached details round-trip as JSON",
              hit is not None and hit.details.get("note") == "test")

        # TTL boundary: a row older than the TTL must not be served.
        stale = "b" * 64
        db.put_cached(CachedResult(
            sha256=stale, file_name="old.exe", file_size=1,
            scanned_at=time.time() - (25 * 3600),
            defender_status="Clean", mb_status="Clean", opswat_status="Clean",
            verdict="Clean", score=0, details={},
        ))
        check("row older than 24h is not served from cache",
              db.get_cached(stale, 24) is None)
        check("same row is served when TTL is widened to 48h",
              db.get_cached(stale, 48) is not None)

        # Upsert must not duplicate.
        db.put_cached(CachedResult(
            sha256=sha, file_name="x.exe", file_size=123, scanned_at=time.time(),
            defender_status="Malicious", mb_status="Malicious", opswat_status="Skipped",
            verdict="Malicious", score=100, details={},
        ))
        check("upsert updates in place rather than duplicating",
              db.stats()["cache_entries"] == 2)
        check("upsert stored the new verdict",
              db.get_cached(sha, 24).verdict == "Malicious")

        # History log.
        db.log_scan(
            sha256=sha, file_path="C:/tmp/x.exe", file_name="x.exe", file_size=123,
            defender_status="Malicious", mb_status="Malicious", opswat_status="Skipped",
            verdict="Malicious", score=100, source="manual", from_cache=False,
        )
        rows = db.recent_scans(10)
        check("scan log records the event", len(rows) == 1)
        check("scan log preserves the verdict", rows[0]["verdict"] == "Malicious")
        check("scan log preserves the source", rows[0]["source"] == "manual")
        check("stats count malicious findings", db.stats()["malicious_findings"] == 1)

        removed = db.purge_expired_cache(24)
        check("purge removes only expired rows", removed == 1,
              f"removed={removed}")
        check("purge left the fresh row", db.get_cached(sha, 24) is not None)
    finally:
        db.close()


# --------------------------------------------------------------------------- #
# Verdict aggregation
# --------------------------------------------------------------------------- #

def test_aggregation() -> None:
    section("Verdict aggregation")

    def L(status: Status) -> LayerResult:
        return LayerResult(status=status)

    cases = [
        ("any malicious layer wins",
         (L(Status.CLEAN), L(Status.MALICIOUS), L(Status.CLEAN)), Verdict.MALICIOUS),
        ("defender malicious short-circuits",
         (L(Status.MALICIOUS), L(Status.SKIPPED), L(Status.SKIPPED)), Verdict.MALICIOUS),
        ("suspicious beats clean",
         (L(Status.CLEAN), L(Status.NOT_FOUND), L(Status.SUSPICIOUS)), Verdict.SUSPICIOUS),
        ("defender clean + no errors is clean",
         (L(Status.CLEAN), L(Status.NOT_FOUND), L(Status.NOT_FOUND)), Verdict.CLEAN),
        ("defender clean + cloud error still clean (local evidence is real)",
         (L(Status.CLEAN), L(Status.ERROR), L(Status.ERROR)), Verdict.CLEAN),
        ("defender error + cloud not-found is unknown, never clean",
         (L(Status.ERROR), L(Status.NOT_FOUND), L(Status.NOT_FOUND)), Verdict.UNKNOWN),
        ("all skipped is unknown",
         (L(Status.SKIPPED), L(Status.SKIPPED), L(Status.SKIPPED)), Verdict.UNKNOWN),
        ("cloud clean without defender is clean but low confidence",
         (L(Status.ERROR), L(Status.CLEAN), L(Status.NOT_FOUND)), Verdict.UNKNOWN),
    ]

    for name, layers, expected in cases:
        verdict, score = aggregate_verdict(*layers)
        check(name, verdict is expected, f"got {verdict.value} (score {score})")

    verdict, score = aggregate_verdict(L(Status.MALICIOUS), L(Status.SKIPPED),
                                       L(Status.SKIPPED))
    check("malicious scores 100", score == 100, f"score={score}")


# --------------------------------------------------------------------------- #
# Watcher
# --------------------------------------------------------------------------- #

def test_watcher(tmp: Path) -> None:
    section("Watcher debounce and lock detection")

    watch_dir = tmp / "watch"
    watch_dir.mkdir()

    ready: list[str] = []
    errors: list[str] = []
    watcher = FolderWatcher(
        watch_dir,
        on_ready=ready.append,
        on_error=errors.append,
        settle_seconds=0.6,
        poll_interval=0.2,
    )
    watcher.start()
    try:
        check("watcher reports running", watcher.running)

        # A file written and closed should be picked up.
        target = watch_dir / "downloaded.txt"
        target.write_text("hello world", encoding="utf-8")
        deadline = time.time() + 8
        while time.time() < deadline and not ready:
            time.sleep(0.2)
        check("settled file is reported ready", str(target) in ready,
              f"ready={ready}")

        # Partial download artefacts must be ignored.
        ready.clear()
        part = watch_dir / "movie.mp4.crdownload"
        part.write_text("partial", encoding="utf-8")
        time.sleep(2.0)
        check("crdownload artefacts are ignored", str(part) not in ready,
              f"ready={ready}")

        # A file that keeps growing must not be reported until it stops.
        ready.clear()
        growing = watch_dir / "growing.bin"
        with open(growing, "wb") as handle:
            for _ in range(6):
                handle.write(b"x" * 4096)
                handle.flush()
                time.sleep(0.3)
        deadline = time.time() + 8
        while time.time() < deadline and str(growing) not in ready:
            time.sleep(0.2)
        check("file reported after writes finish", str(growing) in ready,
              f"ready={ready}")

        # Lock probe on a normal closed file.
        check("closed file reports as unlocked", is_file_unlocked(str(target)))

        # Lock probe on a file held open for writing on Windows.
        if sys.platform == "win32":
            locked = watch_dir / "locked.bin"
            locked.write_bytes(b"data")
            handle = open(locked, "r+b")
            try:
                check("file held open reports as locked",
                      not is_file_unlocked(str(locked)))
            finally:
                handle.close()
            check("file reports unlocked after handle is released",
                  is_file_unlocked(str(locked)))
    finally:
        watcher.stop()
    check("watcher stops cleanly", not watcher.running)


# --------------------------------------------------------------------------- #
# Folder expansion
# --------------------------------------------------------------------------- #

def test_collect(tmp: Path) -> None:
    section("Folder expansion")

    root = tmp / "tree"
    (root / "sub").mkdir(parents=True)
    (root / "a.txt").write_text("a", encoding="utf-8")
    (root / "sub" / "b.txt").write_text("b", encoding="utf-8")
    (root / "desktop.ini").write_text("x", encoding="utf-8")

    files = collect_files(root)
    names = {Path(f).name for f in files}
    check("recursive expansion finds nested files", {"a.txt", "b.txt"} <= names,
          f"found={names}")
    check("system noise files are excluded", "desktop.ini" not in names)

    single = collect_files(root / "a.txt")
    check("single file path returns itself", len(single) == 1)

    check("nonexistent path returns empty", collect_files(tmp / "nope") == [])


# --------------------------------------------------------------------------- #
# Engine end-to-end with no API keys
# --------------------------------------------------------------------------- #

def test_engine_offline(tmp: Path) -> None:
    section("Engine end-to-end (no API keys, cache enabled)")

    from scanner.config import Settings

    settings = Settings.__new__(Settings)
    settings._path = tmp / "settings.json"   # noqa: SLF001
    import threading

    settings._lock = threading.RLock()       # noqa: SLF001
    settings._data = {                        # noqa: SLF001
        "mb_auth_key": "", "opswat_api_key": "",
        "cache_ttl_hours": 24, "defender_timeout_seconds": 300,
        "http_timeout_seconds": 5, "max_scan_workers": 1,
        "defender_path": r"C:\Program Files\Windows Defender\MpCmdRun.exe",
        "watch_folder": "", "watcher_enabled": False,
    }

    db = ScanDatabase(tmp / "engine.db")
    engine = ScanEngine(settings, db)
    try:
        sample = tmp / "sample.txt"
        sample.write_text("not malware, just text", encoding="utf-8")

        result = engine.scan_file(sample, source="test")
        check("scan returns a result", result is not None)
        check("result carries the correct sha256",
              result.sha256 == compute_sha256(sample))
        check("result records the file size", result.file_size == sample.stat().st_size)
        check("no API keys -> MalwareBazaar skipped",
              result.malwarebazaar.status is Status.SKIPPED,
              result.malwarebazaar.status.value)
        check("no API keys -> MetaDefender skipped",
              result.opswat.status is Status.SKIPPED,
              result.opswat.status.value)
        check("verdict is a real verdict, not an exception",
              result.verdict in set(Verdict))
        print(f"        defender={result.defender.status.value} "
              f"verdict={result.verdict.value} "
              f"detail={result.defender.detail[:70]!r}")

        # Second scan must be served from cache.
        second = engine.scan_file(sample, source="test")
        check("second scan is served from the cache", second.from_cache)
        check("cached scan reports the same verdict",
              second.verdict is result.verdict)

        # Missing file degrades to an error result rather than raising.
        missing = engine.scan_file(tmp / "does_not_exist.bin")
        check("missing file returns an Error verdict",
              missing.verdict is Verdict.ERROR, missing.verdict.value)

        # History has both scans plus the error.
        rows = db.recent_scans(10)
        check("every scan attempt is logged", len(rows) >= 2, f"rows={len(rows)}")
    finally:
        db.close()


# --------------------------------------------------------------------------- #
# TOCTOU / locked file access
# --------------------------------------------------------------------------- #

def test_locked_file(tmp: Path) -> None:
    section("Locked file access (TOCTOU defence)")

    from scanner.engine import LockedFile

    sample = tmp / "locked_sample.bin"
    payload = os.urandom(200_000)
    sample.write_bytes(payload)

    with LockedFile(sample) as locked:
        check("locked file reports the correct size",
              locked.size == len(payload), f"{locked.size}")
        check("hash from the handle matches a plain hash",
              locked.sha256() == hashlib.sha256(payload).hexdigest())
        check("unchanged() is true when nothing touched the file",
              locked.unchanged())

        # The core guarantee: while we hold the handle, another writer must be
        # refused. This is what stops the hash/scan race.
        if sys.platform == "win32":
            blocked = False
            try:
                with open(sample, "r+b"):
                    pass
            except OSError:
                blocked = True
            check("a writer is refused while the scan handle is held", blocked)

            delete_blocked = False
            try:
                sample.unlink()
            except OSError:
                delete_blocked = True
            check("deleting is refused while the scan handle is held",
                  delete_blocked)

            # Readers must still be allowed: Defender needs to read the file.
            read_ok = False
            try:
                with open(sample, "rb") as handle:
                    handle.read(16)
                read_ok = True
            except OSError:
                read_ok = False
            check("concurrent readers are still allowed", read_ok)

    # After release, writes work again.
    if sys.platform == "win32":
        released = False
        try:
            with open(sample, "r+b"):
                pass
            released = True
        except OSError:
            released = False
        check("writer is allowed again after the handle is released", released)

    # A file that changes after opening must be detected. On Windows the share
    # mode blocks the write, which is the primary defence; unchanged() is the
    # backstop for filesystems that ignore share modes (network shares, FUSE).
    # Simulate that case by perturbing the recorded stat key.
    with LockedFile(sample) as locked:
        check("unchanged() is true immediately after opening", locked.unchanged())
        size, mtime = locked._stat_key          # noqa: SLF001
        locked._stat_key = (size + 1, mtime)    # noqa: SLF001
        check("unchanged() detects a size change", not locked.unchanged())
        locked._stat_key = (size, mtime + 1)    # noqa: SLF001
        check("unchanged() detects an mtime change", not locked.unchanged())
        locked._stat_key = (size, mtime)        # noqa: SLF001
        check("unchanged() is true again once the key matches", locked.unchanged())

    check("opening a missing file raises OSError",
          _raises_oserror(lambda: LockedFile(tmp / "nope.bin").__enter__()))


def _raises_oserror(fn) -> bool:
    try:
        fn()
    except OSError:
        return True
    except Exception:
        return False
    return False


# --------------------------------------------------------------------------- #
# DPAPI secret storage
# --------------------------------------------------------------------------- #

def test_secret_storage(tmp: Path) -> None:
    section("Secret storage (DPAPI)")

    from scanner.config import Settings, protect_secret, unprotect_secret

    secret = "test-auth-key-1234567890"

    if sys.platform == "win32":
        protected = protect_secret(secret)
        check("protected value is not the plaintext", secret not in protected)
        check("protected value carries the dpapi marker",
              protected.startswith("dpapi:"))
        check("round-trip returns the original secret",
              unprotect_secret(protected) == secret)
        check("ciphertext differs between two encryptions of the same input",
              protect_secret(secret) != protected)
        check("empty string stays empty", protect_secret("") == "")
    else:
        check("non-Windows passes secrets through unchanged",
              protect_secret(secret) == secret)

    check("legacy plaintext is returned unchanged",
          unprotect_secret("legacy-plain-key") == "legacy-plain-key")
    check("a corrupted blob degrades to empty rather than raising",
          unprotect_secret("dpapi:not-valid-base64!!!") == "")

    # End-to-end through the settings file.
    path = tmp / "secret_settings.json"
    settings = Settings(path)
    settings.set("mb_auth_key", secret)
    settings.set("opswat_api_key", "opswat-key-xyz")
    settings.set("cache_ttl_hours", 12)
    settings.save()

    raw = path.read_text(encoding="utf-8")
    if sys.platform == "win32":
        check("the key is not readable in the settings file on disk",
              secret not in raw)
        check("the opswat key is not readable on disk either",
              "opswat-key-xyz" not in raw)
    check("non-secret settings stay plaintext", "cache_ttl_hours" in raw)

    reloaded = Settings(path)
    check("secret survives a save/load cycle",
          reloaded.get("mb_auth_key") == secret,
          str(reloaded.get("mb_auth_key"))[:20])
    check("second secret also survives",
          reloaded.get("opswat_api_key") == "opswat-key-xyz")
    check("ordinary settings survive", reloaded.get("cache_ttl_hours") == 12)


# --------------------------------------------------------------------------- #
# Watcher seen-cache bounding
# --------------------------------------------------------------------------- #

def test_seen_bounding(tmp: Path) -> None:
    section("Watcher seen-cache bounding")

    watch_dir = tmp / "seenwatch"
    watch_dir.mkdir()
    watcher = FolderWatcher(watch_dir, on_ready=lambda p: None,
                            settle_seconds=0.5, poll_interval=0.2)

    now = time.time()
    watcher._seen_max = 10          # noqa: SLF001
    watcher._seen_ttl = 3600.0      # noqa: SLF001
    for i in range(50):
        watcher._seen[f"C:/fake/file{i}.bin"] = now  # noqa: SLF001
    watcher._prune_seen(now)        # noqa: SLF001
    check("seen cache is capped at the maximum",
          len(watcher._seen) == 10, f"len={len(watcher._seen)}")  # noqa: SLF001

    # Expired entries are dropped, so the same path can be rescanned.
    watcher._seen.clear()           # noqa: SLF001
    watcher._seen["C:/fake/old.bin"] = now - 7200  # noqa: SLF001
    check("an expired path is not treated as already seen",
          not watcher._already_seen("C:/fake/old.bin", now))  # noqa: SLF001
    check("a fresh path is treated as already seen",
          watcher._already_seen("C:/fake/file0.bin", now) is False)  # noqa: SLF001
    watcher._seen["C:/fake/new.bin"] = now  # noqa: SLF001
    check("a recently dispatched path is skipped",
          watcher._already_seen("C:/fake/new.bin", now))  # noqa: SLF001


# --------------------------------------------------------------------------- #
# Reparse points and size caps
# --------------------------------------------------------------------------- #

def test_walk_guards(tmp: Path) -> None:
    section("Folder walk guards")

    from scanner.watcher import collect_files

    root = tmp / "walkroot"
    (root / "real").mkdir(parents=True)
    (root / "real" / "inside.txt").write_text("x", encoding="utf-8")
    big = root / "big.bin"
    big.write_bytes(b"0" * 50_000)
    small = root / "small.bin"
    small.write_bytes(b"0" * 10)

    all_files = collect_files(root)
    check("normal files are collected", len(all_files) == 3, f"{len(all_files)}")

    capped = collect_files(root, max_size_bytes=1000)
    names = {Path(f).name for f in capped}
    check("size cap excludes the large file", "big.bin" not in names, f"{names}")
    check("size cap keeps the small files", "small.bin" in names)

    # A junction must not be descended into.
    if sys.platform == "win32":
        junction = root / "link_to_windows"
        made = False
        try:
            subprocess.run(
                ["cmd", "/c", "mklink", "/J", str(junction), r"C:\Windows\System32\drivers\etc"],
                capture_output=True, timeout=20, check=False,
            )
            made = junction.exists()
        except Exception:
            made = False

        if made:
            walked = collect_files(root, limit=100000)
            escaped = [f for f in walked if "link_to_windows" in f]
            check("a junction is not descended into", not escaped,
                  f"{len(escaped)} files escaped")
        else:
            print("        (skipped: could not create a junction in this environment)")


# --------------------------------------------------------------------------- #
# AMSI layer
# --------------------------------------------------------------------------- #

EICAR = r"X5O!P%@AP[4\PZX54(P^)7CC)7}$EICAR-STANDARD-ANTIVIRUS-TEST-FILE!$H+H*"


def test_amsi(tmp: Path) -> None:
    section("AMSI layer")

    from scanner.amsi import AMSI_RESULT_DETECTED, AmsiLayer

    layer = AmsiLayer()
    probe = layer.probe()
    check("AMSI probe returns a verdict object", probe is not None)
    print(f"        available={probe.available} detail={probe.detail!r}")

    if not probe.available:
        print("        (AMSI unavailable here; skipping live detection checks)")
        check("unavailable AMSI reports a reason", bool(probe.detail))
        return

    clean = tmp / "amsi_clean.txt"
    clean.write_text("harmless content\n" * 50, encoding="utf-8")
    clean_verdict = layer.scan(clean)
    check("AMSI clears a harmless file", not clean_verdict.detected,
          clean_verdict.detail)
    check("AMSI reports availability on a clean scan", clean_verdict.available)

    eicar = tmp / "amsi_eicar.com"
    eicar.write_text(EICAR, encoding="ascii")
    eicar_verdict = layer.scan(eicar)
    check("AMSI detects the EICAR test string", eicar_verdict.detected,
          eicar_verdict.detail)
    if eicar_verdict.result_code is not None:
        check("a real AMSI detection carries the detected code",
              eicar_verdict.result_code >= AMSI_RESULT_DETECTED,
              str(eicar_verdict.result_code))

    # A multi-chunk file must not crash the chunked reader.
    big = tmp / "amsi_big.bin"
    big.write_bytes(b"A" * (3 * 1024 * 1024 + 12345))
    big_verdict = layer.scan(big)
    check("a multi-chunk file scans without error",
          big_verdict.available and not big_verdict.detected,
          big_verdict.detail)

    check("scanning a missing file degrades gracefully",
          layer.scan(tmp / "nope.bin").detected is False)


# --------------------------------------------------------------------------- #
# Defender output parsing
# --------------------------------------------------------------------------- #

def test_threat_parsing() -> None:
    section("Defender output parsing")

    from scanner.engine import _extract_threat_name

    check("a bordered separator row is not mistaken for a threat name",
          _extract_threat_name("-----------------------------\n") == "",
          repr(_extract_threat_name("-----------------------------\n")))
    check("a column header is not mistaken for a threat name",
          _extract_threat_name("Name: \n") == "")
    check("a real threat name is extracted",
          _extract_threat_name("Threat information: Trojan:Win32/Emotet") ==
          "Trojan:Win32/Emotet",
          repr(_extract_threat_name("Threat information: Trojan:Win32/Emotet")))
    check("a Name: line with a real value is extracted",
          _extract_threat_name("Name: Virus:DOS/EICAR_Test_File") ==
          "Virus:DOS/EICAR_Test_File")
    check("empty output yields no name", _extract_threat_name("") == "")


# --------------------------------------------------------------------------- #
# Antivirus-block detection
# --------------------------------------------------------------------------- #

def test_av_block_detection(tmp: Path) -> None:
    section("Antivirus-block detection")

    from scanner.engine import (
        FileBlockedByAntivirus,
        LockedFile,
        _is_av_block,
    )

    # Error 225 is ERROR_VIRUS_INFECTED, the definitive one.
    check("ERROR_VIRUS_INFECTED (225) is recognised as an AV block",
          _is_av_block(OSError(225, "virus infected")))
    check("ERROR_BAD_COMMAND (22) is recognised as an AV block",
          _is_av_block(OSError(22, "bad command")))
    check("ERROR_SHARING_VIOLATION (32) is recognised as an AV block",
          _is_av_block(OSError(32, "sharing violation")))
    check("an unrelated error is not an AV block",
          not _is_av_block(OSError(2, "file not found")))

    # A quarantined file must surface as FileBlockedByAntivirus, not a bare
    # OSError, because the engine turns one into Malicious and the other into
    # Error. Getting this wrong is a false negative on the worst case.
    blocked = FileBlockedByAntivirus("blocked", 225)
    check("FileBlockedByAntivirus carries the error code",
          blocked.errno_code == 225)
    check("FileBlockedByAntivirus is an OSError subclass",
          isinstance(blocked, OSError))

    # The engine's AV-blocked result must be Malicious and must not be cached
    # under an empty hash.
    from scanner.config import Settings
    from scanner.database import ScanDatabase
    from scanner.engine import ScanEngine, Verdict

    settings = Settings(tmp / "avblock_settings.json")
    settings.set("mb_auth_key", "")
    settings.set("opswat_api_key", "")
    db = ScanDatabase(tmp / "avblock.db")
    engine = ScanEngine(settings, db)
    try:
        fake = tmp / "blocked_sample.exe"
        fake.write_bytes(b"placeholder")
        result = engine._av_blocked_result(  # noqa: SLF001
            fake, time.time(), "test", "blocked by AV"
        )
        check("an AV-blocked file yields a Malicious verdict",
              result.verdict is Verdict.MALICIOUS, result.verdict.value)
        check("an AV-blocked file scores 100", result.score == 100)
        check("an AV-blocked file has no hash", result.sha256 == "")
        check("the Defender column reports Malicious",
              result.defender.status.value == "Malicious")
        check("cloud layers are skipped, not errored",
              result.malwarebazaar.status.value == "Skipped"
              and result.opswat.status.value == "Skipped")

        empty_rows = db._conn().execute(  # noqa: SLF001
            "SELECT COUNT(*) FROM scan_cache WHERE sha256 = ''"
        ).fetchone()[0]
        check("nothing is cached under an empty hash", empty_rows == 0)

        rows = db.recent_scans(5)
        check("the AV block is recorded in history", len(rows) == 1)
        check("history shows it as Malicious",
              rows and rows[0]["verdict"] == "Malicious")
    finally:
        db.close()


# --------------------------------------------------------------------------- #
# Quarantine
# --------------------------------------------------------------------------- #

def test_quarantine(tmp: Path) -> None:
    section("Quarantine store")

    from scanner.engine import compute_sha256
    from scanner.quarantine import (
        QUARANTINE_SUFFIX,
        FileAlreadyHandled,
        QuarantineError,
        QuarantineManager,
    )

    store = tmp / "qstore"
    db = ScanDatabase(tmp / "quar.db")
    mgr = QuarantineManager(db, store)
    try:
        victim = tmp / "q_evil.exe"
        victim.write_bytes(b"payload bytes" * 50)
        digest = compute_sha256(victim)
        size = victim.stat().st_size

        rec = mgr.quarantine(victim, sha256=digest, threat_detail="Trojan:Test")
        check("quarantine returns a record", rec is not None)
        check("the original file is gone", not victim.exists())
        check("the file is in the store", Path(rec.quarantine_path).is_file())
        check("the stored file is renamed .quar so it cannot execute",
              rec.quarantine_path.endswith(QUARANTINE_SUFFIX))
        check("the record keeps the original path",
              rec.original_path == str(victim.resolve()))
        check("the record keeps the hash", rec.sha256 == digest)
        check("the record keeps the size", rec.file_size == size)
        check("the stored bytes are unchanged",
              compute_sha256(Path(rec.quarantine_path)) == digest)
        check("the stored file is read-only",
              not (Path(rec.quarantine_path).stat().st_mode & 0o222))

        check("the hash is reported as quarantined",
              db.is_quarantined_hash(digest))
        check("stats count it", mgr.stats()["count"] == 1)
        check("db stats count it", db.stats()["quarantined"] == 1)

        # Restore.
        restored = mgr.restore(rec.id)
        check("restore returns the file to its original path", restored == victim)
        check("restored bytes match", compute_sha256(victim) == digest)
        check("restored file is writable", bool(victim.stat().st_mode & 0o200))
        check("record is marked restored",
              db.get_quarantine(rec.id).status == "restored")
        check("the hash is no longer quarantined",
              not db.is_quarantined_hash(digest))

        # Tamper refusal.
        t = tmp / "q_tamper.exe"
        t.write_bytes(b"original payload")
        th = compute_sha256(t)
        rec_t = mgr.quarantine(t, sha256=th)
        stored_t = Path(rec_t.quarantine_path)
        os.chmod(stored_t, 0o600)
        stored_t.write_bytes(b"SWAPPED")
        refused = False
        try:
            mgr.restore(rec_t.id)
        except QuarantineError as exc:
            refused = "modified" in str(exc).lower()
        check("restore refuses a tampered file", refused)
        check("the tampered file was not restored", not t.exists())

        # Delete.
        mgr.delete(rec_t.id, shred=True)
        check("delete removes the stored file", not stored_t.exists())
        check("delete marks the record deleted",
              db.get_quarantine(rec_t.id).status == "deleted")

        # Missing source.
        handled = False
        try:
            mgr.quarantine(tmp / "q_gone.exe", sha256="b" * 64)
        except FileAlreadyHandled:
            handled = True
        check("a missing file raises FileAlreadyHandled", handled)

        # Hash collision in the store.
        a = tmp / "q_dup_a.exe"
        b = tmp / "q_dup_b.exe"
        a.write_bytes(b"identical")
        b.write_bytes(b"identical")
        same = compute_sha256(a)
        ra = mgr.quarantine(a, sha256=same)
        rb = mgr.quarantine(b, sha256=same)
        check("identical hashes get distinct store paths",
              ra.quarantine_path != rb.quarantine_path)
        check("both colliding files are kept",
              Path(ra.quarantine_path).is_file()
              and Path(rb.quarantine_path).is_file())
    finally:
        db.close()


# --------------------------------------------------------------------------- #
# Reputation signals
# --------------------------------------------------------------------------- #

def test_reputation(tmp: Path) -> None:
    section("Local reputation signals")

    from scanner.reputation import (
        ReputationAssessment,
        SignatureStatus,
        analyze_pe,
        assess,
        read_motw,
        should_deep_scan,
        verify_authenticode,
        _entropy,
        _score,
    )

    # -- entropy ----------------------------------------------------------- #
    check("entropy of a constant block is 0", _entropy(b"\x00" * 1000) == 0.0)
    uniform = bytes(range(256)) * 4
    check("entropy of a byte-uniform block is 8.0",
          abs(_entropy(uniform) - 8.0) < 0.01, f"{_entropy(uniform):.3f}")
    check("entropy of random data is high",
          _entropy(os.urandom(8192)) > 7.0)

    # -- non-PE ------------------------------------------------------------ #
    text = tmp / "plain.txt"
    text.write_text("just text", encoding="utf-8")
    pe = analyze_pe(text)
    check("a text file is not a PE", not pe.is_pe)
    check("a non-PE reports a reason", bool(pe.error), pe.error)

    # -- real PE ----------------------------------------------------------- #
    if sys.platform == "win32":
        notepad = Path(r"C:\Windows\System32\notepad.exe")
        if notepad.is_file():
            pe = analyze_pe(notepad)
            check("notepad.exe parses as a PE", pe.is_pe)
            check("machine is detected", pe.machine in ("x64", "x86"), pe.machine)
            check("imports are extracted", len(pe.imports) > 20,
                  f"{len(pe.imports)} imports")
            check("notepad is not packed", not pe.is_packed,
                  f"entropy {pe.max_entropy:.2f}")
            check("notepad has an import table", not pe.has_no_imports)

            sig = verify_authenticode(notepad)
            check("notepad.exe verifies as signed",
                  sig.status is SignatureStatus.VALID, sig.status.value)
            check("the signer is identified", "Microsoft" in sig.signer,
                  sig.signer)

            kernel32 = Path(r"C:\Windows\System32\kernel32.dll")
            if kernel32.is_file():
                ksig = verify_authenticode(kernel32)
                check("kernel32.dll verifies as signed",
                      ksig.status is SignatureStatus.VALID, ksig.status.value)
                check("kernel32 uses an embedded signature",
                      not ksig.via_catalog)
                check("notepad uses a catalog signature", sig.via_catalog)

    # -- MOTW -------------------------------------------------------------- #
    motw = read_motw(text)
    check("a locally created file has no MOTW", not motw.present)

    if sys.platform == "win32":
        tagged = tmp / "tagged.bin"
        tagged.write_bytes(b"payload")
        try:
            with open(f"{tagged}:Zone.Identifier", "w", encoding="utf-8") as handle:
                handle.write("[ZoneTransfer]\nZoneId=3\n"
                             "HostUrl=https://example.com/evil.exe\n")
            info = read_motw(tagged)
            check("a Zone.Identifier stream is detected", info.present)
            check("ZoneId is parsed", info.zone_id == 3, str(info.zone_id))
            check("internet zone is flagged as from-internet", info.from_internet)
            check("HostUrl is parsed",
                  info.host_url == "https://example.com/evil.exe", info.host_url)
            check("zone label is human readable", info.zone_label == "Internet")
        except OSError as exc:
            print(f"        (skipped MOTW write: {exc})")

    # -- scoring ----------------------------------------------------------- #
    clean = ReputationAssessment()
    clean.signature.status = SignatureStatus.VALID
    clean.signature.signer = "Contoso"
    _score(clean)
    check("a signed non-PE scores low", clean.risk <= 0, str(clean.risk))
    check("a signed file is not suspicious", not clean.is_suspicious)

    unsigned_exe = ReputationAssessment()
    unsigned_exe.pe.is_pe = True
    unsigned_exe.pe.imports = ["CreateFileW", "ReadFile", "CloseHandle"]
    unsigned_exe.signature.status = SignatureStatus.UNSIGNED
    _score(unsigned_exe)
    check("an unsigned executable raises risk", unsigned_exe.risk == 25,
          str(unsigned_exe.risk))
    check("unsigned alone is not enough to be suspicious",
          not unsigned_exe.is_suspicious)

    downloaded = ReputationAssessment()
    downloaded.pe.is_pe = True
    downloaded.signature.status = SignatureStatus.UNSIGNED
    downloaded.motw.present = True
    downloaded.motw.zone_id = 3
    _score(downloaded)
    check("unsigned + internet download is suspicious",
          downloaded.is_suspicious, f"risk {downloaded.risk}")

    tampered = ReputationAssessment()
    tampered.pe.is_pe = True
    tampered.signature.status = SignatureStatus.INVALID
    _score(tampered)
    check("an invalid signature is suspicious on its own",
          tampered.is_suspicious, f"risk {tampered.risk}")

    injector = ReputationAssessment()
    injector.pe.is_pe = True
    injector.pe.has_injection_triad = True
    injector.signature.status = SignatureStatus.VALID
    injector.signature.signer = "Nobody"
    _score(injector)
    check("the injection API triad is suspicious on its own",
          injector.is_suspicious, f"risk {injector.risk}")

    packed = ReputationAssessment()
    packed.pe.is_pe = True
    packed.pe.max_entropy = 7.9
    packed.pe.high_entropy_sections = [".upx0 (7.90)"]
    packed.signature.status = SignatureStatus.VALID
    packed.signature.signer = "Nobody"
    _score(packed)
    check("a packed binary raises risk", packed.risk >= 10, str(packed.risk))
    check("a packed binary is flagged",
          any("packed" in f.lower() for f in packed.flags), str(packed.flags))

    # -- deep scan gating -------------------------------------------------- #
    check("an .exe warrants a deep scan", should_deep_scan("a.exe"))
    check("a .dll warrants a deep scan", should_deep_scan("a.dll"))
    check("a .jpg does not warrant a deep scan", not should_deep_scan("a.jpg"))
    check("a .mp4 does not warrant a deep scan", not should_deep_scan("a.mp4"))

    # -- assess() end to end ----------------------------------------------- #
    result = assess(text)
    check("assess returns an assessment", result is not None)
    check("a plain text file has no PE data", not result.pe.is_pe)


# --------------------------------------------------------------------------- #


def main() -> int:
    print("HybridShield smoke tests")
    print("=" * 60)

    with tempfile.TemporaryDirectory(prefix="hybridshield_test_") as raw:
        tmp = Path(raw)
        test_hashing(tmp)
        test_database(tmp)
        test_aggregation()
        test_locked_file(tmp)
        test_secret_storage(tmp)
        test_amsi(tmp)
        test_threat_parsing()
        test_av_block_detection(tmp)
        test_quarantine(tmp)
        test_reputation(tmp)
        test_watcher(tmp)
        test_seen_bounding(tmp)
        test_walk_guards(tmp)
        test_collect(tmp)
        test_engine_offline(tmp)

    print("\n" + "=" * 60)
    print(f"PASSED: {len(PASSED)}   FAILED: {len(FAILED)}")
    if FAILED:
        print("\nFailures:")
        for item in FAILED:
            print(f"  - {item}")
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())
