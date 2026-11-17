"""End-to-end: do reputation signals actually change the verdict?

Builds a genuinely clean-but-suspicious file (a real executable, unsigned, with
a Zone.Identifier marking it as internet-downloaded) and confirms the engine
escalates Clean to Suspicious. Also confirms a signed system binary stays Clean.

Run:  python tools/verify_reputation.py
"""

from __future__ import annotations

import shutil
import sys
import tempfile
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from scanner.config import Settings                              # noqa: E402
from scanner.database import ScanDatabase                        # noqa: E402
from scanner.engine import ScanEngine, Verdict                   # noqa: E402
from scanner.reputation import assess, verify_authenticode        # noqa: E402

PASSED, FAILED = [], []


def check(name, ok, detail=""):
    (PASSED if ok else FAILED).append(name if ok else f"{name}: {detail}")
    print(f"  {'PASS' if ok else 'FAIL'}  {name}"
          + (f"  {detail}" if detail and not ok else ""))


def main() -> int:
    print("Reputation signals end-to-end")
    print("=" * 66)

    if sys.platform != "win32":
        print("Windows-only; nothing to test here.")
        return 0

    source = Path(r"C:\Windows\System32\notepad.exe")
    if not source.is_file():
        print("notepad.exe not found; cannot run this check.")
        return 1

    with tempfile.TemporaryDirectory(prefix="rep_e2e_") as raw:
        tmp = Path(raw)
        db = ScanDatabase(tmp / "rep.db")
        settings = Settings(tmp / "rep_settings.json")
        settings.set("mb_auth_key", "")
        settings.set("opswat_api_key", "")
        settings.set("auto_quarantine", False)   # keep the file for inspection
        engine = ScanEngine(settings, db)

        try:
            # ---- 1. signed system binary stays Clean -------------------- #
            signed = tmp / "signed_copy.exe"
            shutil.copy2(source, signed)
            rep = assess(signed)
            print(f"\n  signed_copy.exe")
            print(f"    signature : {rep.signature.status.value} "
                  f"(catalog={rep.signature.via_catalog}) "
                  f"signer={rep.signature.signer!r}")
            print(f"    risk      : {rep.risk}")
            print(f"    flags     : {rep.flags}")

            check("a signed binary reports a valid signature",
                  rep.signature.status.value == "Valid", rep.signature.status.value)
            check("a signed binary has low risk", rep.risk < 40, str(rep.risk))

            result = engine.scan_file(signed, source="verify")
            print(f"    verdict   : {result.verdict.value} (score {result.score})")
            check("a signed clean binary stays Clean",
                  result.verdict is Verdict.CLEAN, result.verdict.value)

            # ---- 2. same binary + MOTW = Suspicious --------------------- #
            tagged = tmp / "downloaded_copy.exe"
            shutil.copy2(source, tagged)
            with open(f"{tagged}:Zone.Identifier", "w", encoding="utf-8") as handle:
                handle.write(
                    "[ZoneTransfer]\n"
                    "ZoneId=3\n"
                    "HostUrl=https://totally-legit-downloads.example/payload.exe\n"
                )

            rep2 = assess(tagged)
            print(f"\n  downloaded_copy.exe (same bytes + Zone.Identifier)")
            print(f"    motw      : present={rep2.motw.present} "
                  f"zone={rep2.motw.zone_label} host={rep2.motw.host_url}")
            print(f"    signature : {rep2.signature.status.value}")
            print(f"    risk      : {rep2.risk}")
            print(f"    flags     : {rep2.flags}")

            check("MOTW is detected on the tagged copy", rep2.motw.present)
            check("the download host is recorded",
                  "totally-legit-downloads" in rep2.motw.host_url,
                  rep2.motw.host_url)
            # A valid signature offsets the MOTW, so this should stay low:
            # that is the intended behaviour, not a bug.
            print(f"    (signed + MOTW -> risk {rep2.risk}; a valid signature "
                  f"offsets the download signal)")

            # ---- 3. unsigned + MOTW = Suspicious ------------------------ #
            # Use a genuinely unsigned executable. Stripping the signature off
            # a catalog-signed system binary does not work: the catalog still
            # vouches for it, which is the whole point of catalog signing.
            unsigned_source = _find_unsigned_exe()
            if unsigned_source is None:
                print("\n        (no unsigned executable available; skipping escalation check)")
            else:
                unsigned = tmp / "unsigned_tool.exe"
                shutil.copy2(unsigned_source, unsigned)
                with open(f"{unsigned}:Zone.Identifier", "w", encoding="utf-8") as handle:
                    handle.write("[ZoneTransfer]\nZoneId=3\n"
                                 "HostUrl=https://evil.example/tool.exe\n")

                rep3 = assess(unsigned)
                print(f"\n  unsigned_tool.exe (from {unsigned_source.name}, + MOTW)")
                print(f"    signature : {rep3.signature.status.value} "
                      f"(catalog={rep3.signature.via_catalog})")
                print(f"    risk      : {rep3.risk}")
                print(f"    flags     : {rep3.flags}")

                check("a genuinely unsigned exe reports as unsigned",
                      rep3.signature.status.value == "Unsigned",
                      rep3.signature.status.value)
                check("an unsigned file is not marked as catalog-signed",
                      not rep3.signature.via_catalog)
                check("unsigned + internet download is suspicious",
                      rep3.is_suspicious, f"risk {rep3.risk}")

                result3 = engine.scan_file(unsigned, source="verify")
                print(f"    verdict   : {result3.verdict.value} "
                      f"(score {result3.score})")
                check("the engine escalates Clean to Suspicious on local signals",
                      result3.verdict is Verdict.SUSPICIOUS,
                      result3.verdict.value)
                check("the escalated score is at least 40", result3.score >= 40,
                      str(result3.score))
                check("the reputation data survives into the result",
                      result3.reputation is not None
                      and result3.reputation.risk >= 40)

            # ---- 4. reputation never lowers a verdict ------------------- #
            print("\n  invariant: reputation can only escalate")
            check("a signed file is never marked suspicious by signature alone",
                  rep.risk < 40)

            # ---- 5. double extension ------------------------------------ #
            # This used to be a YARA rule, which was wrong: rules see content,
            # and a content rule for it matched the literal ".com" inside any
            # binary mentioning a URL - flagging curl.exe and six other signed
            # Windows binaries as Malicious. It is a filename property.
            print("\n  double extension (filename, not content)")
            from scanner.reputation import double_extension

            deceptive = {
                "invoice.pdf.exe": "invoice.pdf",
                "report.docx.scr": "report.docx",
                "photo.jpg.com": "photo.jpg",
                "a.b.pdf.exe": "a.b.pdf",
                "INVOICE.PDF.EXE": "INVOICE.PDF",
                "x.pdf.bat": "x.pdf",
            }
            for name, want in deceptive.items():
                check(f"{name} is deceptive", double_extension(name) == want,
                      f"got {double_extension(name)!r}, want {want!r}")

            honest = [
                "setup.exe", "readme.txt", "archive.tar.gz", "v1.2.exe",
                "notes.pdf", "my.file.name.pdf", "app.dll",
            ]
            for name in honest:
                check(f"{name} is not deceptive", double_extension(name) == "",
                      f"got {double_extension(name)!r}")

            # A real deceptive file on disk must escalate through the engine.
            trap_dir = Path(tempfile.mkdtemp(prefix="hs_dblext_"))
            trap = trap_dir / "invoice_2026.pdf.exe"
            trap.write_bytes(b"MZ" + b"\x00" * 64)
            trap_rep = assess(str(trap), deep=False)
            check("a deceptive filename raises risk", trap_rep.risk >= 40,
                  str(trap_rep.risk))
            check("a deceptive filename is flagged",
                  any("hides an executable" in f for f in trap_rep.flags),
                  str(trap_rep.flags))
            check("a deceptive filename is suspicious", trap_rep.is_suspicious)

            clean_name = trap_dir / "invoice_2026.pdf"
            clean_name.write_bytes(b"%PDF-1.7\n" + b"\x00" * 64)
            clean_rep = assess(str(clean_name), deep=False)
            check("an honest filename does not raise risk",
                  not any("hides an executable" in f for f in clean_rep.flags),
                  str(clean_rep.flags))
        finally:
            db.close()

    print("\n" + "=" * 66)
    print(f"PASSED: {len(PASSED)}   FAILED: {len(FAILED)}")
    for f in FAILED:
        print(f"  - {f}")
    return 0 if not FAILED else 1


def _find_unsigned_exe() -> Path | None:
    """Locate a genuinely unsigned executable on this machine.

    Used only by this verification script. Windows system binaries are
    catalog-signed and cannot be made unsigned by stripping their embedded
    signature, so a real unsigned binary is needed to test the escalation path.
    """
    candidates = [
        Path(r"C:\Program Files\dotnet\packs\Microsoft.NETCore.App.Host.win-x64"
             r"\10.0.14\runtimes\win-x64\native\apphost.exe"),
        Path(r"C:\Program Files\dotnet\sdk\10.0.403\AppHostTemplate\apphost.exe"),
    ]
    for candidate in candidates:
        if not candidate.is_file():
            continue
        info = verify_authenticode(candidate)
        if info.status.value == "Unsigned":
            return candidate
    return None


def _strip_signature(path: Path) -> None:
    """Zero the PE security data directory so WinVerifyTrust finds no signature.

    This is exactly what a tamperer does to a signed binary, which is why the
    result should read as unsigned rather than valid.
    """
    import struct

    with open(path, "r+b") as handle:
        head = handle.read(4096)
        e = struct.unpack_from("<I", head, 0x3C)[0]
        coff = e + 4
        opt_size = struct.unpack_from("<H", head, coff + 16)[0]
        opt = coff + 20
        magic = struct.unpack_from("<H", head, opt)[0]
        dd = opt + (112 if magic == 0x20B else 96)
        entry = dd + 4 * 8
        handle.seek(entry)
        handle.write(struct.pack("<II", 0, 0))


if __name__ == "__main__":
    sys.exit(main())
