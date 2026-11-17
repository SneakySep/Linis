"""Render the dashboard and quarantine dialog for visual verification."""

from __future__ import annotations

import os
import sys
import tempfile
import time
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

os.environ.setdefault("QT_QPA_PLATFORM", "offscreen")
os.environ.setdefault("QT_QPA_FONTDIR", r"C:\Windows\Fonts")

from PySide6.QtWidgets import QApplication                    # noqa: E402

from scanner.config import Settings                            # noqa: E402
from scanner.database import ScanDatabase                      # noqa: E402
from scanner.engine import LayerResult, ScanResult, Status, Verdict  # noqa: E402
from scanner.reputation import (                               # noqa: E402
    MotwInfo,
    PeInfo,
    ReputationAssessment,
    SignatureInfo,
    SignatureStatus,
)
from scanner.quarantine import QuarantineManager               # noqa: E402
from ui import theme                                           # noqa: E402
from ui.main_window import MainWindow                          # noqa: E402
from ui.quarantine_dialog import QuarantineDialog              # noqa: E402


def make_row(name, size, sha, defender, mb, opswat, verdict, score,
             cache=False, amsi=None, quarantined=False, qerr="", rep=None,
             yara=None, yara_detail="sample detail"):
    result = ScanResult(
        file_path="C:\\Users\\User\\Downloads\\" + name,
        file_name=name, file_size=size, sha256=sha, scanned_at=time.time(),
        verdict=verdict, score=score, from_cache=cache,
    )
    result.amsi = LayerResult(status=amsi if amsi is not None else Status.CLEAN,
                              detail="sample detail")
    result.yara = LayerResult(status=yara if yara is not None else Status.CLEAN,
                              detail=yara_detail)
    result.defender = LayerResult(status=defender, detail="sample detail")
    result.malwarebazaar = LayerResult(status=mb, detail="sample detail")
    result.opswat = LayerResult(status=opswat, detail="sample detail")
    result.quarantined = quarantined
    result.quarantine_path = ("C:\\Users\\User\\AppData\\Local\\HybridShield"
                              "\\Quarantine\\7bd24141" + ".quar") if quarantined else ""
    result.quarantine_error = qerr
    result.reputation = rep
    return result


def signed_rep(signer="Microsoft Windows"):
    rep = ReputationAssessment()
    rep.signature = SignatureInfo(status=SignatureStatus.VALID, signer=signer)
    rep.pe = PeInfo(is_pe=True, machine="x64", subsystem="GUI", max_entropy=6.3)
    rep.flags = [f"Signed by {signer}"]
    rep.risk = 0
    return rep


def unsigned_downloaded_rep():
    rep = ReputationAssessment()
    rep.signature = SignatureInfo(status=SignatureStatus.UNSIGNED)
    rep.pe = PeInfo(is_pe=True, machine="x64", subsystem="GUI", max_entropy=7.8,
                    high_entropy_sections=[".upx0 (7.80)"])
    rep.motw = MotwInfo(present=True, zone_id=3,
                        host_url="https://evil.example/payload.exe")
    rep.risk = 45
    rep.flags = [
        "Downloaded from the internet (Internet): https://evil.example/payload.exe",
        "Executable is not digitally signed",
        "High-entropy section (packed or encrypted): .upx0 (7.80)",
    ]
    return rep


def main() -> int:
    app = QApplication(sys.argv)
    app.setStyleSheet(theme.STYLESHEET)

    window = MainWindow(Settings())
    window.resize(1280, 800)
    window.show()

    rows = [
        make_row("setup_installer.exe", 48_213_004, "a3f1" + "9c" * 30,
                 Status.CLEAN, Status.NOT_FOUND, Status.CLEAN, Verdict.CLEAN, 0,
                 rep=signed_rep()),
        make_row("invoice_2026.pdf.exe", 184_320, "7bd2" + "41" * 30,
                 Status.SKIPPED, Status.SKIPPED, Status.SKIPPED,
                 Verdict.MALICIOUS, 100, amsi=Status.MALICIOUS,
                 quarantined=True, rep=unsigned_downloaded_rep(),
                 yara=Status.MALICIOUS,
                 yara_detail="Code enumerating document extensions for mass "
                             "encryption [Ransomware_Extension_Targeting]"),
        make_row("crack_tool.zip", 9_204_416, "c19e" + "7a" * 30,
                 Status.CLEAN, Status.MALICIOUS, Status.SKIPPED,
                 Verdict.MALICIOUS, 100, quarantined=True,
                 rep=unsigned_downloaded_rep(),
                 yara=Status.SUSPICIOUS,
                 yara_detail="UPX-packed executable [UPX_Packed]"),
        make_row("report_draft.docx", 245_760, "e4b7" + "0f" * 30,
                 Status.CLEAN, Status.NOT_FOUND, Status.SUSPICIOUS,
                 Verdict.SUSPICIOUS, 60, yara=Status.CLEAN,
                 yara_detail="No rule matched"),
        make_row("photo.jpg", 3_810_304, "1a9c" + "d3" * 30,
                 Status.CLEAN, Status.ERROR, Status.NOT_FOUND, Verdict.CLEAN, 5,
                 yara=Status.CLEAN, yara_detail="No rule matched"),
        make_row("unknown_pkg.msi", 7_340_032, "55e1" + "8b" * 30,
                 Status.ERROR, Status.NOT_FOUND, Status.NOT_FOUND,
                 Verdict.UNKNOWN, 20, amsi=Status.SKIPPED,
                 rep=unsigned_downloaded_rep(), yara=Status.CLEAN,
                 yara_detail="No rule matched"),
        make_row("archive.7z", 12_058_624, "9f02" + "2c" * 30,
                 Status.CLEAN, Status.SKIPPED, Status.SKIPPED, Verdict.CLEAN, 0,
                 cache=True, rep=signed_rep("Contoso Ltd"),
                 yara=Status.SKIPPED,
                 yara_detail="Skipped: YARA disabled in settings"),
    ]
    for row in rows:
        window._add_result_row(row)  # noqa: SLF001

    window._refresh_stats()  # noqa: SLF001
    window.set_quota(4870)
    window._set_status("Watching C:\\Users\\User\\Downloads for new files")  # noqa: SLF001
    app.processEvents()

    out = Path(__file__).resolve().parent.parent / "screenshot_main.png"
    window.grab().save(str(out))
    print(f"saved {out} ({out.stat().st_size} bytes), rows={window.table.rowCount()}")

    # -- quarantine dialog ------------------------------------------------ #
    with tempfile.TemporaryDirectory(prefix="qpreview_") as raw:
        tmp = Path(raw)
        db = ScanDatabase(tmp / "preview.db")
        mgr = QuarantineManager(db, tmp / "Quarantine")
        try:
            samples = [
                ("invoice_2026.pdf.exe", b"x" * 184_320, "Trojan:Win32/Emotet"),
                ("crack_tool.zip", b"y" * 9_204_416, "Ransom:Win32/LockBit"),
                ("keygen.exe", b"z" * 655_360, "PUA:Win32/Keygen"),
            ]
            for name, blob, threat in samples:
                p = tmp / name
                p.write_bytes(blob)
                from scanner.engine import compute_sha256
                mgr.quarantine(p, sha256=compute_sha256(p), threat_detail=threat)

            dialog = QuarantineDialog(mgr, window)
            dialog.resize(940, 560)
            dialog.show()
            app.processEvents()
            qout = Path(__file__).resolve().parent.parent / "screenshot_quarantine.png"
            dialog.grab().save(str(qout))
            print(f"saved {qout} ({qout.stat().st_size} bytes), "
                  f"rows={dialog.table.rowCount()}")
            dialog.close()
        finally:
            db.close()

    window._shutdown()  # noqa: SLF001
    return 0


if __name__ == "__main__":
    sys.exit(main())
