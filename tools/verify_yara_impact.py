"""What does a YARA Suspicious hit actually do to a legitimate file?

Medium and low severity map to Suspicious, not Malicious, so a hit at that
level must never quarantine. This proves the end-to-end consequence.

Two halves:

1. A signed system DLL that legitimately schedules tasks (RCoInstII64.dll,
   the Realtek audio installer) must now come back Clean. It used to trip
   Scheduled_Task_Persistence; the rule now requires a recurrence or SYSTEM,
   which an installer registering its own task does not have.
2. A file that genuinely trips a medium-severity rule is Suspicious, stays on
   disk, and is not quarantined - while a critical hit is quarantined and
   leaves disk.

Run:  python tools\\verify_yara_impact.py
"""

from __future__ import annotations

import sys
import tempfile
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from scanner.config import Settings  # noqa: E402
from scanner.database import ScanDatabase  # noqa: E402
from scanner.engine import ScanEngine, Status, Verdict  # noqa: E402

PASS = 0
FAIL = 0


def check(label: str, ok: bool, detail: str = "") -> None:
    global PASS, FAIL
    if ok:
        PASS += 1
        print(f"  PASS  {label}")
    else:
        FAIL += 1
        print(f"  FAIL  {label}" + (f"\n        {detail}" if detail else ""))


tmp = Path(tempfile.mkdtemp(prefix="hs_impact_"))
settings = Settings(tmp / "settings.json")
settings.set("auto_quarantine", True)   # the dangerous setting
settings.set("cache_ttl_hours", 0)
engine = ScanEngine(settings, ScanDatabase(tmp / "db.sqlite"))

print("\nA signed system DLL that legitimately schedules tasks")
target = Path(r"C:\Windows\System32\RCoInstII64.dll")
if not target.exists():
    print("  (target not present on this machine; skipping)")
else:
    before = target.exists()
    result = engine.scan_file(target, source="test", use_cache=False)
    print(f"        yara={result.yara.status.value} "
          f"({result.yara.detail[:70]})")
    print(f"        verdict={result.verdict.value} score={result.score} "
          f"quarantined={result.quarantined}")

    check("YARA reports Clean, not Suspicious",
          result.yara.status is Status.CLEAN, result.yara.status.value)
    check("overall verdict is not Malicious",
          result.verdict is not Verdict.MALICIOUS, result.verdict.value)
    check("the file was NOT quarantined", not result.quarantined)
    check("the file is still on disk", target.exists() and before)

print("\nA medium-severity hit is Suspicious and stays on disk")
suspicious = tmp / "sandbox_check.txt"
suspicious.write_bytes(
    b"if (IsDebuggerPresent()) exit(0); "
    b"if (GetModuleHandle(\"VBoxService\")) exit(0);"
)
result1 = engine.scan_file(suspicious, source="test", use_cache=False)
print(f"        yara={result1.yara.status.value} "
      f"verdict={result1.verdict.value} quarantined={result1.quarantined}")
check("medium rule -> YARA Suspicious",
      result1.yara.status is Status.SUSPICIOUS, result1.yara.status.value)
check("medium rule -> verdict is not Malicious",
      result1.verdict is not Verdict.MALICIOUS, result1.verdict.value)
check("medium rule -> NOT quarantined", not result1.quarantined)
check("medium rule -> file still on disk", suspicious.exists())

print("\nA genuinely malicious file still gets quarantined")
hostile = tmp / "note.txt"
hostile.write_bytes(
    b"All your files are encrypted. To decrypt your files send bitcoin."
)
result2 = engine.scan_file(hostile, source="test", use_cache=False)
print(f"        yara={result2.yara.status.value} verdict={result2.verdict.value} "
      f"quarantined={result2.quarantined}")
check("critical rule -> Malicious", result2.verdict is Verdict.MALICIOUS,
      result2.verdict.value)
check("malicious file is quarantined", result2.quarantined)
check("malicious file left disk", not hostile.exists())

print("\n" + "=" * 60)
print(f"PASSED: {PASS}   FAILED: {FAIL}")
print("=" * 60)
sys.exit(0 if FAIL == 0 else 1)
