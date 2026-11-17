"""Sweep the built-in YARA corpus over real files on this machine.

The calibration in verify_yara_fp.py uses content I constructed. This tool uses
content I did not: actual binaries and data files installed on this Windows
machine. That is the only way to get a real false-positive rate.

It runs the rule set directly rather than through ScanEngine, because the engine
would also run Defender on every file - minutes per thousand files, and the
question here is only about the rules.

Usage:
    python tools\\sweep_yara.py [--limit N] [--workers N] [--dirs DIR [DIR ...]]
                                [--ext .exe .dll] [--json out.json]

Defaults to a stratified sample across System32, SysWOW64 and Program Files.
"""

from __future__ import annotations

import argparse
import json
import os
import random
import sys
import time
from collections import Counter, defaultdict
from concurrent.futures import ProcessPoolExecutor
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

YARA_MAX_BYTES = 32 * 1024 * 1024

DEFAULT_DIRS = [
    r"C:\Windows\System32",
    r"C:\Windows\SysWOW64",
    r"C:\Program Files",
    r"C:\Program Files (x86)",
]

# Directories that are noise for this purpose: caches, uninstallers, logs.
SKIP_PARTS = {
    "installer", "installers", "cache", "caches", "temp", "tmp",
    "logs", "log", "__pycache__", "node_modules", ".git",
}

# Rules whose hits are *expected* on ordinary software and therefore need
# individual judgement rather than a blanket pass/fail.
EXPECTED_ON_SOFTWARE = {
    "UPX_Packed",              # real installers are legitimately UPX-packed
    "Suspicious_Base64_Blob",  # embedded assets
    "Anti_Analysis_Checks",    # debug builds reference debugger APIs
    "Process_Injection_APIs",  # debuggers, AV, EDR all use these APIs
    "Cryptominer_Indicators",
    "Tor_Onion_Reference",
    "Credential_Phishing_Form",
    "Webshell_Indicators",
}

_rules = None


def _load_rules():
    """Compile once per worker process."""
    global _rules
    if _rules is None:
        from scanner.yara_engine import compile_directory

        rules_dir = Path(__file__).resolve().parent.parent / "scanner" / "rules"
        _rules = compile_directory(rules_dir)
    return _rules


def scan_one(path: str) -> dict | None:
    """Match the rules against one file. Returns None when unreadable."""
    try:
        size = os.path.getsize(path)
    except OSError:
        return None
    if size == 0:
        return None

    try:
        with open(path, "rb") as handle:
            data = handle.read(YARA_MAX_BYTES)
    except OSError:
        return None

    rules = _load_rules()
    try:
        matches = rules.match(data, os.path.basename(path))
    except Exception as exc:  # a rule must never kill the sweep
        return {"path": path, "error": f"{type(exc).__name__}: {exc}"}

    if not matches:
        return None

    return {
        "path": path,
        "size": size,
        "truncated": size > len(data),
        "matches": [
            {
                "rule": m.rule,
                "severity": m.severity,
                "description": m.description,
                "strings": dict(m.matched_strings),
            }
            for m in matches
        ],
    }


def collect(dirs: list[str], limit: int, exts: set[str] | None) -> list[str]:
    """Gather candidate files, stratified across the given roots."""
    per_dir = max(1, limit // max(1, len(dirs)))
    chosen: list[str] = []

    for root in dirs:
        if not os.path.isdir(root):
            print(f"  (skipping missing {root})")
            continue
        found: list[str] = []
        for dirpath, dirnames, filenames in os.walk(root, onerror=lambda e: None):
            dirnames[:] = [
                d for d in dirnames
                if d.lower() not in SKIP_PARTS and not d.startswith("$")
            ]
            for name in filenames:
                if exts is not None and Path(name).suffix.lower() not in exts:
                    continue
                found.append(os.path.join(dirpath, name))
                if len(found) >= per_dir * 6:
                    break
            if len(found) >= per_dir * 6:
                break
        random.shuffle(found)
        take = found[:per_dir]
        chosen.extend(take)
        print(f"  {root}: {len(take):,} sampled")

    return chosen


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--limit", type=int, default=4000,
                        help="total files to scan (default 4000)")
    parser.add_argument("--workers", type=int, default=max(1, (os.cpu_count() or 4) - 1))
    parser.add_argument("--dirs", nargs="+", default=DEFAULT_DIRS)
    parser.add_argument("--ext", nargs="+", default=None,
                        help="restrict to these extensions, e.g. .exe .dll")
    parser.add_argument("--json", default="")
    parser.add_argument("--seed", type=int, default=20261117)
    args = parser.parse_args()

    random.seed(args.seed)
    exts = {e.lower() if e.startswith(".") else "." + e.lower()
            for e in args.ext} if args.ext else None

    print(f"\nCollecting files (limit {args.limit:,}, "
          f"exts={sorted(exts) if exts else 'all'})")
    files = collect(args.dirs, args.limit, exts)
    print(f"\nScanning {len(files):,} files with {args.workers} workers...")

    started = time.perf_counter()
    hits: list[dict] = []
    errors: list[dict] = []
    done = 0

    with ProcessPoolExecutor(max_workers=args.workers) as pool:
        for result in pool.map(scan_one, files, chunksize=32):
            done += 1
            if result is None:
                continue
            if "error" in result:
                errors.append(result)
                continue
            hits.append(result)
            if done % 500 == 0:
                print(f"  {done:,}/{len(files):,} ... {len(hits)} hit(s)")

    elapsed = time.perf_counter() - started

    # ---- report ---------------------------------------------------------- #
    rule_counts: Counter[str] = Counter()
    by_rule: defaultdict[str, list[dict]] = defaultdict(list)
    for hit in hits:
        for match in hit["matches"]:
            rule_counts[match["rule"]] += 1
            by_rule[match["rule"]].append(hit)

    print("\n" + "=" * 72)
    print(f"Scanned {len(files):,} files in {elapsed:.1f}s "
          f"({len(files) / max(elapsed, 0.001):.0f} files/s)")
    print(f"Files with at least one hit: {len(hits):,} "
          f"({100 * len(hits) / max(len(files), 1):.2f}%)")
    print(f"Read errors: {len(errors)}")
    print("=" * 72)

    if not rule_counts:
        print("\nNo rule fired on any sampled file.")
    else:
        print("\nHits by rule:")
        for rule, count in rule_counts.most_common():
            expected = "  [expected on software]" if rule in EXPECTED_ON_SOFTWARE else ""
            print(f"  {count:6,}  {rule}{expected}")

        print("\nSample hits per rule (up to 3):")
        for rule, count in rule_counts.most_common():
            print(f"\n  {rule}  ({count:,} files)")
            for hit in by_rule[rule][:3]:
                strings = ", ".join(sorted(hit["matches"][0]["strings"])[:5])
                print(f"    {hit['path']}")
                print(f"      matched: {strings}")

    if errors:
        print(f"\nErrors ({len(errors)}):")
        for err in errors[:5]:
            print(f"  {err['path']}: {err['error']}")

    if args.json:
        Path(args.json).write_text(
            json.dumps(
                {
                    "scanned": len(files),
                    "elapsed_s": round(elapsed, 2),
                    "hits": hits,
                    "errors": errors,
                    "rule_counts": dict(rule_counts),
                },
                indent=2,
            ),
            encoding="utf-8",
        )
        print(f"\nWrote {args.json}")

    return 0


if __name__ == "__main__":
    sys.exit(main())
