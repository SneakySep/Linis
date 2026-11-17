"""Prove AMSI works and measure it against the Defender CLI.

Development helper. Creates the EICAR test string (the industry-standard
antivirus test file - harmless by design, every engine flags it) and scans it
both ways.

Run:  python tools/verify_amsi.py
"""

from __future__ import annotations

import sys
import tempfile
import time
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from scanner.amsi import AmsiLayer                      # noqa: E402
from scanner.config import Settings                     # noqa: E402
from scanner.engine import DefenderLayer                # noqa: E402

# The EICAR antivirus test string, assembled so this source file does not
# itself trip a scanner.
EICAR = (
    r"X5O!P%@AP[4\PZX54(P^)7CC)7}$EICAR-STANDARD-ANTIVIRUS-TEST-FILE!$H+H*"
)


def main() -> int:
    print("AMSI verification")
    print("=" * 60)

    amsi = AmsiLayer()
    probe = amsi.probe()
    print(f"AMSI available : {probe.available}")
    print(f"AMSI detail    : {probe.detail}")
    if not probe.available:
        print("\nAMSI is not usable here; nothing further to test.")
        return 1

    with tempfile.TemporaryDirectory(prefix="amsi_verify_") as raw:
        tmp = Path(raw)

        clean = tmp / "clean.txt"
        clean.write_text("This is an ordinary harmless text file.\n" * 20,
                         encoding="utf-8")

        eicar = tmp / "eicar.com"
        eicar.write_text(EICAR, encoding="ascii")

        # -- clean file ---------------------------------------------------- #
        t0 = time.perf_counter()
        clean_verdict = amsi.scan(clean)
        clean_ms = (time.perf_counter() - t0) * 1000
        print(f"\nclean.txt   -> detected={clean_verdict.detected} "
              f"code={clean_verdict.result_code} in {clean_ms:.1f} ms")
        print(f"               {clean_verdict.detail}")

        # -- EICAR --------------------------------------------------------- #
        t0 = time.perf_counter()
        eicar_verdict = amsi.scan(eicar)
        eicar_ms = (time.perf_counter() - t0) * 1000
        print(f"\neicar.com   -> detected={eicar_verdict.detected} "
              f"code={eicar_verdict.result_code} in {eicar_ms:.1f} ms")
        print(f"               {eicar_verdict.detail}")

        # -- CLI comparison ------------------------------------------------ #
        settings = Settings()
        defender = DefenderLayer(settings)
        if defender.available():
            t0 = time.perf_counter()
            cli_clean = defender.scan(str(clean))
            cli_clean_ms = (time.perf_counter() - t0) * 1000
            print(f"\nDefender CLI on clean.txt -> {cli_clean.status.value} "
                  f"in {cli_clean_ms:.0f} ms")

            t0 = time.perf_counter()
            cli_eicar = defender.scan(str(eicar))
            cli_eicar_ms = (time.perf_counter() - t0) * 1000
            print(f"Defender CLI on eicar.com -> {cli_eicar.status.value} "
                  f"in {cli_eicar_ms:.0f} ms")
            print(f"               {cli_eicar.detail}")

            if cli_clean_ms > 0 and clean_ms > 0:
                print(f"\nSpeed: AMSI is {cli_clean_ms / clean_ms:.0f}x faster "
                      f"per clean file ({clean_ms:.1f} ms vs {cli_clean_ms:.0f} ms)")
        else:
            print("\nDefender CLI not available for comparison.")

    print("\n" + "=" * 60)
    ok = eicar_verdict.detected and not clean_verdict.detected
    print("RESULT:", "AMSI detects EICAR and clears a clean file"
          if ok else "UNEXPECTED - see output above")
    return 0 if ok else 1


if __name__ == "__main__":
    sys.exit(main())
