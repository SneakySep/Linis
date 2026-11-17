"""Three-layer hybrid scanning engine.

Design contract
---------------
1. Hash the file locally in 64 KiB chunks. Nothing but the SHA-256 ever leaves
   the machine. Raw file bytes are never uploaded to any provider.
2. Consult the local SQLite cache. A hit younger than the TTL returns the
   stored verdict immediately and spends zero API quota.
3. Otherwise run the three layers in order of cost:

   Layer 1 - Windows Defender CLI (free, local, authoritative for the machine)
   Layer 2 - MalwareBazaar (hash reputation, needs Auth-Key)
   Layer 3 - OPSWAT MetaDefender Cloud (multi-engine hash lookup, needs apikey)

Layers 2 and 3 short-circuit when Layer 1 already proves the file malicious:
there is nothing to add to a positive local detection, and skipping them
preserves quota.

Every layer is independently failable. A missing API key, a network error or a
provider outage degrades that one column to "Skipped"/"Error" and the scan
still completes with a defensible overall verdict.
"""

from __future__ import annotations

import hashlib
import logging
import os
import re
import subprocess
import sys
import time
from dataclasses import dataclass, field
from enum import Enum
from pathlib import Path
from typing import Any, BinaryIO, Callable, Iterable

import httpx

from .config import Settings, settings as default_settings
from .database import CachedResult, ScanDatabase
from .amsi import AmsiLayer
from .quarantine import FileAlreadyHandled, QuarantineError, QuarantineManager
from .reputation import ReputationAssessment, assess as assess_reputation, should_deep_scan
from .yara_engine import RuleSet, YaraError, compile_directory

log = logging.getLogger(__name__)

CHUNK_SIZE = 64 * 1024  # 64 KiB, per spec

MB_ENDPOINT = "https://mb-api.abuse.ch/api/v1/"
OPSWAT_ENDPOINT = "https://api.metadefender.com/v4/hash/{sha256}"

DEFAULT_DEFENDER_PATH = r"C:\Program Files\Windows Defender\MpCmdRun.exe"


# --------------------------------------------------------------------------- #
# Status vocabulary
# --------------------------------------------------------------------------- #

class Status(str, Enum):
    """Per-layer outcome. Values are the exact strings shown in the UI."""

    CLEAN = "Clean"
    MALICIOUS = "Malicious"
    SUSPICIOUS = "Suspicious"
    UNKNOWN = "Unknown"
    NOT_FOUND = "Not Found"
    SKIPPED = "Skipped"
    ERROR = "Error"
    SCANNING = "Scanning"

    @classmethod
    def coerce(cls, value: Any) -> "Status":
        if isinstance(value, cls):
            return value
        text = str(value or "").strip().lower()
        for member in cls:
            if member.value.lower() == text or member.name.lower() == text:
                return member
        return cls.UNKNOWN


class Verdict(str, Enum):
    """Overall verdict for a file."""

    MALICIOUS = "Malicious"
    SUSPICIOUS = "Suspicious"
    CLEAN = "Clean"
    UNKNOWN = "Unknown"
    ERROR = "Error"

    @classmethod
    def coerce(cls, value: Any) -> "Verdict":
        if isinstance(value, cls):
            return value
        text = str(value or "").strip().lower()
        for member in cls:
            if member.value.lower() == text or member.name.lower() == text:
                return member
        return cls.UNKNOWN


# --------------------------------------------------------------------------- #
# Result containers
# --------------------------------------------------------------------------- #

@dataclass
class LayerResult:
    """Outcome of a single detection layer."""

    status: Status = Status.UNKNOWN
    detail: str = ""
    raw: dict[str, Any] = field(default_factory=dict)
    elapsed_ms: int = 0

    @property
    def is_malicious(self) -> bool:
        return self.status is Status.MALICIOUS


@dataclass
class ScanResult:
    """Full result of scanning one file."""

    file_path: str
    file_name: str
    file_size: int
    sha256: str
    scanned_at: float
    defender: LayerResult = field(default_factory=LayerResult)
    amsi: LayerResult = field(default_factory=LayerResult)
    yara: LayerResult = field(default_factory=LayerResult)
    malwarebazaar: LayerResult = field(default_factory=LayerResult)
    opswat: LayerResult = field(default_factory=LayerResult)
    verdict: Verdict = Verdict.UNKNOWN
    score: int = 0
    from_cache: bool = False
    error: str = ""
    opswat_quota_remaining: int | None = None
    quarantined: bool = False
    quarantine_id: int | None = None
    quarantine_path: str = ""
    quarantine_error: str = ""
    reputation: ReputationAssessment | None = None

    @property
    def is_malicious(self) -> bool:
        return self.verdict is Verdict.MALICIOUS

    @property
    def timestamp_text(self) -> str:
        return time.strftime("%Y-%m-%d %H:%M:%S", time.localtime(self.scanned_at))

    def details(self) -> dict[str, Any]:
        """Serialisable evidence blob stored alongside the verdict."""
        return {
            "defender": {"status": self.defender.status.value, "detail": self.defender.detail,
                         "raw": self.defender.raw},
            "amsi": {"status": self.amsi.status.value, "detail": self.amsi.detail,
                     "raw": self.amsi.raw},
            "yara": {"status": self.yara.status.value, "detail": self.yara.detail,
                     "raw": self.yara.raw},
            "malwarebazaar": {"status": self.malwarebazaar.status.value,
                              "detail": self.malwarebazaar.detail,
                              "raw": self.malwarebazaar.raw},
            "opswat": {"status": self.opswat.status.value, "detail": self.opswat.detail,
                       "raw": self.opswat.raw},
            "error": self.error,
            "quarantined": self.quarantined,
            "quarantine_id": self.quarantine_id,
            "quarantine_path": self.quarantine_path,
            "reputation": self._reputation_blob(),
        }

    def _reputation_blob(self) -> dict[str, Any]:
        rep = self.reputation
        if rep is None:
            return {}
        return {
            "risk": rep.risk,
            "flags": list(rep.flags),
            "motw": {
                "present": rep.motw.present,
                "zone_id": rep.motw.zone_id,
                "zone_label": rep.motw.zone_label,
                "host_url": rep.motw.host_url,
                "referrer_url": rep.motw.referrer_url,
            },
            "signature": {
                "status": rep.signature.status.value,
                "signer": rep.signature.signer,
                "via_catalog": rep.signature.via_catalog,
                "error": rep.signature.error,
            },
            "pe": {
                "is_pe": rep.pe.is_pe,
                "machine": rep.pe.machine,
                "subsystem": rep.pe.subsystem,
                "max_entropy": round(rep.pe.max_entropy, 3),
                "is_packed": rep.pe.is_packed,
                "suspicious_apis": list(rep.pe.suspicious_apis),
                "has_injection_triad": rep.pe.has_injection_triad,
                "has_no_imports": rep.pe.has_no_imports,
                "error": rep.pe.error,
            },
        }

    @staticmethod
    def _reputation_from_blob(blob: dict[str, Any]) -> ReputationAssessment | None:
        if not blob:
            return None
        from .reputation import (
            MotwInfo,
            PeInfo,
            ReputationAssessment,
            SignatureInfo,
            SignatureStatus,
        )

        motw_blob = blob.get("motw") or {}
        sig_blob = blob.get("signature") or {}
        pe_blob = blob.get("pe") or {}

        return ReputationAssessment(
            motw=MotwInfo(
                present=bool(motw_blob.get("present")),
                zone_id=motw_blob.get("zone_id"),
                host_url=str(motw_blob.get("host_url") or ""),
                referrer_url=str(motw_blob.get("referrer_url") or ""),
            ),
            signature=SignatureInfo(
                status=SignatureStatus(sig_blob.get("status", "Unknown"))
                if sig_blob.get("status") in {s.value for s in SignatureStatus}
                else SignatureStatus.UNKNOWN,
                signer=str(sig_blob.get("signer") or ""),
                via_catalog=bool(sig_blob.get("via_catalog")),
                error=str(sig_blob.get("error") or ""),
            ),
            pe=PeInfo(
                is_pe=bool(pe_blob.get("is_pe")),
                machine=str(pe_blob.get("machine") or ""),
                subsystem=str(pe_blob.get("subsystem") or ""),
                max_entropy=float(pe_blob.get("max_entropy") or 0.0),
                suspicious_apis=list(pe_blob.get("suspicious_apis") or []),
                has_injection_triad=bool(pe_blob.get("has_injection_triad")),
                error=str(pe_blob.get("error") or ""),
            ),
            risk=int(blob.get("risk") or 0),
            flags=list(blob.get("flags") or []),
        )

    def to_cached(self) -> CachedResult:
        return CachedResult(
            sha256=self.sha256,
            file_name=self.file_name,
            file_size=self.file_size,
            scanned_at=self.scanned_at,
            defender_status=self.defender.status.value,
            amsi_status=self.amsi.status.value,
            yara_status=self.yara.status.value,
            mb_status=self.malwarebazaar.status.value,
            opswat_status=self.opswat.status.value,
            verdict=self.verdict.value,
            score=self.score,
            details=self.details(),
        )

    @classmethod
    def from_cached(cls, cached: CachedResult, file_path: str) -> "ScanResult":
        details = cached.details or {}

        def layer(key: str) -> LayerResult:
            blob = details.get(key) or {}
            return LayerResult(
                status=Status.coerce(blob.get("status", "Unknown")),
                detail=str(blob.get("detail", "")),
                raw=blob.get("raw") or {},
            )

        return cls(
            file_path=file_path,
            file_name=cached.file_name or Path(file_path).name,
            file_size=cached.file_size,
            sha256=cached.sha256,
            scanned_at=cached.scanned_at,
            defender=layer("defender"),
            amsi=layer("amsi"),
            yara=layer("yara"),
            malwarebazaar=layer("malwarebazaar"),
            opswat=layer("opswat"),
            verdict=Verdict.coerce(cached.verdict),
            score=cached.score,
            from_cache=True,
            error=str(details.get("error", "")),
            quarantined=bool(details.get("quarantined", False)),
            quarantine_id=details.get("quarantine_id"),
            quarantine_path=str(details.get("quarantine_path", "") or ""),
            reputation=cls._reputation_from_blob(details.get("reputation") or {}),
        )


# --------------------------------------------------------------------------- #
# Hashing
# --------------------------------------------------------------------------- #

def compute_sha256(path: str | Path, chunk_size: int = CHUNK_SIZE,
                   cancel: Callable[[], bool] | None = None) -> str:
    """Hash a file in fixed-size chunks.

    Chunked reading keeps memory flat regardless of file size, so a 20 GB
    installer costs the same RAM as a 20 KB text file.
    """
    digest = hashlib.sha256()
    with open(path, "rb") as handle:
        while True:
            if cancel is not None and cancel():
                raise ScanCancelled("Hash computation cancelled")
            block = handle.read(chunk_size)
            if not block:
                break
            digest.update(block)
    return digest.hexdigest()


class ScanCancelled(Exception):
    """Raised when a scan is cancelled by the user."""


class FileBlockedByAntivirus(OSError):
    """The OS refused to open the file because antivirus has flagged it.

    Windows returns ``ERROR_VIRUS_INFECTED`` (225) from ``CreateFileW``, and
    ``ERROR_BAD_COMMAND`` (22) from a plain read, when the AV provider has
    quarantined or is blocking a file. The file's metadata still exists, so a
    naive ``is_file()`` check passes and the open then fails.

    This is a *detection*, not an operational error. Reporting it as "Error:
    cannot open file" would be a false negative on exactly the files that
    matter most, so it is surfaced as its own exception and converted to a
    Malicious verdict by the engine.
    """

    def __init__(self, message: str, errno_code: int = 0) -> None:
        super().__init__(errno_code, message)
        self.errno_code = errno_code


# Windows error codes that mean "antivirus is blocking this file".
_AV_BLOCK_ERRNOS = frozenset({
    22,    # ERROR_BAD_COMMAND - seen from a plain read on a quarantined file
    32,    # ERROR_SHARING_VIOLATION
    33,    # ERROR_LOCK_VIOLATION
    225,   # ERROR_VIRUS_INFECTED - the definitive one
})


def _is_av_block(exc: OSError) -> bool:
    """True when an OSError means antivirus blocked the file."""
    winerror = getattr(exc, "winerror", None)
    if winerror in _AV_BLOCK_ERRNOS:
        return True
    return getattr(exc, "errno", None) in _AV_BLOCK_ERRNOS


# --------------------------------------------------------------------------- #
# Locked file access - the TOCTOU defence
# --------------------------------------------------------------------------- #

_GENERIC_READ = 0x80000000
_FILE_SHARE_READ = 0x00000001   # allow readers, deny writers and deleters
_OPEN_EXISTING = 3
_FILE_ATTRIBUTE_NORMAL = 0x80


class LockedFile:
    """A file held open for the whole scan, with writes and deletes denied.

    Why this exists
    ---------------
    Hashing a path and then handing that same path to Defender is a
    time-of-check/time-of-use race: between the two calls the path can be
    repointed at different bytes, so the hash that gets cached describes a file
    Defender never inspected. An attacker with a local write primitive wins that
    race every time, and the cache then serves a Clean verdict for a hash that
    never matched the scanned content.

    Holding a handle with ``dwShareMode = FILE_SHARE_READ`` closes it. While the
    handle is open:

      * other processes may still READ the file (Defender needs to),
      * no process may WRITE it, and
      * no process may DELETE or RENAME it, so the path cannot be repointed.

    The hash and the Defender scan therefore provably describe the same bytes.
    A re-hash from the same handle after the scan is kept as a cheap
    belt-and-braces check for filesystems that ignore share modes (some network
    shares and FUSE mounts do).
    """

    def __init__(self, path: str | Path) -> None:
        self.path = str(path)
        self._file: BinaryIO | None = None
        self._size = 0
        self._stat_key: tuple[int, int] | None = None

    def __enter__(self) -> "LockedFile":
        self._open()
        return self

    def __exit__(self, *exc_info: object) -> None:
        self.close()

    # -- opening ----------------------------------------------------------- #

    def _open(self) -> None:
        if sys.platform == "win32":
            self._open_windows()
        else:
            self._file = open(self.path, "rb")
        assert self._file is not None
        st = os.fstat(self._file.fileno())
        self._size = st.st_size
        self._stat_key = (st.st_size, st.st_mtime_ns)

    def _open_windows(self) -> None:
        import ctypes
        import msvcrt
        from ctypes import wintypes

        kernel32 = ctypes.WinDLL("kernel32", use_last_error=True)
        kernel32.CreateFileW.restype = wintypes.HANDLE
        kernel32.CreateFileW.argtypes = [
            wintypes.LPCWSTR,   # lpFileName
            wintypes.DWORD,     # dwDesiredAccess
            wintypes.DWORD,     # dwShareMode
            wintypes.LPVOID,    # lpSecurityAttributes
            wintypes.DWORD,     # dwCreationDisposition
            wintypes.DWORD,     # dwFlagsAndAttributes
            wintypes.HANDLE,    # hTemplateFile
        ]
        kernel32.CloseHandle.argtypes = [wintypes.HANDLE]

        handle = kernel32.CreateFileW(
            self.path,
            _GENERIC_READ,
            _FILE_SHARE_READ,       # readers yes, writers and deleters no
            None,
            _OPEN_EXISTING,
            _FILE_ATTRIBUTE_NORMAL,
            None,
        )
        invalid = wintypes.HANDLE(-1).value
        if handle == invalid or handle is None:
            err = ctypes.get_last_error()
            if err in _AV_BLOCK_ERRNOS:
                raise FileBlockedByAntivirus(
                    f"Antivirus is blocking {self.path} (Windows error {err})",
                    err,
                )
            raise OSError(err, f"Cannot open {self.path} for scanning", self.path)

        try:
            fd = msvcrt.open_osfhandle(handle, os.O_RDONLY | os.O_BINARY)
        except OSError:
            kernel32.CloseHandle(handle)
            raise
        # os.fdopen takes ownership of the fd, and closing it closes the handle.
        self._file = os.fdopen(fd, "rb")

    # -- use --------------------------------------------------------------- #

    @property
    def size(self) -> int:
        return self._size

    def sha256(self, chunk_size: int = CHUNK_SIZE,
               cancel: Callable[[], bool] | None = None) -> str:
        """Hash the open handle from the beginning."""
        if self._file is None:
            raise OSError("File handle is not open")
        self._file.seek(0)
        digest = hashlib.sha256()
        while True:
            if cancel is not None and cancel():
                raise ScanCancelled("Hash computation cancelled")
            block = self._file.read(chunk_size)
            if not block:
                break
            digest.update(block)
        return digest.hexdigest()

    def unchanged(self) -> bool:
        """True when size and mtime still match what was opened."""
        if self._file is None or self._stat_key is None:
            return False
        try:
            st = os.fstat(self._file.fileno())
        except OSError:
            return False
        return (st.st_size, st.st_mtime_ns) == self._stat_key

    def read_all(self, limit: int, cancel: Callable[[], bool] | None = None) -> bytes:
        """Read up to ``limit`` bytes from the open handle.

        Used by the YARA layer so it inspects the same bytes that were hashed,
        under the same write-denying handle. Reading through the handle rather
        than re-opening the path is what makes the rule verdict describe the
        hashed content instead of whatever the path points at now.
        """
        if self._file is None:
            raise OSError("File handle is not open")
        self._file.seek(0)
        chunks: list[bytes] = []
        remaining = limit
        while remaining > 0:
            if cancel is not None and cancel():
                raise ScanCancelled("YARA read cancelled")
            block = self._file.read(min(CHUNK_SIZE, remaining))
            if not block:
                break
            chunks.append(block)
            remaining -= len(block)
        return b"".join(chunks)

    def close(self) -> None:
        if self._file is not None:
            try:
                self._file.close()
            finally:
                self._file = None


# --------------------------------------------------------------------------- #
# Layer 1 - Windows Defender CLI
# --------------------------------------------------------------------------- #

class DefenderLayer:
    """Wraps ``MpCmdRun.exe -Scan -ScanType 3 -File <path>``.

    Exit code contract (documented by Microsoft):
        0 -> no threat found
        2 -> threat found
    Anything else is an operational error (Defender disabled, path missing,
    policy block, timeout) and is reported as Error rather than Clean. This
    matters: treating a failed Defender run as "clean" would silently produce
    a false negative.
    """

    def __init__(self, settings: Settings) -> None:
        self._settings = settings

    def _exe(self) -> str:
        configured = str(self._settings.get("defender_path") or "").strip()
        if configured and Path(configured).is_file():
            return configured
        if Path(DEFAULT_DEFENDER_PATH).is_file():
            return DEFAULT_DEFENDER_PATH
        return ""

    def available(self) -> bool:
        return bool(self._exe())

    def scan(self, path: str, cancel: Callable[[], bool] | None = None) -> LayerResult:
        started = time.perf_counter()
        exe = self._exe()
        if not exe:
            return LayerResult(
                status=Status.SKIPPED,
                detail="MpCmdRun.exe not found; Windows Defender layer unavailable",
                elapsed_ms=_ms(started),
            )
        if cancel is not None and cancel():
            raise ScanCancelled("Cancelled before Defender scan")

        timeout = int(self._settings.get("defender_timeout_seconds") or 300)
        cmd = [exe, "-Scan", "-ScanType", "3", "-File", path, "-DisableRemediation"]

        try:
            proc = subprocess.run(
                cmd,
                capture_output=True,
                timeout=timeout,
                check=False,
                creationflags=getattr(subprocess, "CREATE_NO_WINDOW", 0),
            )
        except subprocess.TimeoutExpired:
            return LayerResult(
                status=Status.ERROR,
                detail=f"Defender scan timed out after {timeout}s",
                elapsed_ms=_ms(started),
            )
        except OSError as exc:
            return LayerResult(
                status=Status.ERROR,
                detail=f"Could not launch Defender: {exc}",
                elapsed_ms=_ms(started),
            )

        output = _decode(proc.stdout) + "\n" + _decode(proc.stderr)
        code = proc.returncode

        if code == 0:
            return LayerResult(
                status=Status.CLEAN,
                detail="No threats found",
                raw={"exit_code": code, "output": _tail(output)},
                elapsed_ms=_ms(started),
            )
        if code == 2:
            threat = _extract_threat_name(output)
            return LayerResult(
                status=Status.MALICIOUS,
                detail=threat or "Threat detected by Windows Defender",
                raw={"exit_code": code, "threat": threat, "output": _tail(output)},
                elapsed_ms=_ms(started),
            )
        return LayerResult(
            status=Status.ERROR,
            detail=f"Defender exited with code {code}",
            raw={"exit_code": code, "output": _tail(output)},
            elapsed_ms=_ms(started),
        )


_THREAT_RE = re.compile(
    r"(?:Threat\s+information|Threat\s+detected)[:\s]*(?P<name>[^\r\n]+)",
    re.IGNORECASE,
)
_THREAT_ALT_RE = re.compile(r"Name:\s*(?P<name>[^\r\n]+)", re.IGNORECASE)


def _extract_threat_name(output: str) -> str:
    """Pull a threat name out of MpCmdRun output.

    MpCmdRun prints a bordered table, so a naive ``Name:`` match can capture a
    row of dashes or a column header. Anything without at least one
    alphanumeric character is rejected.
    """
    for pattern in (_THREAT_RE, _THREAT_ALT_RE):
        for match in pattern.finditer(output):
            name = match.group("name").strip().strip("-|=_ ").strip()
            if not name:
                continue
            if not any(ch.isalnum() for ch in name):
                continue
            # Column headers are not threat names.
            if name.lower().rstrip(":") in {"name", "threat", "threat name",
                                             "threat information", "severity"}:
                continue
            return name
    return ""


# --------------------------------------------------------------------------- #
# Layer 2 - MalwareBazaar
# --------------------------------------------------------------------------- #

class MalwareBazaarLayer:
    """Hash reputation lookup against abuse.ch MalwareBazaar.

    Sends only the SHA-256. ``query_status`` values handled:
        ok             -> hash is a known malware sample
        hash_not_found -> hash is not in the corpus (not proof of clean)
        anything else  -> provider-side error
    """

    def __init__(self, settings: Settings, client: httpx.Client | None = None) -> None:
        self._settings = settings
        self._client = client

    def _key(self) -> str:
        return str(self._settings.get("mb_auth_key") or "").strip()

    def available(self) -> bool:
        return bool(self._key())

    def scan(self, sha256: str, cancel: Callable[[], bool] | None = None) -> LayerResult:
        started = time.perf_counter()
        key = self._key()
        if not key:
            return LayerResult(
                status=Status.SKIPPED,
                detail="No MalwareBazaar Auth-Key configured",
                elapsed_ms=_ms(started),
            )
        if cancel is not None and cancel():
            raise ScanCancelled("Cancelled before MalwareBazaar lookup")

        timeout = float(self._settings.get("http_timeout_seconds") or 20)
        headers = {"Auth-Key": key, "Accept": "application/json"}
        data = {"query": "get_info", "hash": sha256}

        try:
            client = self._client or httpx.Client(timeout=timeout)
            owned = self._client is None
            try:
                response = client.post(MB_ENDPOINT, headers=headers, data=data)
            finally:
                if owned:
                    client.close()
        except httpx.HTTPError as exc:
            return LayerResult(
                status=Status.ERROR,
                detail=f"MalwareBazaar request failed: {exc}",
                elapsed_ms=_ms(started),
            )

        if response.status_code == 401 or response.status_code == 403:
            return LayerResult(
                status=Status.ERROR,
                detail=f"MalwareBazaar rejected the Auth-Key (HTTP {response.status_code})",
                raw={"http_status": response.status_code},
                elapsed_ms=_ms(started),
            )
        if response.status_code >= 500:
            return LayerResult(
                status=Status.ERROR,
                detail=f"MalwareBazaar unavailable (HTTP {response.status_code})",
                raw={"http_status": response.status_code},
                elapsed_ms=_ms(started),
            )
        if response.status_code != 200:
            return LayerResult(
                status=Status.ERROR,
                detail=f"MalwareBazaar returned HTTP {response.status_code}",
                raw={"http_status": response.status_code},
                elapsed_ms=_ms(started),
            )

        try:
            payload = response.json()
        except ValueError:
            return LayerResult(
                status=Status.ERROR,
                detail="MalwareBazaar returned a non-JSON body",
                elapsed_ms=_ms(started),
            )

        query_status = str(payload.get("query_status") or "").lower()
        if query_status == "ok":
            samples = payload.get("data") or []
            first = samples[0] if isinstance(samples, list) and samples else {}
            signature = str(first.get("signature") or "").strip()
            tags = first.get("tags") or []
            file_type = str(first.get("file_type") or "").strip()
            bits = [b for b in (signature, file_type) if b]
            detail = "Known malware sample"
            if bits:
                detail += f": {', '.join(bits)}"
            if tags:
                detail += f" [{', '.join(str(t) for t in tags[:5])}]"
            return LayerResult(
                status=Status.MALICIOUS,
                detail=detail,
                raw={
                    "query_status": query_status,
                    "signature": signature,
                    "tags": tags,
                    "file_type": file_type,
                    "first_seen": first.get("first_seen"),
                    "delivery_method": first.get("delivery_method"),
                },
                elapsed_ms=_ms(started),
            )

        if query_status in {"hash_not_found", "no_results"}:
            return LayerResult(
                status=Status.NOT_FOUND,
                detail="Hash not present in MalwareBazaar corpus",
                raw={"query_status": query_status},
                elapsed_ms=_ms(started),
            )

        return LayerResult(
            status=Status.ERROR,
            detail=f"MalwareBazaar query_status={query_status or 'unknown'}",
            raw={"query_status": query_status},
            elapsed_ms=_ms(started),
        )


# --------------------------------------------------------------------------- #
# Layer 3 - OPSWAT MetaDefender Cloud
# --------------------------------------------------------------------------- #

class OpswatLayer:
    """Multi-engine hash lookup against MetaDefender Cloud.

    ``GET /v4/hash/{sha256}`` with the ``apikey`` header. A 404 means OPSWAT
    has never seen this hash, which is reported as "Not Found" - not clean.
    ``X-RateLimit-Remaining`` is read from the response headers so the UI can
    show the remaining daily quota.
    """

    def __init__(self, settings: Settings, client: httpx.Client | None = None) -> None:
        self._settings = settings
        self._client = client
        self.quota_remaining: int | None = None

    def _key(self) -> str:
        return str(self._settings.get("opswat_api_key") or "").strip()

    def available(self) -> bool:
        return bool(self._key())

    def scan(self, sha256: str, cancel: Callable[[], bool] | None = None) -> LayerResult:
        started = time.perf_counter()
        key = self._key()
        if not key:
            return LayerResult(
                status=Status.SKIPPED,
                detail="No OPSWAT API key configured",
                elapsed_ms=_ms(started),
            )
        if cancel is not None and cancel():
            raise ScanCancelled("Cancelled before MetaDefender lookup")

        timeout = float(self._settings.get("http_timeout_seconds") or 20)
        headers = {"apikey": key, "Accept": "application/json"}
        url = OPSWAT_ENDPOINT.format(sha256=sha256)

        try:
            client = self._client or httpx.Client(timeout=timeout)
            owned = self._client is None
            try:
                response = client.get(url, headers=headers)
            finally:
                if owned:
                    client.close()
        except httpx.HTTPError as exc:
            return LayerResult(
                status=Status.ERROR,
                detail=f"MetaDefender request failed: {exc}",
                elapsed_ms=_ms(started),
            )

        self._read_quota(response)

        if response.status_code == 404:
            return LayerResult(
                status=Status.NOT_FOUND,
                detail="Hash unknown to MetaDefender Cloud",
                raw={"http_status": 404},
                elapsed_ms=_ms(started),
            )
        if response.status_code in (401, 403):
            return LayerResult(
                status=Status.ERROR,
                detail=f"MetaDefender rejected the API key (HTTP {response.status_code})",
                raw={"http_status": response.status_code},
                elapsed_ms=_ms(started),
            )
        if response.status_code == 429:
            return LayerResult(
                status=Status.ERROR,
                detail="MetaDefender rate limit reached",
                raw={"http_status": 429, "quota_remaining": self.quota_remaining},
                elapsed_ms=_ms(started),
            )
        if response.status_code != 200:
            return LayerResult(
                status=Status.ERROR,
                detail=f"MetaDefender returned HTTP {response.status_code}",
                raw={"http_status": response.status_code},
                elapsed_ms=_ms(started),
            )

        try:
            payload = response.json()
        except ValueError:
            return LayerResult(
                status=Status.ERROR,
                detail="MetaDefender returned a non-JSON body",
                elapsed_ms=_ms(started),
            )

        results = payload.get("scan_results") or {}
        summary = str(results.get("scan_all_result_a") or "").strip()
        detected = _as_int(results.get("total_detected_avs"))
        total = _as_int(results.get("total_avs"))
        file_info = payload.get("file_info") or {}

        lowered = summary.lower()
        if "malicious" in lowered or "infected" in lowered or (detected or 0) > 0:
            detail = f"{detected}/{total} engines detected a threat" if total else (
                summary or "Threat detected"
            )
            return LayerResult(
                status=Status.MALICIOUS,
                detail=detail,
                raw={
                    "scan_all_result_a": summary,
                    "total_detected_avs": detected,
                    "total_avs": total,
                    "threat_name": results.get("scan_all_result_i"),
                    "file_type": file_info.get("file_type_description"),
                    "quota_remaining": self.quota_remaining,
                },
                elapsed_ms=_ms(started),
            )
        if "clean" in lowered or "no threat" in lowered:
            return LayerResult(
                status=Status.CLEAN,
                detail=f"0/{total} engines flagged" if total else "Clean",
                raw={"scan_all_result_a": summary, "total_avs": total,
                     "quota_remaining": self.quota_remaining},
                elapsed_ms=_ms(started),
            )
        if "suspicious" in lowered:
            return LayerResult(
                status=Status.SUSPICIOUS,
                detail=summary or "Suspicious",
                raw={"scan_all_result_a": summary, "quota_remaining": self.quota_remaining},
                elapsed_ms=_ms(started),
            )
        return LayerResult(
            status=Status.UNKNOWN,
            detail=summary or "MetaDefender returned no verdict",
            raw={"scan_all_result_a": summary, "quota_remaining": self.quota_remaining},
            elapsed_ms=_ms(started),
        )

    def _read_quota(self, response: httpx.Response) -> None:
        raw = response.headers.get("X-RateLimit-Remaining")
        if raw is None:
            return
        try:
            self.quota_remaining = int(str(raw).strip())
        except (TypeError, ValueError):
            return


# --------------------------------------------------------------------------- #
# Layer - YARA rules (local, content-based)
# --------------------------------------------------------------------------- #

# Scan cap. Rules are string matches, so a 2 GB installer would cost seconds of
# CPU for no extra signal. 32 MiB covers every realistic download and document;
# anything larger is reported as a partial scan rather than silently skipped.
YARA_MAX_BYTES = 32 * 1024 * 1024

# Rule severities that make a hit a hard detection rather than a caution.
_YARA_MALICIOUS = {"critical", "high"}


def default_rules_dir() -> Path:
    """Where the bundled rules live, in source and in a PyInstaller build."""
    bundled = Path(getattr(sys, "_MEIPASS", Path(__file__).resolve().parent.parent))
    return bundled / "scanner" / "rules"


class YaraLayer:
    """Runs the built-in YARA rule set against file content.

    Why this layer exists
    ---------------------
    Signature engines answer "is this exact file known bad?". They do not answer
    "does this file behave like ransomware / a credential dumper / a download
    cradle?". A brand-new sample has no hash reputation anywhere, so every
    cloud layer says Not Found and the file reads Clean. This layer is the one
    that can still say something useful about it.

    Severity mapping is deliberately conservative and one-directional, matching
    the reputation layer's contract: a ``critical``/``high`` rule is Malicious,
    a ``medium``/``low`` rule is Suspicious, and a miss is Clean. A rule hit can
    never lower a verdict.
    """

    def __init__(self, settings: Settings, rules_dir: Path | None = None) -> None:
        self.settings = settings
        self._rules_dir = rules_dir or default_rules_dir()
        self._rules: RuleSet | None = None
        self._load_error = ""
        self._loaded = False

    @property
    def enabled(self) -> bool:
        return bool(self.settings.get("yara_enabled", True))

    def rules(self) -> RuleSet | None:
        """Compile the rule set once, lazily, and cache it."""
        if self._loaded:
            return self._rules
        self._loaded = True
        try:
            rule_set = compile_directory(self._rules_dir)
        except (OSError, YaraError) as exc:
            self._load_error = f"Cannot load rules: {exc}"
            log.warning("YARA rules unavailable: %s", exc)
            return None
        if len(rule_set) == 0:
            self._load_error = f"No rules found in {self._rules_dir}"
            log.warning(self._load_error)
            return None
        self._rules = rule_set
        log.info("YARA: loaded %d rules from %s", len(rule_set), self._rules_dir)
        return rule_set

    def scan(self, locked: "LockedFile", file_name: str = "",
             cancel: Callable[[], bool] | None = None) -> LayerResult:
        """Match the rule set against the bytes behind an open handle."""
        started = time.perf_counter()

        if not self.enabled:
            return LayerResult(status=Status.SKIPPED,
                               detail="Skipped: YARA disabled in settings")

        rule_set = self.rules()
        if rule_set is None:
            return LayerResult(
                status=Status.ERROR,
                detail=self._load_error or "YARA rules unavailable",
                elapsed_ms=_ms(started),
            )

        try:
            data = locked.read_all(YARA_MAX_BYTES, cancel=cancel)
        except ScanCancelled:
            raise
        except OSError as exc:
            return LayerResult(status=Status.ERROR,
                               detail=f"Cannot read file for YARA: {exc}",
                               elapsed_ms=_ms(started))

        truncated = locked.size > len(data)
        try:
            matches = rule_set.match(data, file_name)
        except Exception as exc:
            log.exception("YARA matching crashed")
            return LayerResult(status=Status.ERROR,
                               detail=f"YARA error: {exc}",
                               elapsed_ms=_ms(started))

        if not matches:
            detail = "No rule matched"
            if truncated:
                detail += f" (first {len(data) // (1024 * 1024)} MiB scanned)"
            return LayerResult(status=Status.CLEAN, detail=detail,
                               elapsed_ms=_ms(started))

        worst = matches[0]  # RuleSet.match sorts highest severity first
        names = ", ".join(m.rule for m in matches[:4])
        if len(matches) > 4:
            names += f" (+{len(matches) - 4} more)"

        status = Status.MALICIOUS if worst.severity in _YARA_MALICIOUS \
            else Status.SUSPICIOUS
        detail = f"{worst.description or worst.rule} [{names}]"
        if truncated:
            detail += f" (first {len(data) // (1024 * 1024)} MiB scanned)"

        return LayerResult(
            status=status,
            detail=detail,
            raw={
                "matches": [
                    {
                        "rule": m.rule,
                        "severity": m.severity,
                        "tags": list(m.tags),
                        "description": m.description,
                        "strings": dict(m.matched_strings),
                        "first_offsets": dict(m.first_offsets),
                    }
                    for m in matches
                ],
                "bytes_scanned": len(data),
                "truncated": truncated,
            },
            elapsed_ms=_ms(started),
        )


# --------------------------------------------------------------------------- #
# Verdict aggregation
# --------------------------------------------------------------------------- #

def aggregate_verdict(defender: LayerResult, mb: LayerResult,
                      opswat: LayerResult,
                      amsi: LayerResult | None = None,
                      reputation: "ReputationAssessment | None" = None,
                      yara: LayerResult | None = None,
                      ) -> tuple[Verdict, int]:
    """Combine the layers into one verdict plus a 0-100 risk score.

    Precedence, highest first:
      * any layer says Malicious            -> Malicious
      * any layer says Suspicious           -> Suspicious
      * Layer 1 Clean AND no layer errored  -> Clean
      * otherwise                           -> Unknown

    A Clean verdict deliberately requires a successful local Defender scan.
    If Defender errored and the cloud layers only said "not found", the honest
    answer is Unknown, not Clean: nobody actually inspected the bytes.

    AMSI is treated as *corroboration only*. An AMSI "not detected" never
    upgrades a scan to Clean on its own, because a provider disabled by policy
    returns NOT_DETECTED for everything and that is indistinguishable from a
    genuine clean result. An AMSI *detection* is conclusive, but that path is
    short-circuited before aggregation ever runs.

    Local reputation signals (MOTW, Authenticode, PE heuristics) are **advisory
    and one-directional**: they can raise a Clean verdict to Suspicious when the
    evidence warrants it, and they can never lower a verdict. A signature engine
    saying Malicious always wins over a heuristic saying "looks fine".

    YARA is a content-based *detection* layer, not an advisory one: a rule hit
    at critical/high severity is Malicious in its own right, because it describes
    behaviour (ransomware note text, credential dumping) rather than a heuristic
    guess. Medium/low hits are Suspicious.
    """
    statuses = [defender.status, mb.status, opswat.status]
    if amsi is not None:
        statuses.append(amsi.status)
    if yara is not None:
        statuses.append(yara.status)

    if Status.MALICIOUS in statuses:
        score = 100
        return Verdict.MALICIOUS, score
    if Status.SUSPICIOUS in statuses:
        return Verdict.SUSPICIOUS, 60

    defender_ok = defender.status is Status.CLEAN
    cloud_clean = any(s is Status.CLEAN for s in (mb.status, opswat.status))
    amsi_clean = amsi is not None and amsi.status is Status.CLEAN
    any_error = Status.ERROR in statuses

    if defender_ok and not any_error:
        verdict, score = Verdict.CLEAN, 0
    elif defender_ok and cloud_clean and not any_error:
        verdict, score = Verdict.CLEAN, 0
    elif defender_ok:
        # Defender inspected the bytes and found nothing; other layers merely
        # failed or had no record. Local evidence is real evidence.
        verdict, score = Verdict.CLEAN, 5
    elif cloud_clean and not any_error:
        verdict, score = Verdict.CLEAN, 10
    elif amsi_clean and not any_error and (cloud_clean or defender_ok):
        verdict, score = Verdict.CLEAN, 15
    else:
        verdict, score = Verdict.UNKNOWN, 20

    # ---- advisory reputation pass ---------------------------------------- #
    # Only ever escalates. No engine said malicious, so this is the only place
    # local signals get a say - and they can only make the answer more cautious.
    if reputation is not None and reputation.risk > 0:
        if verdict is Verdict.CLEAN and reputation.is_suspicious:
            return Verdict.SUSPICIOUS, max(40, min(99, reputation.risk))
        # Even below the suspicious threshold, carry the risk into the score so
        # the UI can show "clean, but downloaded from the internet".
        score = max(score, min(39, reputation.risk))

    return verdict, score


# --------------------------------------------------------------------------- #
# Engine
# --------------------------------------------------------------------------- #

class ScanEngine:
    """Orchestrates hashing, the cache gate, and the three layers."""

    def __init__(self, settings: Settings | None = None,
                 database: ScanDatabase | None = None) -> None:
        self.settings = settings or default_settings
        self.db = database or ScanDatabase()
        self.defender = DefenderLayer(self.settings)
        self.amsi = AmsiLayer(self.settings)
        self.yara = YaraLayer(self.settings)
        self.malwarebazaar = MalwareBazaarLayer(self.settings)
        self.opswat = OpswatLayer(self.settings)
        self._quarantine: QuarantineManager | None = None

    # -- quarantine -------------------------------------------------------- #

    @property
    def quarantine(self) -> QuarantineManager:
        """Lazily created so a scan-only engine never touches the store."""
        if self._quarantine is None:
            self._quarantine = QuarantineManager(self.db)
        return self._quarantine

    def _maybe_quarantine(self, result: ScanResult,
                          emit: Callable[[str], None]) -> None:
        """Move a malicious file into quarantine when the setting is on.

        Never raises: a quarantine failure must not lose the scan result the
        user is waiting for. The failure is recorded on the result instead.
        """
        if not bool(self.settings.get("auto_quarantine")):
            return
        if result.verdict is not Verdict.MALICIOUS:
            return
        if result.quarantined:
            return

        emit("Quarantining...")
        detail = ""
        for layer in (result.defender, result.amsi, result.yara,
                      result.malwarebazaar, result.opswat):
            if layer.status is Status.MALICIOUS and layer.detail:
                detail = layer.detail
                break

        try:
            record = self.quarantine.quarantine(
                result.file_path,
                sha256=result.sha256,
                verdict=result.verdict.value,
                score=result.score,
                threat_detail=detail,
            )
        except FileAlreadyHandled as exc:
            # Defender removed or locked the file before we could move it.
            # The threat is handled, just not by us - not an error.
            result.quarantine_error = str(exc)
            emit("File already handled by antivirus")
            return
        except QuarantineError as exc:
            log.warning("Quarantine failed for %s: %s", result.file_path, exc)
            result.quarantine_error = str(exc)
            emit(f"Quarantine failed: {exc}")
            return
        except Exception as exc:
            log.exception("Quarantine crashed for %s", result.file_path)
            result.quarantine_error = str(exc)
            emit("Quarantine failed")
            return

        result.quarantined = True
        result.quarantine_id = record.id
        result.quarantine_path = record.quarantine_path
        emit("Quarantined")

    # -- public API -------------------------------------------------------- #

    def scan_file(
        self,
        path: str | Path,
        *,
        source: str = "manual",
        use_cache: bool = True,
        progress: Callable[[str], None] | None = None,
        cancel: Callable[[], bool] | None = None,
    ) -> ScanResult:
        """Scan one file end to end and record it in the history log."""
        file_path = Path(path)
        started = time.time()

        def emit(message: str) -> None:
            if progress is not None:
                try:
                    progress(message)
                except Exception:  # a UI callback must never break a scan
                    log.debug("progress callback raised", exc_info=True)

        if not file_path.is_file():
            result = ScanResult(
                file_path=str(file_path),
                file_name=file_path.name,
                file_size=0,
                sha256="",
                scanned_at=started,
                verdict=Verdict.ERROR,
                error="Path is not a readable file",
            )
            result.defender.status = Status.ERROR
            result.malwarebazaar.status = Status.ERROR
            result.opswat.status = Status.ERROR
            return result

        # ---- open once, hold it for the whole scan ----------------------- #
        # The handle denies writes and deletes, so the bytes we hash are the
        # bytes Defender inspects. See LockedFile for the reasoning.
        emit("Opening file...")
        try:
            locked = LockedFile(file_path)
            locked.__enter__()
        except FileBlockedByAntivirus as exc:
            # The OS refused the file because antivirus has already flagged it.
            # That is a positive detection, not a failure to scan.
            log.info("Antivirus blocked %s: %s", file_path, exc)
            return self._av_blocked_result(file_path, started, source, str(exc))
        except OSError as exc:
            result = ScanResult(
                file_path=str(file_path),
                file_name=file_path.name,
                file_size=0,
                sha256="",
                scanned_at=started,
                verdict=Verdict.ERROR,
                error=f"Cannot open file: {exc}",
            )
            result.defender.status = Status.ERROR
            result.malwarebazaar.status = Status.ERROR
            result.opswat.status = Status.ERROR
            return result

        try:
            result = self._scan_locked(
                file_path, locked, started, source, use_cache, emit, cancel
            )
        finally:
            locked.close()

        # Quarantine only after the locked handle is released.
        #
        # LockedFile holds the file with dwShareMode = FILE_SHARE_READ, which
        # denies delete. Moving the file while that handle is open fails with
        # WinError 32 (sharing violation) every single time - so auto-quarantine
        # never worked for any file while it was called from inside the scan.
        # The TOCTOU guarantee only needs to cover hashing and the Defender
        # scan; once the verdict is decided the handle has done its job.
        if result.verdict is Verdict.MALICIOUS and not result.quarantined:
            self._maybe_quarantine(result, emit)
            if result.quarantined:
                self.db.put_cached(result.to_cached())

        return result

    def _av_blocked_result(self, file_path: Path, started: float,
                           source: str, detail: str) -> ScanResult:
        """Build a Malicious result for a file the OS refused to open.

        No hash can be computed (the bytes are unreachable), so this result is
        deliberately NOT written to the hash cache: caching a verdict under an
        empty or guessed hash would poison the cache for unrelated files.
        """
        result = ScanResult(
            file_path=str(file_path),
            file_name=file_path.name,
            file_size=0,
            sha256="",
            scanned_at=started,
            verdict=Verdict.MALICIOUS,
            score=100,
            error=detail,
        )
        blocked = LayerResult(
            status=Status.MALICIOUS,
            detail="Antivirus blocked access to this file (ERROR_VIRUS_INFECTED)",
            raw={"windows_error": 225},
        )
        result.defender = blocked
        result.amsi = LayerResult(
            status=Status.MALICIOUS,
            detail="Antivirus blocked access to this file",
        )
        result.yara = LayerResult(
            status=Status.SKIPPED, detail="Skipped: file blocked by antivirus"
        )
        result.malwarebazaar = LayerResult(
            status=Status.SKIPPED, detail="Skipped: file blocked by antivirus"
        )
        result.opswat = LayerResult(
            status=Status.SKIPPED, detail="Skipped: file blocked by antivirus"
        )
        # Do not attempt to quarantine here: the file cannot be opened or moved,
        # which is exactly why we are in this branch. Defender owns it. Record
        # the reason so the UI explains itself instead of going silent.
        result.quarantine_error = (
            "Not quarantined: Windows blocked access to this file, so it could "
            "not be moved. Antivirus is already handling it."
        )
        self._log(result, source=source, from_cache=False)
        return result

    def _scan_locked(
        self,
        file_path: Path,
        locked: LockedFile,
        started: float,
        source: str,
        use_cache: bool,
        emit: Callable[[str], None],
        cancel: Callable[[], bool] | None,
    ) -> ScanResult:
        """Scan body. Runs with the file handle already held open."""
        size = locked.size

        emit("Hashing file...")
        try:
            sha256 = locked.sha256(cancel=cancel)
        except ScanCancelled:
            raise
        except OSError as exc:
            if _is_av_block(exc):
                return self._av_blocked_result(
                    file_path, started, source,
                    f"Antivirus blocked the read: {exc}",
                )
            return ScanResult(
                file_path=str(file_path),
                file_name=file_path.name,
                file_size=size,
                sha256="",
                scanned_at=started,
                verdict=Verdict.ERROR,
                error=f"Cannot read file: {exc}",
            )

        # ---- cache gate -------------------------------------------------- #
        if use_cache:
            ttl = float(self.settings.get("cache_ttl_hours") or 24)
            cached = self.db.get_cached(sha256, ttl_hours=ttl)
            if cached is not None:
                emit("Cache hit - reusing verdict from the last 24 hours")
                result = ScanResult.from_cached(cached, str(file_path))
                result.file_path = str(file_path)
                result.file_name = file_path.name
                result.file_size = size
                self._log(result, source=source, from_cache=True)
                return result

        result = ScanResult(
            file_path=str(file_path),
            file_name=file_path.name,
            file_size=size,
            sha256=sha256,
            scanned_at=started,
        )

        # ---- Layer 0: AMSI (fast, in-process) ---------------------------- #
        # Runs first because it is milliseconds. A positive result is
        # conclusive and skips everything else, including the slow CLI scan.
        emit("AMSI pre-scan...")
        try:
            amsi_verdict = self.amsi.scan(str(file_path), cancel=cancel)
        except ScanCancelled:
            raise
        except Exception as exc:
            log.exception("AMSI layer crashed")
            amsi_verdict = None
            result.amsi = LayerResult(status=Status.ERROR,
                                      detail=f"AMSI layer error: {exc}")

        if amsi_verdict is not None:
            if amsi_verdict.detected:
                result.amsi = LayerResult(
                    status=Status.MALICIOUS,
                    detail=amsi_verdict.detail,
                    raw={"amsi_result": amsi_verdict.result_code},
                    elapsed_ms=amsi_verdict.elapsed_ms,
                )
            elif not amsi_verdict.available:
                result.amsi = LayerResult(
                    status=Status.SKIPPED,
                    detail=amsi_verdict.detail or "AMSI unavailable",
                    elapsed_ms=amsi_verdict.elapsed_ms,
                )
            elif amsi_verdict.blocked_by_admin:
                # A policy-blocked provider returns NOT_DETECTED for everything.
                # Reporting that as Clean would be a silent false negative.
                result.amsi = LayerResult(
                    status=Status.ERROR,
                    detail=amsi_verdict.detail,
                    raw={"amsi_result": amsi_verdict.result_code},
                    elapsed_ms=amsi_verdict.elapsed_ms,
                )
            elif amsi_verdict.result_code is not None and amsi_verdict.detail.startswith(
                "AMSI scan failed"
            ):
                result.amsi = LayerResult(
                    status=Status.ERROR,
                    detail=amsi_verdict.detail,
                    elapsed_ms=amsi_verdict.elapsed_ms,
                )
            else:
                result.amsi = LayerResult(
                    status=Status.CLEAN,
                    detail=amsi_verdict.detail,
                    raw={"amsi_result": amsi_verdict.result_code},
                    elapsed_ms=amsi_verdict.elapsed_ms,
                )

        # AMSI positive: conclusive, skip the CLI and the cloud entirely.
        if result.amsi.status is Status.MALICIOUS:
            emit("AMSI detected a threat - skipping remaining layers")
            skip = LayerResult(status=Status.SKIPPED,
                               detail="Skipped: AMSI detection already conclusive")
            result.defender = LayerResult(
                status=Status.SKIPPED, detail="Skipped: AMSI detection already conclusive"
            )
            result.malwarebazaar = LayerResult(
                status=Status.SKIPPED, detail="Skipped: AMSI detection already conclusive"
            )
            result.opswat = LayerResult(
                status=Status.SKIPPED, detail="Skipped: AMSI detection already conclusive"
            )
            result.verdict = Verdict.MALICIOUS
            result.score = 100
            # Quarantine is handled by scan_file once the locked handle is
            # released; moving the file here always fails with a sharing
            # violation.
            self.db.put_cached(result.to_cached())
            self._log(result, source=source, from_cache=False)
            emit("Done - Malicious")
            return result

        # ---- Layer: YARA (local, content-based) -------------------------- #
        # Runs after AMSI and before Defender. It reads through the same locked
        # handle, so the rules see the bytes we hashed. Cheap enough to always
        # run, and it is the only layer that can say anything about a brand-new
        # sample no provider has ever seen.
        emit("YARA rules...")
        try:
            result.yara = self.yara.scan(
                locked, file_name=file_path.name, cancel=cancel
            )
        except ScanCancelled:
            raise
        except Exception as exc:
            log.exception("YARA layer crashed")
            result.yara = LayerResult(status=Status.ERROR,
                                      detail=f"YARA layer error: {exc}")

        # ---- Layer 1: Defender ------------------------------------------- #
        # The handle is still open here, so Defender reads the same bytes we
        # hashed and nothing can swap the file underneath us.
        emit("Layer 1/3 - Windows Defender...")
        try:
            result.defender = self.defender.scan(str(file_path), cancel=cancel)
        except ScanCancelled:
            raise
        except Exception as exc:  # defensive: a layer must never kill the scan
            log.exception("Defender layer crashed")
            result.defender = LayerResult(status=Status.ERROR,
                                          detail=f"Defender layer error: {exc}")

        # ---- post-scan integrity check ------------------------------------ #
        # Cheap belt-and-braces: if the filesystem ignored our share mode and
        # the file changed anyway, the verdict does not describe what we hashed.
        if not locked.unchanged():
            log.warning("File changed during scan: %s", file_path)
            result.defender = LayerResult(
                status=Status.ERROR,
                detail="File was modified during the scan; verdict discarded",
            )
            result.malwarebazaar = LayerResult(
                status=Status.SKIPPED, detail="Skipped: file changed mid-scan"
            )
            result.opswat = LayerResult(
                status=Status.SKIPPED, detail="Skipped: file changed mid-scan"
            )
            result.verdict = Verdict.ERROR
            result.score = 0
            result.error = "File modified during scan"
            emit("File changed mid-scan - verdict discarded")
            return result

        # ---- Layers 2 and 3 ---------------------------------------------- #
        if result.defender.is_malicious or result.yara.is_malicious:
            reason = ("local detection already conclusive"
                      if result.defender.is_malicious
                      else "YARA detection already conclusive")
            emit(f"{reason.capitalize()} - skipping cloud lookups")
            skip = LayerResult(
                status=Status.SKIPPED,
                detail=f"Skipped: {reason}",
            )
            result.malwarebazaar = skip
            result.opswat = LayerResult(
                status=Status.SKIPPED,
                detail=f"Skipped: {reason}",
            )
        else:
            emit("Layer 2/3 - MalwareBazaar...")
            try:
                result.malwarebazaar = self.malwarebazaar.scan(sha256, cancel=cancel)
            except ScanCancelled:
                raise
            except Exception as exc:
                log.exception("MalwareBazaar layer crashed")
                result.malwarebazaar = LayerResult(
                    status=Status.ERROR, detail=f"MalwareBazaar layer error: {exc}"
                )

            emit("Layer 3/3 - MetaDefender Cloud...")
            try:
                result.opswat = self.opswat.scan(sha256, cancel=cancel)
            except ScanCancelled:
                raise
            except Exception as exc:
                log.exception("MetaDefender layer crashed")
                result.opswat = LayerResult(
                    status=Status.ERROR, detail=f"MetaDefender layer error: {exc}"
                )

        result.opswat_quota_remaining = self.opswat.quota_remaining

        # ---- local reputation signals (advisory, never lowers) ----------- #
        emit("Local reputation checks...")
        try:
            result.reputation = assess_reputation(
                str(file_path), deep=should_deep_scan(file_path)
            )
        except Exception as exc:
            log.exception("Reputation assessment crashed")
            result.reputation = None

        result.verdict, result.score = aggregate_verdict(
            result.defender, result.malwarebazaar, result.opswat, result.amsi,
            result.reputation, result.yara,
        )

        # ---- quarantine -------------------------------------------------- #
        # Deferred: scan_file quarantines after releasing the locked handle.
        # See the comment there for why it cannot happen while it is held.

        # ---- persist ------------------------------------------------------ #
        self.db.put_cached(result.to_cached())
        self._log(result, source=source, from_cache=False)
        emit(f"Done - {result.verdict.value}")
        return result

    def scan_many(
        self,
        paths: Iterable[str | Path],
        *,
        source: str = "manual",
        progress: Callable[[str], None] | None = None,
        on_result: Callable[[ScanResult], None] | None = None,
        cancel: Callable[[], bool] | None = None,
    ) -> list[ScanResult]:
        """Scan a list of files sequentially, reporting each as it finishes."""
        results: list[ScanResult] = []
        for path in paths:
            if cancel is not None and cancel():
                break
            try:
                result = self.scan_file(path, source=source, progress=progress, cancel=cancel)
            except ScanCancelled:
                break
            except Exception as exc:
                log.exception("Scan failed for %s", path)
                result = ScanResult(
                    file_path=str(path),
                    file_name=Path(path).name,
                    file_size=0,
                    sha256="",
                    scanned_at=time.time(),
                    verdict=Verdict.ERROR,
                    error=str(exc),
                )
            results.append(result)
            if on_result is not None:
                try:
                    on_result(result)
                except Exception:
                    log.debug("on_result callback raised", exc_info=True)
        return results

    def quota_status(self) -> int | None:
        """Last observed MetaDefender quota, if a lookup has run this session."""
        return self.opswat.quota_remaining

    # -- internals --------------------------------------------------------- #

    def _log(self, result: ScanResult, *, source: str, from_cache: bool) -> None:
        try:
            self.db.log_scan(
                sha256=result.sha256,
                file_path=result.file_path,
                file_name=result.file_name,
                file_size=result.file_size,
                defender_status=result.defender.status.value,
                mb_status=result.malwarebazaar.status.value,
                opswat_status=result.opswat.status.value,
                verdict=result.verdict.value,
                score=result.score,
                source=source,
                from_cache=from_cache,
                details=result.details(),
                scanned_at=result.scanned_at,
                amsi_status=result.amsi.status.value,
                yara_status=result.yara.status.value,
            )
        except Exception:
            log.exception("Could not write scan to history log")


# --------------------------------------------------------------------------- #
# Small helpers
# --------------------------------------------------------------------------- #

def _ms(started: float) -> int:
    return int((time.perf_counter() - started) * 1000)


def _decode(raw: bytes | None) -> str:
    if not raw:
        return ""
    for encoding in ("utf-8", "utf-16-le", "cp1252"):
        try:
            return raw.decode(encoding, errors="strict")
        except (UnicodeDecodeError, LookupError):
            continue
    return raw.decode("utf-8", errors="replace")


def _tail(text: str, limit: int = 2000) -> str:
    text = text.strip()
    return text[-limit:] if len(text) > limit else text


def _as_int(value: Any) -> int | None:
    try:
        return int(value)
    except (TypeError, ValueError):
        return None


def is_scannable(path: str | Path) -> bool:
    """Cheap pre-check before queueing a file."""
    try:
        p = Path(path)
        return p.is_file() and os.access(p, os.R_OK)
    except OSError:
        return False
