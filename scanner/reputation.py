"""Local reputation signals: MOTW, Authenticode, PE heuristics.

These are the things Windows knows about a file that an antivirus verdict does
not tell you. They cost nothing, need no network, and add the judgment a bare
"Clean" hides:

* **MOTW (Mark of the Web).** A file downloaded from the internet carries a
  ``Zone.Identifier`` alternate data stream with ``ZoneId=3``. Defender does not
  surface this. "Clean but arrived from the internet" is a different decision
  from "clean and was already on this machine".
* **Authenticode.** Is the binary signed, and by whom? "Clean and signed by
  Microsoft" and "clean and unsigned, downloaded from a random host" both
  currently render as ``Clean``. They should not.
* **PE heuristics.** Section entropy, import table shape, and suspicious API
  combinations catch packed and injected binaries that signatures miss.

None of these can *lower* a verdict. They are advisory: they can raise Clean to
Suspicious, never the reverse. A signature engine saying Malicious always wins
over a heuristic saying "looks fine".

Everything here degrades gracefully. A parse failure yields "unknown", never a
false "clean".
"""

from __future__ import annotations

import logging
import math
import os
import struct
import sys
from dataclasses import dataclass, field
from enum import Enum
from pathlib import Path

log = logging.getLogger(__name__)


# --------------------------------------------------------------------------- #
# Mark of the Web
# --------------------------------------------------------------------------- #

class Zone(int, Enum):
    """Internet Explorer / Windows security zones."""

    LOCAL_MACHINE = 0
    INTRANET = 1
    TRUSTED = 2
    INTERNET = 3
    RESTRICTED = 4

    @classmethod
    def label(cls, value: int) -> str:
        return {
            0: "Local machine",
            1: "Intranet",
            2: "Trusted sites",
            3: "Internet",
            4: "Restricted sites",
        }.get(value, f"Zone {value}")


@dataclass
class MotwInfo:
    """Parsed Zone.Identifier stream."""

    present: bool = False
    zone_id: int | None = None
    referrer_url: str = ""
    host_url: str = ""
    error: str = ""

    @property
    def from_internet(self) -> bool:
        return self.zone_id is not None and self.zone_id >= Zone.INTERNET

    @property
    def zone_label(self) -> str:
        if self.zone_id is None:
            return "Unknown"
        return Zone.label(self.zone_id)


def read_motw(path: str | Path) -> MotwInfo:
    """Read the ``Zone.Identifier`` alternate data stream, if any.

    On Windows this is ``<path>:Zone.Identifier``. Reading an ADS that does not
    exist raises ``OSError``; that is the normal case for locally created files
    and is reported as ``present=False``, not as an error.
    """
    if sys.platform != "win32":
        return MotwInfo(present=False)

    stream = f"{path}:Zone.Identifier"
    try:
        with open(stream, "r", encoding="utf-8", errors="replace") as handle:
            raw = handle.read()
    except OSError:
        # No ADS: locally created file. Not an error.
        return MotwInfo(present=False)
    except Exception as exc:
        return MotwInfo(present=False, error=str(exc))

    info = MotwInfo(present=True)
    for line in raw.splitlines():
        line = line.strip()
        if not line or "=" not in line:
            continue
        key, _, value = line.partition("=")
        key = key.strip().lower()
        value = value.strip()
        if key == "zoneid":
            try:
                info.zone_id = int(value)
            except ValueError:
                pass
        elif key == "referrerurl":
            info.referrer_url = value
        elif key == "hosturl":
            info.host_url = value
    return info


# --------------------------------------------------------------------------- #
# Authenticode
# --------------------------------------------------------------------------- #

class SignatureStatus(str, Enum):
    """Outcome of an Authenticode verification."""

    VALID = "Valid"
    """Signed and the signature verifies, and the chain is trusted."""

    UNSIGNED = "Unsigned"
    """No signature at all, and no catalog entry either."""

    INVALID = "Invalid"
    """A signature is present but does not verify (tampered or corrupt)."""

    UNTRUSTED = "Untrusted"
    """Signed, but the chain does not lead to a trusted root."""

    UNKNOWN = "Unknown"
    """Verification could not be performed."""


@dataclass
class SignatureInfo:
    status: SignatureStatus = SignatureStatus.UNKNOWN
    signer: str = ""
    error: str = ""
    via_catalog: bool = False
    """True when the signature was found in a system catalog, not the file."""

    @property
    def is_signed(self) -> bool:
        return self.status in (SignatureStatus.VALID, SignatureStatus.UNTRUSTED)


# WinVerifyTrust constants
_WTD_UI_NONE = 2
_WTD_REVOKE_NONE = 0
_WTD_CHOICE_FILE = 1
_WTD_STATEACTION_VERIFY = 1
_WTD_STATEACTION_CLOSE = 2
_WTD_SAFER_FLAG = 0x100

# Trust status codes returned in dwUIChoice's place on failure.
_TRUST_E_NOSIGNATURE = 0x800B0100
_TRUST_E_SUBJECT_FORM_UNKNOWN = 0x800B0003
_TRUST_E_PROVIDER_UNKNOWN = 0x800B0001
_TRUST_E_EXPLICIT_DISTRUST = 0x800B0111
_TRUST_E_SUBJECT_NOT_TRUSTED = 0x800B0004
_CERT_E_UNTRUSTEDROOT = 0x800B0109
_CERT_E_CHAINING = 0x800B010A
_CERT_E_EXPIRED = 0x800B0101
_TRUST_E_BAD_DIGEST = 0x80096010
_TRUST_E_BAD_SIGNATURE = 0x80096019
_CRYPT_E_SECURITY_SETTINGS = 0x80092026


def has_embedded_signature(path: str | Path) -> bool:
    """True when the PE carries an Authenticode signature inside the file.

    Many Windows system binaries (notepad.exe, cmd.exe) are **catalog-signed**:
    their signature lives in a system catalog file, not in the PE's security
directory. ``WinVerifyTrust`` on such a file returns
    ``TRUST_E_NOSIGNATURE``, which is technically accurate and practically
    misleading - those binaries are genuinely signed.

    Checking the security data directory first lets us tell the two cases apart
    and only pay for a catalog lookup when there is no embedded signature.
    """
    try:
        with open(path, "rb") as handle:
            head = handle.read(4096)
            if len(head) < 0x40 or head[:2] != b"MZ":
                return False
            e_lfanew = struct.unpack_from("<I", head, 0x3C)[0]
            if e_lfanew + 24 > len(head) or head[e_lfanew:e_lfanew + 4] != b"PE\0\0":
                return False
            coff = e_lfanew + 4
            optional_size = struct.unpack_from("<H", head, coff + 16)[0]
            optional = coff + 20
            magic = struct.unpack_from("<H", head, optional)[0]
            dd_offset = optional + (112 if magic == 0x20B else 96)
            # Data directory index 4 is IMAGE_DIRECTORY_ENTRY_SECURITY.
            entry = dd_offset + 4 * 8
            if entry + 8 > len(head):
                return False
            _offset, size = struct.unpack_from("<II", head, entry)
            return size > 0
    except (OSError, struct.error, IndexError):
        return False


def verify_authenticode(path: str | Path) -> SignatureInfo:
    """Verify a file's Authenticode signature.

    Two-stage:

    1. ``WinVerifyTrust`` with ``WTD_REVOKE_NONE`` - no network revocation
       check, so a revoked-but-valid certificate reports as Valid. That is a
       deliberate trade-off: revocation checking would add a round trip per
       file and make scans depend on connectivity.
    2. If there is no embedded signature, fall back to a catalog lookup via
       ``Get-AuthenticodeSignature``. Windows system binaries are
       catalog-signed and would otherwise be misreported as unsigned.
    """
    if sys.platform != "win32":
        return SignatureInfo(status=SignatureStatus.UNKNOWN,
                             error="Authenticode is Windows-only")

    info = _verify_embedded(path)

    # No embedded signature: it may still be catalog-signed.
    if info.status is SignatureStatus.UNSIGNED and not has_embedded_signature(path):
        catalog = _verify_via_catalog(path)
        if catalog is not None:
            # Only mark it as a catalog hit when the catalog actually vouched
            # for the file. A catalog lookup that comes back NotSigned means we
            # looked and found nothing - reporting via_catalog=True there would
            # wrongly imply a catalog endorsed the file.
            catalog.via_catalog = catalog.status is not SignatureStatus.UNSIGNED
            return catalog
    return info


def _verify_embedded(path: str | Path) -> SignatureInfo:
    """WinVerifyTrust against the file's embedded signature."""
    try:
        import ctypes
        from ctypes import wintypes

        class GUID(ctypes.Structure):
            _fields_ = [
                ("Data1", wintypes.DWORD),
                ("Data2", wintypes.WORD),
                ("Data3", wintypes.WORD),
                ("Data4", ctypes.c_ubyte * 8),
            ]

        class WINTRUST_FILE_INFO(ctypes.Structure):
            _fields_ = [
                ("cbStruct", wintypes.DWORD),
                ("pcwszFilePath", wintypes.LPCWSTR),
                ("hFile", wintypes.HANDLE),
                ("pgKnownSubject", ctypes.POINTER(GUID)),
            ]

        class WINTRUST_DATA(ctypes.Structure):
            _fields_ = [
                ("cbStruct", wintypes.DWORD),
                ("pPolicyCallbackData", wintypes.LPVOID),
                ("pSIPClientData", wintypes.LPVOID),
                ("dwUIChoice", wintypes.DWORD),
                ("fdwRevocationChecks", wintypes.DWORD),
                ("dwUnionChoice", wintypes.DWORD),
                ("pFile", ctypes.POINTER(WINTRUST_FILE_INFO)),
                ("dwStateAction", wintypes.DWORD),
                ("hWVTStateData", wintypes.HANDLE),
                ("pwszURLReference", wintypes.LPWSTR),
                ("dwProvFlags", wintypes.DWORD),
                ("dwUIContext", wintypes.DWORD),
                ("pSignatureSettings", wintypes.LPVOID),
            ]

        # WINTRUST_ACTION_GENERIC_VERIFY_V2
        action = GUID(
            0x00AAC56B, 0xCD44, 0x11D0,
            (ctypes.c_ubyte * 8)(0x8C, 0xC2, 0x00, 0xC0, 0x4F, 0xC2, 0x95, 0xEE),
        )

        file_info = WINTRUST_FILE_INFO()
        file_info.cbStruct = ctypes.sizeof(WINTRUST_FILE_INFO)
        file_info.pcwszFilePath = str(path)
        file_info.hFile = None
        file_info.pgKnownSubject = None

        trust_data = WINTRUST_DATA()
        trust_data.cbStruct = ctypes.sizeof(WINTRUST_DATA)
        trust_data.dwUIChoice = _WTD_UI_NONE
        trust_data.fdwRevocationChecks = _WTD_REVOKE_NONE
        trust_data.dwUnionChoice = _WTD_CHOICE_FILE
        trust_data.pFile = ctypes.pointer(file_info)
        trust_data.dwStateAction = _WTD_STATEACTION_VERIFY
        trust_data.dwProvFlags = _WTD_SAFER_FLAG
        trust_data.dwUIContext = 0

        wintrust = ctypes.WinDLL("wintrust.dll")
        wintrust.WinVerifyTrust.restype = ctypes.c_long
        wintrust.WinVerifyTrust.argtypes = [
            wintypes.HWND, ctypes.POINTER(GUID), ctypes.c_void_p
        ]

        result = wintrust.WinVerifyTrust(
            None, ctypes.byref(action), ctypes.byref(trust_data)
        )

        # Always close the state, even on failure, or we leak a handle.
        trust_data.dwStateAction = _WTD_STATEACTION_CLOSE
        try:
            wintrust.WinVerifyTrust(None, ctypes.byref(action), ctypes.byref(trust_data))
        except Exception:
            pass

        code = result & 0xFFFFFFFF
        info = SignatureInfo()

        if result == 0:
            info.status = SignatureStatus.VALID
        elif code in (_TRUST_E_NOSIGNATURE, _TRUST_E_SUBJECT_FORM_UNKNOWN,
                      _TRUST_E_PROVIDER_UNKNOWN):
            info.status = SignatureStatus.UNSIGNED
        elif code in (_TRUST_E_BAD_DIGEST, _TRUST_E_BAD_SIGNATURE):
            info.status = SignatureStatus.INVALID
            info.error = "Signature does not match the file contents"
        elif code in (_CERT_E_UNTRUSTEDROOT, _CERT_E_CHAINING,
                      _TRUST_E_SUBJECT_NOT_TRUSTED, _TRUST_E_EXPLICIT_DISTRUST):
            info.status = SignatureStatus.UNTRUSTED
            info.error = "Signature chain is not trusted"
        elif code == _CERT_E_EXPIRED:
            info.status = SignatureStatus.UNTRUSTED
            info.error = "Signing certificate has expired"
        else:
            info.status = SignatureStatus.UNKNOWN
            info.error = f"WinVerifyTrust returned 0x{code:08X}"

        if info.status in (SignatureStatus.VALID, SignatureStatus.UNTRUSTED):
            info.signer = _extract_signer(str(path))
        return info

    except Exception as exc:
        log.debug("Authenticode verification failed for %s", path, exc_info=True)
        return SignatureInfo(status=SignatureStatus.UNKNOWN, error=str(exc))


def _verify_via_catalog(path: str | Path) -> SignatureInfo | None:
    """Look the file up in the system catalogs via Get-AuthenticodeSignature.

    Returns None when the lookup itself could not be performed, so the caller
    keeps the original "unsigned" answer rather than inventing a status.

    This costs ~20-50 ms because it starts PowerShell. It only runs for files
    with no embedded signature, which in practice means Windows system binaries
    and unsigned downloads - exactly the cases where the distinction matters.
    """
    try:
        import subprocess

        script = (
            "$s = Get-AuthenticodeSignature -LiteralPath "
            f"'{path}'; "
            "if ($s.Status -eq 'Valid') { "
            "  Write-Output ('VALID|' + $s.SignerCertificate.Subject) "
            "} elseif ($s.Status -eq 'NotSigned') { "
            "  Write-Output 'NOTSIGNED|' "
            "} else { "
            "  Write-Output ($s.Status.ToString() + '|' + $s.StatusMessage) "
            "}"
        )
        proc = subprocess.run(
            ["powershell", "-NoProfile", "-NonInteractive", "-Command", script],
            capture_output=True, timeout=15, check=False,
            creationflags=getattr(subprocess, "CREATE_NO_WINDOW", 0),
        )
        text = (proc.stdout or b"").decode("utf-8", errors="replace").strip()
        if not text or "|" not in text:
            return None

        status_text, _, detail = text.partition("|")
        status_text = status_text.strip()
        detail = detail.strip()

        info = SignatureInfo()
        if status_text == "VALID":
            info.status = SignatureStatus.VALID
            info.signer = _common_name(detail)
        elif status_text == "NOTSIGNED":
            info.status = SignatureStatus.UNSIGNED
        elif status_text in ("HashMismatch", "NotTrusted"):
            info.status = SignatureStatus.INVALID
            info.error = detail or status_text
        elif status_text == "UnknownError":
            info.status = SignatureStatus.UNKNOWN
            info.error = detail or status_text
        else:
            info.status = SignatureStatus.UNTRUSTED
            info.error = detail or status_text
        return info
    except Exception:
        log.debug("Catalog signature lookup failed for %s", path, exc_info=True)
        return None


def _common_name(distinguished_name: str) -> str:
    """Pull CN= out of an X.500 distinguished name."""
    if not distinguished_name:
        return ""
    for part in distinguished_name.split(","):
        part = part.strip()
        if part.upper().startswith("CN="):
            return part[3:].strip()
    return distinguished_name[:120]


def _extract_signer(path: str) -> str:
    """Best-effort signer common name from the embedded certificate.

    Uses PowerShell's Get-AuthenticodeSignature, which is far less ctypes than
    walking CryptQueryObject by hand. Only called for files that already proved
    signed, so it is not on the hot path for unsigned files.
    """
    try:
        import subprocess

        proc = subprocess.run(
            ["powershell", "-NoProfile", "-NonInteractive", "-Command",
             f"(Get-AuthenticodeSignature -LiteralPath '{path}').SignerCertificate.Subject"],
            capture_output=True, timeout=10, check=False,
            creationflags=getattr(subprocess, "CREATE_NO_WINDOW", 0),
        )
        text = (proc.stdout or b"").decode("utf-8", errors="replace").strip()
        if not text:
            return ""
        # Pull CN= out of the DN for a readable name.
        for part in text.split(","):
            part = part.strip()
            if part.upper().startswith("CN="):
                return part[3:].strip()
        return text[:120]
    except Exception:
        log.debug("Could not extract signer name", exc_info=True)
        return ""


# --------------------------------------------------------------------------- #
# PE analysis
# --------------------------------------------------------------------------- #

# APIs that, in combination, indicate injection or process manipulation.
_SUSPICIOUS_APIS = {
    "VirtualAllocEx": "allocates memory in another process",
    "WriteProcessMemory": "writes into another process",
    "CreateRemoteThread": "starts a thread in another process",
    "NtCreateThreadEx": "starts a thread in another process",
    "SetWindowsHookEx": "installs a system-wide hook",
    "QueueUserAPC": "APC injection",
    "NtUnmapViewOfSection": "process hollowing",
    "IsDebuggerPresent": "anti-analysis check",
    "CheckRemoteDebuggerPresent": "anti-analysis check",
    "VirtualProtect": "changes memory protection",
    "GetProcAddress": "dynamic API resolution",
    "LoadLibraryA": "dynamic library loading",
    "URLDownloadToFile": "downloads a file",
    "WinExec": "executes a program",
    "ShellExecute": "executes a program",
    "CryptEncrypt": "encryption (ransomware indicator)",
    "FindFirstFile": "file enumeration",
}

# Combinations that are far more meaningful than any single API.
_INJECTION_TRIAD = {"VirtualAllocEx", "WriteProcessMemory", "CreateRemoteThread"}


@dataclass
class PeInfo:
    """Structural facts about a PE binary."""

    is_pe: bool = False
    machine: str = ""
    subsystem: str = ""
    section_count: int = 0
    max_entropy: float = 0.0
    high_entropy_sections: list[str] = field(default_factory=list)
    imports: list[str] = field(default_factory=list)
    suspicious_apis: list[str] = field(default_factory=list)
    has_injection_triad: bool = False
    entry_point_section: str = ""
    error: str = ""

    @property
    def is_packed(self) -> bool:
        """A section at ~7.5+ bits/byte is compressed or encrypted."""
        return self.max_entropy >= 7.5

    @property
    def has_no_imports(self) -> bool:
        """A PE with no imports is almost always packed or a stub."""
        return self.is_pe and not self.imports


def analyze_pe(path: str | Path, max_read: int = 8 * 1024 * 1024) -> PeInfo:
    """Parse a PE file's headers, sections and imports.

    Pure Python, no ``pefile`` dependency. Reads at most ``max_read`` bytes so a
    huge installer does not cost a huge allocation. Any parse failure returns
    ``is_pe=False`` with a reason: an unparseable file is not evidence of
    anything, so it must never be reported as clean-and-fine.
    """
    info = PeInfo()
    try:
        with open(path, "rb") as handle:
            data = handle.read(max_read)
    except OSError as exc:
        info.error = f"Cannot read file: {exc}"
        return info

    try:
        return _parse_pe(data, info)
    except (struct.error, IndexError, ValueError) as exc:
        info.error = f"Malformed PE: {exc}"
        return info


def _parse_pe(data: bytes, info: PeInfo) -> PeInfo:
    if len(data) < 0x40 or data[:2] != b"MZ":
        info.error = "Not a PE file (no MZ header)"
        return info

    e_lfanew = struct.unpack_from("<I", data, 0x3C)[0]
    if e_lfanew + 24 > len(data) or data[e_lfanew:e_lfanew + 4] != b"PE\0\0":
        info.error = "Not a PE file (no PE signature)"
        return info

    info.is_pe = True
    coff = e_lfanew + 4
    machine, section_count = struct.unpack_from("<HH", data, coff)
    optional_size = struct.unpack_from("<H", data, coff + 16)[0]

    info.machine = {
        0x014C: "x86", 0x8664: "x64", 0x01C0: "ARM", 0xAA64: "ARM64",
    }.get(machine, f"0x{machine:04X}")
    info.section_count = section_count

    optional = coff + 20
    if optional + 2 <= len(data):
        magic = struct.unpack_from("<H", data, optional)[0]
        # Subsystem sits at offset 68 in both PE32 and PE32+ optional headers.
        if optional + 70 <= len(data):
            subsystem = struct.unpack_from("<H", data, optional + 68)[0]
            info.subsystem = {
                1: "Native", 2: "GUI", 3: "Console", 9: "Windows CE",
            }.get(subsystem, f"0x{subsystem:04X}")
        _ = magic

    # Section table follows the optional header.
    section_table = optional + optional_size
    sections = []
    for index in range(min(section_count, 96)):
        offset = section_table + index * 40
        if offset + 40 > len(data):
            break
        name = data[offset:offset + 8].rstrip(b"\0").decode("ascii", "replace")
        virtual_size, virtual_addr = struct.unpack_from("<II", data, offset + 8)
        raw_size, raw_ptr = struct.unpack_from("<II", data, offset + 16)
        sections.append((name, virtual_addr, virtual_size, raw_ptr, raw_size))

    # Entropy per section.
    for name, _vaddr, _vsize, raw_ptr, raw_size in sections:
        if raw_size == 0 or raw_ptr + raw_size > len(data):
            continue
        block = data[raw_ptr:raw_ptr + raw_size]
        entropy = _entropy(block)
        if entropy > info.max_entropy:
            info.max_entropy = entropy
        if entropy >= 7.5:
            info.high_entropy_sections.append(f"{name} ({entropy:.2f})")

    # Imports.
    info.imports = _parse_imports(data, optional, optional_size, sections)
    for api in info.imports:
        if api in _SUSPICIOUS_APIS:
            info.suspicious_apis.append(api)

    info.has_injection_triad = _INJECTION_TRIAD.issubset(set(info.imports))
    return info


def _entropy(block: bytes) -> float:
    """Shannon entropy in bits per byte (0-8)."""
    if not block:
        return 0.0
    counts = [0] * 256
    for byte in block:
        counts[byte] += 1
    total = len(block)
    entropy = 0.0
    for count in counts:
        if count:
            p = count / total
            entropy -= p * math.log2(p)
    return entropy


def _parse_imports(data: bytes, optional: int, optional_size: int,
                   sections: list) -> list[str]:
    """Walk the import directory and collect imported function names."""
    if optional + optional_size > len(data):
        return []

    magic = struct.unpack_from("<H", data, optional)[0]
    # Data directory offset differs between PE32 and PE32+.
    if magic == 0x20B:      # PE32+
        dd_offset = optional + 112
    elif magic == 0x10B:    # PE32
        dd_offset = optional + 96
    else:
        return []

    if dd_offset + 16 > len(data):
        return []

    import_rva, import_size = struct.unpack_from("<II", data, dd_offset + 8)
    if import_rva == 0 or import_size == 0:
        return []

    def rva_to_offset(rva: int) -> int | None:
        for _name, vaddr, vsize, raw_ptr, raw_size in sections:
            span = max(vsize, raw_size)
            if vaddr <= rva < vaddr + span:
                delta = rva - vaddr
                if delta < raw_size:
                    return raw_ptr + delta
        return None

    names: list[str] = []
    descriptor = rva_to_offset(import_rva)
    if descriptor is None:
        return []

    # Each IMAGE_IMPORT_DESCRIPTOR is 20 bytes; the list ends with a zero entry.
    for index in range(256):
        entry = descriptor + index * 20
        if entry + 20 > len(data):
            break
        original_first_thunk, _ts, _fwd, name_rva, first_thunk = struct.unpack_from(
            "<IIIII", data, entry
        )
        if original_first_thunk == 0 and name_rva == 0 and first_thunk == 0:
            break

        thunk_rva = original_first_thunk or first_thunk
        thunk_offset = rva_to_offset(thunk_rva) if thunk_rva else None
        if thunk_offset is None:
            continue

        is_64 = struct.unpack_from("<H", data, optional)[0] == 0x20B
        step = 8 if is_64 else 4
        fmt = "<Q" if is_64 else "<I"
        ordinal_flag = (1 << 63) if is_64 else (1 << 31)

        for slot in range(2048):
            pos = thunk_offset + slot * step
            if pos + step > len(data):
                break
            thunk = struct.unpack_from(fmt, data, pos)[0]
            if thunk == 0:
                break
            if thunk & ordinal_flag:
                continue
            hint_offset = rva_to_offset(thunk & 0x7FFFFFFF)
            if hint_offset is None or hint_offset + 2 > len(data):
                continue
            end = data.find(b"\0", hint_offset + 2, hint_offset + 2 + 256)
            if end == -1:
                continue
            try:
                names.append(data[hint_offset + 2:end].decode("ascii"))
            except UnicodeDecodeError:
                continue
    return names


# --------------------------------------------------------------------------- #
# Double extension (filename masquerading as a document)
# --------------------------------------------------------------------------- #

# Extensions that mean "this is a document" to a user.
_DOCUMENT_EXTS = {
    ".pdf", ".doc", ".docx", ".xls", ".xlsx", ".ppt", ".pptx",
    ".jpg", ".jpeg", ".png", ".gif", ".txt", ".rtf", ".csv",
    ".invoice", ".receipt", ".html", ".htm", ".mp3", ".mp4",
}

# Extensions that the shell will execute.
_EXECUTABLE_EXTS = {
    ".exe", ".scr", ".com", ".pif", ".bat", ".cmd", ".js", ".jse",
    ".vbs", ".vbe", ".wsf", ".wsh", ".hta", ".cpl", ".msi", ".jar",
    ".ps1", ".lnk", ".reg",
}


def double_extension(name: str) -> str:
    """Return the deceptive stem when a filename hides an executable.

    ``invoice.pdf.exe`` returns ``"invoice.pdf"``: the shell runs it, but a
    user reading the name sees a PDF. Returns ``""`` when the name is honest.

    This is a *filename* property, so it cannot live in a YARA rule - rules see
    content, and a content rule for this matches the literal string ``.com``
    inside any binary that mentions a URL. That is exactly the false positive
    that flagged curl.exe and six other signed Windows binaries.
    """
    parts = Path(name).name.split(".")
    if len(parts) < 3:
        return ""
    final = "." + parts[-1].lower()
    if final not in _EXECUTABLE_EXTS:
        return ""
    # Walk back over the stem to find a document extension immediately before
    # the executable one. ``a.b.pdf.exe`` is deceptive; ``v1.2.exe`` is not.
    previous = "." + parts[-2].lower()
    if previous in _DOCUMENT_EXTS:
        return ".".join(parts[:-1])
    return ""


# --------------------------------------------------------------------------- #
# Combined assessment
# --------------------------------------------------------------------------- #

@dataclass
class ReputationAssessment:
    """Everything the local signals say about a file."""

    motw: MotwInfo = field(default_factory=MotwInfo)
    signature: SignatureInfo = field(default_factory=SignatureInfo)
    pe: PeInfo = field(default_factory=PeInfo)
    risk: int = 0
    flags: list[str] = field(default_factory=list)
    error: str = ""
    double_extension: str = ""

    @property
    def is_suspicious(self) -> bool:
        """True when the local signals justify raising the verdict."""
        return self.risk >= 40

    def summary(self) -> str:
        if not self.flags:
            return "No local risk signals"
        return "; ".join(self.flags)


def assess(path: str | Path, *, deep: bool = True) -> ReputationAssessment:
    """Run all local reputation checks on a file.

    ``deep=False`` skips the PE parse, which is the expensive part. Use it when
    the extension already tells you it is not an executable.
    """
    result = ReputationAssessment()

    try:
        result.motw = read_motw(path)
    except Exception as exc:
        log.debug("MOTW read failed", exc_info=True)
        result.error = str(exc)

    try:
        result.signature = verify_authenticode(path)
    except Exception as exc:
        log.debug("Authenticode failed", exc_info=True)

    # A deceptive filename is evidence on its own and needs no PE parse.
    result.double_extension = double_extension(str(path))

    if deep:
        try:
            result.pe = analyze_pe(path)
        except Exception as exc:
            log.debug("PE analysis failed", exc_info=True)

    _score(result)
    return result


def _score(result: ReputationAssessment) -> None:
    """Turn the signals into a risk score and human-readable flags.

    Weights are deliberately conservative. Each signal alone is weak; the score
    only crosses the "suspicious" threshold (40) when several line up, or when a
    single signal is strong on its own (an invalid signature on an executable).

    Calibration note: an unsigned executable is 25 and an internet download is
    20, so the two together (45) cross the threshold. That combination - an
    unsigned binary that arrived from the internet - is the single most common
    shape of a malicious download, and it must not land just under the line.
    """
    risk = 0
    flags: list[str] = []

    # -- MOTW -------------------------------------------------------------- #
    if result.motw.present and result.motw.from_internet:
        risk += 20
        origin = result.motw.host_url or result.motw.referrer_url
        flags.append(
            f"Downloaded from the internet ({result.motw.zone_label})"
            + (f": {origin[:80]}" if origin else "")
        )

    # -- Authenticode ------------------------------------------------------ #
    sig = result.signature.status
    is_executable = result.pe.is_pe
    if sig is SignatureStatus.INVALID:
        risk += 55
        flags.append("Signature is present but does not verify - file was modified")
    elif sig is SignatureStatus.UNTRUSTED:
        risk += 20
        flags.append(f"Signed by an untrusted chain ({result.signature.signer or 'unknown signer'})")
    elif sig is SignatureStatus.UNSIGNED and is_executable:
        risk += 25
        flags.append("Executable is not digitally signed")
    elif sig is SignatureStatus.VALID and result.signature.signer:
        # A valid signature is a genuine positive signal: subtract risk.
        risk -= 15
        flags.append(f"Signed by {result.signature.signer}")

    # -- double extension -------------------------------------------------- #
    # A name like invoice.pdf.exe is deceptive regardless of what the bytes
    # contain, so it scores on its own. 45 clears the 40 threshold: a file
    # pretending to be a document while being executable is the whole attack.
    if result.double_extension:
        risk += 45
        flags.append(
            f"Filename hides an executable behind a document extension: "
            f"{result.double_extension}"
        )

    # -- PE heuristics ----------------------------------------------------- #
    pe = result.pe
    if pe.is_pe:
        if pe.has_injection_triad:
            risk += 45
            flags.append(
                "Imports the process-injection API set "
                "(VirtualAllocEx + WriteProcessMemory + CreateRemoteThread)"
            )
        elif len(pe.suspicious_apis) >= 4:
            risk += 20
            flags.append(
                f"Imports {len(pe.suspicious_apis)} process-manipulation APIs: "
                + ", ".join(pe.suspicious_apis[:6])
            )

        if pe.is_packed:
            risk += 25
            flags.append(
                f"High-entropy section (packed or encrypted): "
                + ", ".join(pe.high_entropy_sections[:3])
            )

        if pe.has_no_imports:
            risk += 25
            flags.append("PE has no import table (packed stub)")

    result.risk = max(0, min(100, risk))
    result.flags = flags


def should_deep_scan(path: str | Path) -> bool:
    """Cheap check: is this worth a PE parse?

    Parsing a 200 MB video is wasted work. Executables and scripts are where the
    heuristics pay off.
    """
    suffix = Path(path).suffix.lower()
    return suffix in {
        ".exe", ".dll", ".sys", ".scr", ".cpl", ".ocx", ".drv", ".efi",
        ".com", ".pif", ".msi", ".msp", ".bat", ".cmd", ".ps1", ".vbs",
        ".js", ".jse", ".wsf", ".hta", ".jar", ".py", ".sh",
    }
