"""Application paths and persisted settings.

Everything the app writes lives under %LOCALAPPDATA%\\HybridShield so that a
PyInstaller --onedir build (which may sit in a read-only or Program Files
location) never needs write access next to the executable.

API keys are stored locally in settings.json with the file ACL locked down to
the current user. They are never logged, never sent anywhere except to the
provider that owns them, and never included in scan results.
"""

from __future__ import annotations

import json
import logging
import os
import sys
import threading
from pathlib import Path
from typing import Any

log = logging.getLogger(__name__)

APP_NAME = "HybridShield"
APP_VERSION = "1.0.0"

# Settings keys whose values are encrypted at rest with DPAPI.
SECRET_KEYS = ("mb_auth_key", "opswat_api_key")
_SECRET_PREFIX = "dpapi:"


# --------------------------------------------------------------------------- #
# DPAPI secret protection
# --------------------------------------------------------------------------- #

def _dpapi_available() -> bool:
    return sys.platform == "win32"


def protect_secret(plaintext: str) -> str:
    """Encrypt a secret for the current Windows user.

    Uses DPAPI (``CryptProtectData``) with the user's own credentials as the
    key material. The ciphertext is bound to that user account: another account
    on the same machine, or the same file copied to another machine, cannot
    decrypt it. No key is stored anywhere, so there is no key to steal.

    The ``dpapi:`` prefix marks the value as encrypted, so a settings file
    written by an older build (plaintext) still loads and is upgraded on the
    next save.
    """
    if not plaintext:
        return ""
    if not _dpapi_available():
        # Non-Windows development: keep the value usable, clearly marked.
        return plaintext
    try:
        blob = _crypt_protect(plaintext.encode("utf-8"))
    except Exception:
        log.warning("DPAPI encryption failed; storing secret unprotected", exc_info=True)
        return plaintext
    import base64

    return _SECRET_PREFIX + base64.b64encode(blob).decode("ascii")


def unprotect_secret(stored: str) -> str:
    """Decrypt a value produced by :func:`protect_secret`.

    A value without the ``dpapi:`` prefix is treated as legacy plaintext and
    returned unchanged, so existing installs keep working.
    """
    if not stored:
        return ""
    if not stored.startswith(_SECRET_PREFIX):
        return stored
    if not _dpapi_available():
        return ""
    import base64

    try:
        blob = base64.b64decode(stored[len(_SECRET_PREFIX):].encode("ascii"))
        return _crypt_unprotect(blob).decode("utf-8")
    except Exception:
        # Wrong user, corrupted blob, or tampering. Treat as "no key" rather
        # than crashing: the user can simply re-enter it.
        log.warning("Could not decrypt a stored secret; it will need re-entering")
        return ""


def _crypt_protect(data: bytes) -> bytes:
    """Thin ctypes wrapper over CryptProtectData."""
    import ctypes
    from ctypes import wintypes

    class DATA_BLOB(ctypes.Structure):
        _fields_ = [("cbData", wintypes.DWORD),
                    ("pbData", ctypes.POINTER(ctypes.c_char))]

    def to_blob(raw: bytes) -> DATA_BLOB:
        buffer = ctypes.create_string_buffer(raw, len(raw))
        return DATA_BLOB(len(raw), ctypes.cast(buffer, ctypes.POINTER(ctypes.c_char)))

    crypt32 = ctypes.WinDLL("crypt32", use_last_error=True)
    kernel32 = ctypes.WinDLL("kernel32", use_last_error=True)
    crypt32.CryptProtectData.restype = wintypes.BOOL

    blob_in = to_blob(data)
    blob_out = DATA_BLOB()
    ok = crypt32.CryptProtectData(
        ctypes.byref(blob_in),
        "HybridShield",
        None, None, None,
        0x01,                      # CRYPTPROTECT_UI_FORBIDDEN
        ctypes.byref(blob_out),
    )
    if not ok:
        raise OSError(ctypes.get_last_error(), "CryptProtectData failed")
    try:
        return ctypes.string_at(blob_out.pbData, blob_out.cbData)
    finally:
        kernel32.LocalFree(blob_out.pbData)


def _crypt_unprotect(blob: bytes) -> bytes:
    """Thin ctypes wrapper over CryptUnprotectData."""
    import ctypes
    from ctypes import wintypes

    class DATA_BLOB(ctypes.Structure):
        _fields_ = [("cbData", wintypes.DWORD),
                    ("pbData", ctypes.POINTER(ctypes.c_char))]

    def to_blob(raw: bytes) -> DATA_BLOB:
        buffer = ctypes.create_string_buffer(raw, len(raw))
        return DATA_BLOB(len(raw), ctypes.cast(buffer, ctypes.POINTER(ctypes.c_char)))

    crypt32 = ctypes.WinDLL("crypt32", use_last_error=True)
    kernel32 = ctypes.WinDLL("kernel32", use_last_error=True)
    crypt32.CryptUnprotectData.restype = wintypes.BOOL

    blob_in = to_blob(blob)
    blob_out = DATA_BLOB()
    ok = crypt32.CryptUnprotectData(
        ctypes.byref(blob_in),
        None, None, None, None,
        0x01,                      # CRYPTPROTECT_UI_FORBIDDEN
        ctypes.byref(blob_out),
    )
    if not ok:
        raise OSError(ctypes.get_last_error(), "CryptUnprotectData failed")
    try:
        return ctypes.string_at(blob_out.pbData, blob_out.cbData)
    finally:
        kernel32.LocalFree(blob_out.pbData)

# --------------------------------------------------------------------------- #
# Paths
# --------------------------------------------------------------------------- #

def _app_data_dir() -> Path:
    """Return the per-user writable data directory, creating it if needed."""
    if sys.platform == "win32":
        base = os.environ.get("LOCALAPPDATA") or os.environ.get("APPDATA")
        root = Path(base) if base else Path.home() / "AppData" / "Local"
    else:
        # Keeps the app importable on macOS/Linux for development and tests.
        base = os.environ.get("XDG_DATA_HOME")
        root = Path(base) if base else Path.home() / ".local" / "share"
    path = root / APP_NAME
    path.mkdir(parents=True, exist_ok=True)
    return path


DATA_DIR: Path = _app_data_dir()
DB_PATH: Path = DATA_DIR / "scan_history.db"
SETTINGS_PATH: Path = DATA_DIR / "settings.json"
LOG_PATH: Path = DATA_DIR / "hybridshield.log"

# Default folder to watch: the real Downloads folder, resolved per user.
def default_watch_folder() -> str:
    downloads = Path.home() / "Downloads"
    return str(downloads if downloads.is_dir() else Path.home())


# --------------------------------------------------------------------------- #
# Settings
# --------------------------------------------------------------------------- #

DEFAULT_SETTINGS: dict[str, Any] = {
    "mb_auth_key": "",
    "opswat_api_key": "",
    "watch_folder": "",          # empty -> default_watch_folder()
    "watcher_enabled": False,
    "cache_ttl_hours": 24,
    "minimize_to_tray": True,
    "notify_on_clean": False,
    "auto_quarantine": True,
    "yara_enabled": True,
    "defender_path": r"C:\Program Files\Windows Defender\MpCmdRun.exe",
    "defender_timeout_seconds": 300,
    "http_timeout_seconds": 20,
    "max_scan_workers": 3,
}


class Settings:
    """Thread-safe JSON-backed settings store.

    Writes are atomic (temp file + os.replace) so a crash mid-save cannot
    corrupt the file and lose the user's API keys.
    """

    def __init__(self, path: Path = SETTINGS_PATH) -> None:
        self._path = path
        self._lock = threading.RLock()
        self._data: dict[str, Any] = dict(DEFAULT_SETTINGS)
        self.load()

    # -- persistence ------------------------------------------------------- #

    def load(self) -> None:
        with self._lock:
            if not self._path.exists():
                return
            try:
                raw = json.loads(self._path.read_text(encoding="utf-8"))
            except (OSError, json.JSONDecodeError):
                # Corrupt or unreadable settings: fall back to defaults rather
                # than crashing at startup. The bad file is kept for recovery.
                try:
                    self._path.replace(self._path.with_suffix(".json.bad"))
                except OSError:
                    pass
                return
            if isinstance(raw, dict):
                for key, value in raw.items():
                    if key not in DEFAULT_SETTINGS:
                        continue
                    if key in SECRET_KEYS and isinstance(value, str):
                        # Decrypt on load so the rest of the app only ever sees
                        # plaintext in memory. Legacy plaintext passes through.
                        self._data[key] = unprotect_secret(value)
                    else:
                        self._data[key] = value

    def save(self) -> None:
        with self._lock:
            self._path.parent.mkdir(parents=True, exist_ok=True)
            tmp = self._path.with_suffix(".json.tmp")

            # Encrypt secrets at rest; everything else is plain JSON.
            payload_data = dict(self._data)
            for key in SECRET_KEYS:
                value = payload_data.get(key)
                if isinstance(value, str) and value:
                    payload_data[key] = protect_secret(value)

            payload = json.dumps(payload_data, indent=2, ensure_ascii=False)
            tmp.write_text(payload, encoding="utf-8")
            try:
                _restrict_to_current_user(tmp)
            except OSError:
                pass
            os.replace(tmp, self._path)

    # -- accessors --------------------------------------------------------- #

    def get(self, key: str, default: Any = None) -> Any:
        with self._lock:
            return self._data.get(key, DEFAULT_SETTINGS.get(key, default))

    def set(self, key: str, value: Any) -> None:
        with self._lock:
            self._data[key] = value

    def update(self, values: dict[str, Any]) -> None:
        with self._lock:
            self._data.update(values)

    def as_dict(self) -> dict[str, Any]:
        with self._lock:
            return dict(self._data)

    # -- derived ----------------------------------------------------------- #

    @property
    def watch_folder(self) -> str:
        configured = str(self.get("watch_folder") or "").strip()
        return configured or default_watch_folder()

    @property
    def has_mb_key(self) -> bool:
        return bool(str(self.get("mb_auth_key") or "").strip())

    @property
    def has_opswat_key(self) -> bool:
        return bool(str(self.get("opswat_api_key") or "").strip())


def _restrict_to_current_user(path: Path) -> None:
    """Best-effort ACL lock-down of a file on Windows.

    Uses icacls to remove inherited permissions and grant the current user full
    control only. Failure is non-fatal: the file still lives in the user's own
    profile directory, which is already user-scoped by default.
    """
    if sys.platform != "win32":
        try:
            path.chmod(0o600)
        except OSError:
            pass
        return

    import subprocess

    user = os.environ.get("USERNAME")
    if not user:
        return
    try:
        subprocess.run(
            ["icacls", str(path), "/inheritance:r", "/grant:r", f"{user}:F"],
            capture_output=True,
            timeout=15,
            check=False,
            creationflags=getattr(subprocess, "CREATE_NO_WINDOW", 0),
        )
    except (OSError, subprocess.SubprocessError):
        pass


# A single shared instance for the process. Tests may construct their own.
settings = Settings()
