"""HybridShield - Windows hybrid file scanner.

Entry point. Sets up logging, applies the dark theme, and shows the dashboard.

Run from source:
    python main.py

Package for Windows:
    build.bat
"""

from __future__ import annotations

import logging
import logging.handlers
import os
import sys
import traceback
from pathlib import Path

# --------------------------------------------------------------------------- #
# Crash safety: log before importing anything heavy so a bad dependency still
# produces a readable log file.
# --------------------------------------------------------------------------- #

def _configure_logging() -> Path:
    from scanner.config import LOG_PATH

    handler = logging.handlers.RotatingFileHandler(
        LOG_PATH, maxBytes=2_000_000, backupCount=3, encoding="utf-8"
    )
    handler.setFormatter(
        logging.Formatter("%(asctime)s %(levelname)-8s %(name)s: %(message)s")
    )
    root = logging.getLogger()
    root.setLevel(logging.INFO)
    root.addHandler(handler)

    if sys.stderr is not None:
        console = logging.StreamHandler(sys.stderr)
        console.setFormatter(logging.Formatter("%(levelname)-8s %(name)s: %(message)s"))
        root.addHandler(console)

    return LOG_PATH


LOG_FILE = _configure_logging()
log = logging.getLogger("hybridshield")


def _install_excepthook() -> None:
    """Surface unhandled exceptions instead of dying silently in --windowed."""

    def hook(exc_type, exc_value, exc_tb) -> None:
        if issubclass(exc_type, KeyboardInterrupt):
            sys.__excepthook__(exc_type, exc_value, exc_tb)
            return
        text = "".join(traceback.format_exception(exc_type, exc_value, exc_tb))
        log.critical("Unhandled exception:\n%s", text)
        try:
            from PySide6.QtWidgets import QApplication, QMessageBox

            if QApplication.instance() is not None:
                QMessageBox.critical(
                    None,
                    "HybridShield - unexpected error",
                    f"Something went wrong:\n\n{exc_value}\n\n"
                    f"Details were written to:\n{LOG_FILE}",
                )
        except Exception:
            pass

    sys.excepthook = hook


def main() -> int:
    _install_excepthook()

    try:
        from PySide6.QtCore import Qt
        from PySide6.QtGui import QIcon
        from PySide6.QtWidgets import QApplication, QMessageBox
    except ImportError as exc:
        print(
            "PySide6 is not installed.\n"
            "Install the dependencies first:\n\n"
            "    pip install -r requirements.txt\n\n"
            f"({exc})",
            file=sys.stderr,
        )
        return 1

    # Windows taskbar identity: without this the app groups under python.exe
    # and shows the generic interpreter icon.
    if sys.platform == "win32":
        try:
            import ctypes

            ctypes.windll.shell32.SetCurrentProcessExplicitAppUserModelID(
                "HybridShield.Scanner.1"
            )
        except Exception:
            log.debug("Could not set AppUserModelID", exc_info=True)

    QApplication.setAttribute(Qt.ApplicationAttribute.AA_DontCreateNativeWidgetSiblings, True)

    app = QApplication(sys.argv)
    app.setApplicationName("HybridShield")
    app.setApplicationDisplayName("HybridShield")
    app.setOrganizationName("HybridShield")
    app.setQuitOnLastWindowClosed(False)  # tray keeps the app alive

    from scanner.config import APP_NAME, APP_VERSION, settings
    from ui import theme
    from ui.main_window import MainWindow

    app.setStyleSheet(theme.STYLESHEET)

    log.info("Starting %s %s (Python %s)", APP_NAME, APP_VERSION,
             sys.version.split()[0])
    log.info("Data directory: %s", settings._path.parent)  # noqa: SLF001

    # Single-instance guard: two copies would fight over the same watch folder
    # and the same SQLite file, so refuse to start the second one.
    if not _acquire_single_instance():
        QMessageBox.information(
            None,
            "HybridShield is already running",
            "Another copy of HybridShield is already running.\n\n"
            "Look for its icon in the system tray.",
        )
        log.warning("Second instance started; exiting")
        return 0

    try:
        window = MainWindow(settings)
    except Exception as exc:
        log.exception("Could not create the main window")
        QMessageBox.critical(
            None,
            "HybridShield could not start",
            f"The application failed to start:\n\n{exc}\n\nLog: {LOG_FILE}",
        )
        return 1

    window.show()
    return app.exec()


def _acquire_single_instance() -> bool:
    """Best-effort single-instance guard using a named mutex on Windows."""
    if sys.platform != "win32":
        return True
    try:
        import ctypes
        from ctypes import wintypes

        kernel32 = ctypes.WinDLL("kernel32", use_last_error=True)
        kernel32.CreateMutexW.restype = wintypes.HANDLE
        kernel32.CreateMutexW.argtypes = [wintypes.LPCVOID, wintypes.BOOL,
                                          wintypes.LPCWSTR]
        handle = kernel32.CreateMutexW(None, True, "Global\\HybridShieldScannerMutex")
        if not handle:
            return True  # cannot determine: allow the app to run
        already_exists = ctypes.get_last_error() == 183  # ERROR_ALREADY_EXISTS
        # Keep the handle referenced for the process lifetime.
        _acquire_single_instance.handle = handle  # type: ignore[attr-defined]
        return not already_exists
    except Exception:
        log.debug("Single-instance check failed", exc_info=True)
        return True


if __name__ == "__main__":
    sys.exit(main())
