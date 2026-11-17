"""Dark theme: palette constants and the application stylesheet.

Kept in one module so the dashboard, the settings dialog and the tray menu all
draw from the same tokens. Colours are chosen for contrast on a dark surface
and for legibility of the verdict column at a glance.
"""

from __future__ import annotations

# --------------------------------------------------------------------------- #
# Palette
# --------------------------------------------------------------------------- #

BG_BASE = "#0f1216"        # window background
BG_SURFACE = "#161b22"     # cards, panels
BG_ELEVATED = "#1c232c"    # inputs, hovered rows
BG_HOVER = "#232c37"
BORDER = "#2a3441"
BORDER_STRONG = "#3a4756"

TEXT_PRIMARY = "#e6edf3"
TEXT_SECONDARY = "#9aa7b4"
TEXT_MUTED = "#6b7885"

ACCENT = "#3d8bfd"         # primary action
ACCENT_HOVER = "#5a9dff"
ACCENT_PRESSED = "#2f74d9"

GREEN = "#2ea043"          # clean
GREEN_BG = "#0d2a17"
RED = "#f85149"            # malicious
RED_BG = "#2d1214"
AMBER = "#d29922"          # suspicious
AMBER_BG = "#2b2110"
GREY = "#6b7885"           # unknown / skipped
GREY_BG = "#1a1f26"

# Verdict -> (foreground, background) for table cells and pills.
VERDICT_COLORS: dict[str, tuple[str, str]] = {
    "Clean": (GREEN, GREEN_BG),
    "Malicious": (RED, RED_BG),
    "Suspicious": (AMBER, AMBER_BG),
    "Unknown": (GREY, GREY_BG),
    "Error": (RED, RED_BG),
    "Not Found": (GREY, GREY_BG),
    "Skipped": (TEXT_MUTED, GREY_BG),
    "Scanning": (ACCENT, "#12233d"),
}


def color_for(status: str) -> tuple[str, str]:
    """Foreground/background pair for a status or verdict string."""
    return VERDICT_COLORS.get(status, (TEXT_SECONDARY, GREY_BG))


# --------------------------------------------------------------------------- #
# Stylesheet
# --------------------------------------------------------------------------- #

STYLESHEET = f"""
* {{
    font-family: "Segoe UI", "Inter", system-ui, sans-serif;
    font-size: 13px;
}}

QWidget {{
    background-color: {BG_BASE};
    color: {TEXT_PRIMARY};
}}

QMainWindow, QDialog {{
    background-color: {BG_BASE};
}}

/* ---------------------------------------------------------------- cards -- */
QFrame#Card {{
    background-color: {BG_SURFACE};
    border: 1px solid {BORDER};
    border-radius: 10px;
}}

QFrame#DropZone {{
    background-color: {BG_SURFACE};
    border: 2px dashed {BORDER_STRONG};
    border-radius: 12px;
}}

QFrame#DropZone[dragActive="true"] {{
    border: 2px dashed {ACCENT};
    background-color: #14243a;
}}

/* --------------------------------------------------------------- labels -- */
QLabel {{
    background: transparent;
    color: {TEXT_PRIMARY};
}}

QLabel#Title {{
    font-size: 20px;
    font-weight: 600;
    color: {TEXT_PRIMARY};
}}

QLabel#Subtitle {{
    font-size: 12px;
    color: {TEXT_SECONDARY};
}}

QLabel#SectionTitle {{
    font-size: 13px;
    font-weight: 600;
    color: {TEXT_PRIMARY};
}}

QLabel#Hint {{
    font-size: 12px;
    color: {TEXT_MUTED};
}}

QLabel#DropTitle {{
    font-size: 15px;
    font-weight: 600;
    color: {TEXT_PRIMARY};
}}

QLabel#DropHint {{
    font-size: 12px;
    color: {TEXT_MUTED};
}}

QLabel#StatValue {{
    font-size: 22px;
    font-weight: 600;
    color: {TEXT_PRIMARY};
}}

QLabel#StatLabel {{
    font-size: 11px;
    color: {TEXT_MUTED};
    text-transform: uppercase;
    letter-spacing: 1px;
}}

QLabel#StatusBar {{
    font-size: 12px;
    color: {TEXT_SECONDARY};
}}

/* -------------------------------------------------------------- buttons -- */
QPushButton {{
    background-color: {BG_ELEVATED};
    color: {TEXT_PRIMARY};
    border: 1px solid {BORDER_STRONG};
    border-radius: 7px;
    padding: 8px 16px;
    font-weight: 500;
}}

QPushButton:hover {{
    background-color: {BG_HOVER};
    border-color: {ACCENT};
}}

QPushButton:pressed {{
    background-color: {BORDER};
}}

QPushButton:disabled {{
    color: {TEXT_MUTED};
    border-color: {BORDER};
    background-color: {BG_SURFACE};
}}

QPushButton#Primary {{
    background-color: {ACCENT};
    color: #ffffff;
    border: 1px solid {ACCENT};
    font-weight: 600;
}}

QPushButton#Primary:hover {{
    background-color: {ACCENT_HOVER};
    border-color: {ACCENT_HOVER};
}}

QPushButton#Primary:pressed {{
    background-color: {ACCENT_PRESSED};
}}

QPushButton#Primary:disabled {{
    background-color: #24303f;
    color: {TEXT_MUTED};
    border-color: #24303f;
}}

QPushButton#Danger {{
    color: {RED};
    border-color: #4a2124;
}}

QPushButton#Danger:hover {{
    background-color: {RED_BG};
    border-color: {RED};
}}

QPushButton#Ghost {{
    background: transparent;
    border: 1px solid transparent;
    color: {TEXT_SECONDARY};
    padding: 6px 10px;
}}

QPushButton#Ghost:hover {{
    background-color: {BG_ELEVATED};
    color: {TEXT_PRIMARY};
}}

/* --------------------------------------------------------------- inputs -- */
QLineEdit, QSpinBox, QComboBox {{
    background-color: {BG_ELEVATED};
    color: {TEXT_PRIMARY};
    border: 1px solid {BORDER_STRONG};
    border-radius: 7px;
    padding: 8px 10px;
    selection-background-color: {ACCENT};
}}

QLineEdit:focus, QSpinBox:focus, QComboBox:focus {{
    border-color: {ACCENT};
}}

QLineEdit:disabled, QSpinBox:disabled {{
    color: {TEXT_MUTED};
    background-color: {BG_SURFACE};
}}

QComboBox::drop-down {{
    border: none;
    width: 22px;
}}

QComboBox QAbstractItemView {{
    background-color: {BG_ELEVATED};
    border: 1px solid {BORDER_STRONG};
    selection-background-color: {ACCENT};
    outline: none;
}}

QSpinBox::up-button, QSpinBox::down-button {{
    background-color: {BG_HOVER};
    border: none;
    width: 16px;
}}

/* ---------------------------------------------------------------- table -- */
QTableView {{
    background-color: {BG_SURFACE};
    alternate-background-color: {BG_BASE};
    gridline-color: {BORDER};
    border: 1px solid {BORDER};
    border-radius: 10px;
    selection-background-color: #1e3a5f;
    selection-color: {TEXT_PRIMARY};
    outline: none;
}}

QTableView::item {{
    padding: 6px 8px;
    border: none;
}}

QHeaderView::section {{
    background-color: {BG_ELEVATED};
    color: {TEXT_SECONDARY};
    border: none;
    border-bottom: 1px solid {BORDER};
    border-right: 1px solid {BORDER};
    padding: 9px 8px;
    font-size: 11px;
    font-weight: 600;
    text-transform: uppercase;
    letter-spacing: 0.6px;
}}

QHeaderView::section:last {{
    border-right: none;
}}

QTableCornerButton::section {{
    background-color: {BG_ELEVATED};
    border: none;
}}

/* ------------------------------------------------------------ scrollbar -- */
QScrollBar:vertical {{
    background: transparent;
    width: 10px;
    margin: 0;
}}

QScrollBar::handle:vertical {{
    background: {BORDER_STRONG};
    border-radius: 5px;
    min-height: 28px;
}}

QScrollBar::handle:vertical:hover {{
    background: {TEXT_MUTED};
}}

QScrollBar::add-line:vertical, QScrollBar::sub-line:vertical,
QScrollBar::add-page:vertical, QScrollBar::sub-page:vertical {{
    height: 0;
    background: none;
    border: none;
}}

QScrollBar:horizontal {{
    background: transparent;
    height: 10px;
}}

QScrollBar::handle:horizontal {{
    background: {BORDER_STRONG};
    border-radius: 5px;
    min-width: 28px;
}}

QScrollBar::add-line:horizontal, QScrollBar::sub-line:horizontal,
QScrollBar::add-page:horizontal, QScrollBar::sub-page:horizontal {{
    width: 0;
    background: none;
    border: none;
}}

/* -------------------------------------------------------------- toggle --- */
QCheckBox {{
    background: transparent;
    color: {TEXT_PRIMARY};
    spacing: 8px;
}}

QCheckBox::indicator {{
    width: 18px;
    height: 18px;
    border-radius: 4px;
    border: 1px solid {BORDER_STRONG};
    background-color: {BG_ELEVATED};
}}

QCheckBox::indicator:checked {{
    background-color: {ACCENT};
    border-color: {ACCENT};
    image: none;
}}

QCheckBox::indicator:hover {{
    border-color: {ACCENT};
}}

/* --------------------------------------------------------------- misc ---- */
QProgressBar {{
    background-color: {BG_ELEVATED};
    border: none;
    border-radius: 3px;
    height: 5px;
    text-align: center;
    color: transparent;
}}

QProgressBar::chunk {{
    background-color: {ACCENT};
    border-radius: 3px;
}}

QToolTip {{
    background-color: {BG_ELEVATED};
    color: {TEXT_PRIMARY};
    border: 1px solid {BORDER_STRONG};
    padding: 6px;
    border-radius: 6px;
}}

QSplitter::handle {{
    background-color: {BORDER};
}}

QMenu {{
    background-color: {BG_SURFACE};
    border: 1px solid {BORDER_STRONG};
    border-radius: 8px;
    padding: 6px;
}}

QMenu::item {{
    padding: 7px 24px 7px 12px;
    border-radius: 5px;
}}

QMenu::item:selected {{
    background-color: {BG_HOVER};
}}

QMenu::separator {{
    height: 1px;
    background-color: {BORDER};
    margin: 5px 8px;
}}

QGroupBox {{
    border: 1px solid {BORDER};
    border-radius: 10px;
    margin-top: 14px;
    padding: 16px 14px 12px 14px;
    font-weight: 600;
}}

QGroupBox::title {{
    subcontrol-origin: margin;
    subcontrol-position: top left;
    left: 14px;
    padding: 0 6px;
    color: {TEXT_SECONDARY};
    font-size: 11px;
    text-transform: uppercase;
    letter-spacing: 1px;
}}
"""
