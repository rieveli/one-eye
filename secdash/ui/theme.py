"""One Eye theme: black / dark grey / white with the logo's crimson.
Brand red (ACCENT) is for buttons and highlights; alerts use DANGER plus a text label
(HIGH, MALICIOUS...), so color is never the only signal."""

BG = "#0A0A0C"
SURFACE = "#131316"
RAISED = "#1C1C20"
BORDER = "#2C2C33"
TEXT = "#F2F2F4"
MUTED = "#9A9AA3"
ACCENT = "#D7263D"
ACCENT_HOVER = "#EE3A51"
INFO = "#8AB4F8"
OK = "#3FB950"
WARN = "#E3B341"
DANGER = "#FF5A5F"
MONO = "Cascadia Mono, Consolas, monospace"

SEVERITY_COLORS = {"HIGH": DANGER, "MED": WARN, "LOW": INFO, "OK": OK}
CATEGORY_COLORS = {
    "Browser": "#58A6FF", "Game": "#BC8CFF", "Communication": "#3FB950", "System": MUTED,
    "Background": WARN, "Development": "#22D3EE", "Media": "#F778BA", "Security": OK, "Installed app": "#79C0FF", "Unknown": DANGER, "Protected": WARN,
}

QSS = f"""
* {{ font-family: "Segoe UI"; font-size: 13px; color: {TEXT}; }}
QMainWindow, QWidget#root {{ background: {BG}; }}
QWidget#page {{ background: {BG}; }}

QWidget#sidebar {{ background: {SURFACE}; border-right: 1px solid {BORDER}; }}
QLabel#brand {{ font-size: 19px; font-weight: 800; letter-spacing: 3px; }}
QLabel#brandSub {{ color: {MUTED}; font-size: 11px; }}
QListWidget#nav {{ background: transparent; border: none; outline: none; }}
QListWidget#nav::item {{ padding: 10px 14px; margin: 2px 8px; border-radius: 6px; color: {MUTED};
                         border-left: 3px solid transparent; }}
QListWidget#nav::item:hover {{ background: {RAISED}; color: {TEXT}; }}
QListWidget#nav::item:selected {{ background: {RAISED}; color: {TEXT}; border-left: 3px solid {ACCENT}; }}
QFrame#statusBlock {{ background: {RAISED}; border: 1px solid {BORDER}; border-radius: 8px; margin: 10px; }}
QLabel#statusLine {{ color: {MUTED}; font-size: 11px; }}

QLabel#pageTitle {{ font-size: 22px; font-weight: 700; }}
QLabel#pageSub {{ color: {MUTED}; }}
QLabel#sectionTitle {{ font-size: 14px; font-weight: 600; }}
QLabel#muted {{ color: {MUTED}; }}
QLabel#note {{ color: {MUTED}; background: {RAISED}; border: 1px solid {BORDER}; border-radius: 6px;
               padding: 8px 10px; }}
QLabel#danger {{ color: {DANGER}; }}

QFrame#card {{ background: {SURFACE}; border: 1px solid {BORDER}; border-radius: 8px; }}
QLabel#cardLabel {{ color: {MUTED}; font-size: 12px; }}
QLabel#cardValue {{ font-size: 26px; font-weight: 700; font-family: {MONO}; }}
QLabel#cardSub {{ color: {MUTED}; font-size: 11px; font-family: {MONO}; }}

QPushButton {{ background: {RAISED}; border: 1px solid {BORDER}; border-radius: 6px; padding: 7px 14px; }}
QPushButton:hover {{ border-color: {ACCENT}; }}
QPushButton:pressed {{ background: {BORDER}; }}
QPushButton:checked {{ border-color: {WARN}; color: {WARN}; }}
QPushButton:disabled {{ color: {MUTED}; border-color: {BORDER}; }}
QPushButton#primary {{ background: {ACCENT}; color: {TEXT}; border: 1px solid {ACCENT}; font-weight: 600; }}
QPushButton#primary:hover {{ background: {ACCENT_HOVER}; border-color: {ACCENT_HOVER}; }}
QPushButton#primary:disabled {{ background: {RAISED}; color: {MUTED}; border-color: {BORDER}; }}
QPushButton#danger {{ background: transparent; color: {DANGER}; border: 1px solid {DANGER}; }}
QPushButton#danger:hover {{ background: #2A1517; }}

QLineEdit, QComboBox, QSpinBox, QDoubleSpinBox, QPlainTextEdit, QTextEdit {{
    background: {SURFACE}; border: 1px solid {BORDER}; border-radius: 6px; padding: 6px 8px;
    selection-background-color: {ACCENT}; selection-color: {TEXT}; }}
QLineEdit:focus, QComboBox:focus, QSpinBox:focus, QPlainTextEdit:focus, QTextEdit:focus {{ border-color: {ACCENT}; }}
QComboBox QAbstractItemView {{ background: {SURFACE}; border: 1px solid {BORDER}; selection-background-color: {RAISED}; }}
QCheckBox {{ spacing: 8px; }}

QTableWidget {{ background: {SURFACE}; border: 1px solid {BORDER}; border-radius: 8px; gridline-color: {BORDER};
                alternate-background-color: #141B25; selection-background-color: {RAISED}; selection-color: {TEXT}; }}
QTableWidget::item {{ padding: 4px 6px; border: none; }}
QHeaderView::section {{ background: {RAISED}; color: {MUTED}; border: none; border-bottom: 1px solid {BORDER};
                        padding: 6px; font-weight: 600; }}
QTableCornerButton::section {{ background: {RAISED}; border: none; }}

QListWidget#alerts {{ background: {SURFACE}; border: 1px solid {BORDER}; border-radius: 8px; padding: 4px; }}
QListWidget#alerts::item {{ padding: 6px; border-bottom: 1px solid {BORDER}; }}

QProgressBar {{ background: {SURFACE}; border: 1px solid {BORDER}; border-radius: 6px; text-align: center; height: 16px; }}
QProgressBar::chunk {{ background: {ACCENT}; border-radius: 5px; }}

QScrollBar:vertical {{ background: transparent; width: 10px; margin: 2px; }}
QScrollBar::handle:vertical {{ background: {BORDER}; border-radius: 4px; min-height: 30px; }}
QScrollBar::add-line, QScrollBar::sub-line {{ height: 0; width: 0; }}
QScrollBar:horizontal {{ background: transparent; height: 10px; margin: 2px; }}
QScrollBar::handle:horizontal {{ background: {BORDER}; border-radius: 4px; min-width: 30px; }}
QToolTip {{ background: {RAISED}; color: {TEXT}; border: 1px solid {BORDER}; padding: 4px; }}
QMessageBox {{ background: {SURFACE}; }}
"""
