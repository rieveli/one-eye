"""One Eye entry point.  Run:  python main.py"""
import sys

SPLASH_MS = 1400   # animated intro before the (blocking) window build


def splash(app):
    from PySide6.QtCore import Qt
    from PySide6.QtWidgets import QLabel, QVBoxLayout, QWidget

    from secdash.ui import theme
    from secdash.ui.eye import EyeWidget

    w = QWidget(None, Qt.SplashScreen | Qt.FramelessWindowHint)
    w.setStyleSheet(f"background: {theme.BG};")
    lay = QVBoxLayout(w)
    lay.setContentsMargins(60, 40, 60, 36)
    lay.setSpacing(6)
    lay.addWidget(EyeWidget(260), 0, Qt.AlignHCenter)
    for text, css in (("ONE EYE", "font-size: 34px; font-weight: 800; letter-spacing: 6px;"),
                      ("LOCAL ENDPOINT SECURITY & INTELLIGENCE", f"color: {theme.MUTED}; letter-spacing: 3px;"),
                      ("SEE. ANALYSE. STAY AHEAD.", f"color: {theme.ACCENT}; letter-spacing: 3px; margin-top: 10px;")):
        lbl = QLabel(text)
        lbl.setStyleSheet(css)
        lay.addWidget(lbl, 0, Qt.AlignHCenter)
    w.show()
    return w


def main():
    from PySide6.QtCore import QTimer
    from PySide6.QtGui import QIcon
    from PySide6.QtWidgets import QApplication

    from secdash import APP_NAME
    from secdash.ui.eye import asset
    from secdash.ui.theme import QSS

    app = QApplication(sys.argv)
    app.setApplicationName(APP_NAME)
    app.setWindowIcon(QIcon(asset("icon.ico")))
    app.setStyle("Fusion")
    app.setStyleSheet(QSS)
    intro = splash(app)

    def build():
        from secdash.core.settings import Settings
        from secdash.ui.main_window import MainWindow
        app.window = MainWindow(Settings())
        app.window.show()
        intro.close()

    QTimer.singleShot(SPLASH_MS, build)
    sys.exit(app.exec())


if __name__ == "__main__":
    from secdash.core import demo
    if demo.FLAG in sys.argv:          # the harmless demo threat: same exe, no UI
        demo.main_from_argv(sys.argv)
    else:
        main()
