"""
SOC Project Information View
----------------------------
Opens project documentation in the system browser.

✔ Opens HTML externally (Chrome / Edge / Firefox)
✔ EXE-safe (PyInstaller)
✔ No embedded rendering
✔ Zero UI overhead
✔ SOC-grade simplicity
"""

import sys
import webbrowser
from pathlib import Path

from PySide6.QtWidgets import QWidget, QMessageBox
from PySide6.QtCore import QTimer


def resource_path(relative: str) -> Path:
    """
    Resolve resource path for both:
    - normal Python execution
    - PyInstaller EXE (_MEIPASS)
    """
    if hasattr(sys, "_MEIPASS"):
        return Path(sys._MEIPASS) / relative
    return Path(__file__).resolve().parents[2] / relative


class ProjectInfoView(QWidget):
    """
    Launcher-only view.
    Immediately opens project_info.html in system browser.
    """

    def __init__(self, parent=None):
        super().__init__(parent)
        self._html_path = resource_path("assets/project_info.html")

    # ==================================================
    # NAVIGATION LIFECYCLE
    # ==================================================

    def on_navigate(self):
        """
        Called by NavigationManager when Project Info is clicked.
        """
        QTimer.singleShot(0, self._open_in_browser)

    # ==================================================
    # ACTION
    # ==================================================

    def _open_in_browser(self):
        if not self._html_path.exists():
            QMessageBox.critical(
                self,
                "Project Info Not Found",
                f"project_info.html was not found at:\n\n{self._html_path}"
            )
            self._go_back()
            return

        # 🔥 Open in default browser
        webbrowser.open(self._html_path.as_uri())

        # Immediately return to dashboard
        self._go_back()

    # ==================================================
    # NAVIGATION
    # ==================================================

    def _go_back(self):
        """
        Return to dashboard cleanly.
        """
        window = self.window()
        if hasattr(window, "navigator"):
            window.navigator.navigate("dashboard")
