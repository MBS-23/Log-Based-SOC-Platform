"""
SOC Sidebar Widget
------------------
Primary navigation panel for Log-Based SOC Platform.

• Icon + text navigation
• Proper padding & alignment
• Active indicator bar
• Section separation
• Enterprise SOC-grade UI
"""

from pathlib import Path
from PySide6.QtWidgets import QWidget, QPushButton, QVBoxLayout, QLabel, QFrame
from PySide6.QtCore import Qt, Signal, QSize
from PySide6.QtGui import QFont, QIcon

# --------------------------------------------------
# RESOURCE PATHS
# --------------------------------------------------
BASE_DIR = Path(__file__).resolve().parents[2]
ICON_DIR = BASE_DIR / "frontend" / "resources" / "icons"


class Sidebar(QWidget):
    navigate = Signal(str)

    def __init__(self, parent=None):
        super().__init__(parent)

        self.setObjectName("Sidebar")
        self.setFixedWidth(240)

        self._buttons: dict[str, QPushButton] = {}
        self._active_key: str | None = None

        self._build_ui()

    # ==================================================
    # UI
    # ==================================================

    def _build_ui(self):
        layout = QVBoxLayout(self)
        layout.setContentsMargins(12, 16, 12, 16)
        layout.setSpacing(6)

        # ---------------- HEADER ----------------
        title = QLabel("SOC NAVIGATION")
        title.setAlignment(Qt.AlignCenter)
        title.setFont(QFont("Segoe UI", 10, QFont.Bold))
        title.setObjectName("SidebarTitle")

        layout.addWidget(title)
        layout.addSpacing(8)

        self._add_separator(layout)

        # ---------------- NAV ITEMS ----------------
        self._add_nav_button("dashboard", "Dashboard", "dashboard.png")
        self._add_nav_button("log_viewer", "Log Viewer", "logs.png")
        self._add_nav_button("analytics", "Analytics", "analytics.png")

        self._add_separator(layout)

        self._add_nav_button("blocked_ips", "Blocked IPs", "blocked.png")
        self._add_nav_button("rules", "Detection Rules", "rules.png")

        self._add_separator(layout)

        self._add_nav_button("project_info", "Project Info", "project.png")

        layout.addStretch()

        # ---------------- FOOTER ----------------
        footer = QLabel("© Log SOC Platform")
        footer.setAlignment(Qt.AlignCenter)
        footer.setObjectName("SidebarFooter")
        layout.addWidget(footer)

        self.set_active("dashboard")

    # ==================================================
    # SEPARATOR
    # ==================================================

    def _add_separator(self, layout: QVBoxLayout):
        sep = QFrame()
        sep.setObjectName("SidebarSeparator")
        sep.setFixedHeight(1)
        layout.addWidget(sep)
        layout.addSpacing(6)

    # ==================================================
    # NAV BUTTON FACTORY
    # ==================================================

    def _add_nav_button(self, key: str, text: str, icon_name: str):
        btn = QPushButton(text)
        btn.setObjectName("SidebarButton")
        btn.setCheckable(True)
        btn.setCursor(Qt.PointingHandCursor)
        btn.setFixedHeight(40)

        icon_path = ICON_DIR / icon_name
        if icon_path.exists():
            btn.setIcon(QIcon(str(icon_path)))
            btn.setIconSize(QSize(18, 18))

        btn.setLayoutDirection(Qt.LeftToRight)
        btn.clicked.connect(lambda _, k=key: self._on_nav_clicked(k))

        self._buttons[key] = btn
        self.layout().addWidget(btn)

    # ==================================================
    # EVENTS
    # ==================================================

    def _on_nav_clicked(self, key: str):
        self.set_active(key)
        self.navigate.emit(key)

    # ==================================================
    # ACTIVE STATE
    # ==================================================

    def set_active(self, key: str):
        if self._active_key == key:
            return

        for k, btn in self._buttons.items():
            btn.setChecked(k == key)

        self._active_key = key
