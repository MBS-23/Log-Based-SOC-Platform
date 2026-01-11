"""
SOC Header Widget
-----------------
Top navigation bar for Log-Based SOC Platform.

Features:
• Platform branding (logo + title)
• Logged-in user info
• Theme toggle
• Logout action

UI ONLY
QSS-DRIVEN
ENTERPRISE • SOC-GRADE • EXE-SAFE
"""

from PySide6.QtWidgets import (
    QWidget,
    QLabel,
    QPushButton,
    QHBoxLayout,
    QVBoxLayout,
    QFrame
)
from PySide6.QtCore import Qt, Signal
from PySide6.QtGui import QFont, QPixmap

from pathlib import Path


class Header(QWidget):
    """
    SOC top header bar.
    """

    toggle_theme = Signal()
    logout_requested = Signal()

    def __init__(self, user: dict | None = None):
        super().__init__()

        self.user = user or {}

        self.setObjectName("Header")
        self.setFixedHeight(64)

        self._build_ui()

    # ==================================================
    # UI
    # ==================================================

    def _build_ui(self):
        root = QVBoxLayout(self)
        root.setContentsMargins(0, 0, 0, 0)
        root.setSpacing(0)

        # ---------------- MAIN BAR ----------------
        bar = QFrame()
        bar.setObjectName("HeaderBar")

        bar_layout = QHBoxLayout(bar)
        bar_layout.setContentsMargins(16, 8, 16, 8)
        bar_layout.setSpacing(14)

        # --------------------------------------------------
        # LEFT: LOGO + TITLE
        # --------------------------------------------------
        left_box = QHBoxLayout()
        left_box.setSpacing(10)

        self.logo_label = QLabel()
        self.logo_label.setFixedSize(38, 38)
        self.logo_label.setScaledContents(True)

        self._set_placeholder_logo()

        title_box = QVBoxLayout()
        title_box.setSpacing(0)

        title = QLabel("Log-Based SOC Platform")
        title.setObjectName("HeaderTitle")
        title.setFont(QFont("Segoe UI", 14, QFont.Bold))

        subtitle = QLabel("Threat Detection & SOC Automation")
        subtitle.setObjectName("HeaderSubtitle")

        title_box.addWidget(title)
        title_box.addWidget(subtitle)

        left_box.addWidget(self.logo_label)
        left_box.addLayout(title_box)

        # --------------------------------------------------
        # RIGHT: USER + ACTIONS
        # --------------------------------------------------
        actions = QHBoxLayout()
        actions.setSpacing(10)

        self.user_label = QLabel(
            self.user.get("username", "SOC User")
        )
        self.user_label.setObjectName("HeaderUser")

        theme_btn = QPushButton("🌗 Theme")
        theme_btn.setObjectName("HeaderButton")
        theme_btn.setCursor(Qt.PointingHandCursor)
        theme_btn.clicked.connect(self.toggle_theme.emit)

        logout_btn = QPushButton("Logout")
        logout_btn.setObjectName("HeaderDangerButton")
        logout_btn.setCursor(Qt.PointingHandCursor)
        logout_btn.clicked.connect(self.logout_requested.emit)

        actions.addWidget(self.user_label)
        actions.addWidget(theme_btn)
        actions.addWidget(logout_btn)

        # --------------------------------------------------
        # ASSEMBLE BAR
        # --------------------------------------------------
        bar_layout.addLayout(left_box)
        bar_layout.addStretch()
        bar_layout.addLayout(actions)

        # ---------------- BOTTOM GLOW LINE ----------------
        glow = QFrame()
        glow.setObjectName("HeaderGlow")
        glow.setFixedHeight(2)

        # ---------------- ASSEMBLE ROOT ----------------
        root.addWidget(bar)
        root.addWidget(glow)

    # ==================================================
    # LOGO HANDLING
    # ==================================================

    def set_logo(self, image_path: Path):
        """
        Set header logo safely.
        Called by theme manager.
        """
        if image_path.exists():
            self.logo_label.setPixmap(QPixmap(str(image_path)))

    def _set_placeholder_logo(self):
        """
        Safe placeholder if logo not yet loaded.
        """
        self.logo_label.setText("SOC")
        self.logo_label.setAlignment(Qt.AlignCenter)
        self.logo_label.setStyleSheet(
            """
            QLabel {
                background-color: #1e293b;
                color: #e5e7eb;
                border-radius: 8px;
                font-weight: bold;
                font-size: 12px;
            }
            """
        )

    # ==================================================
    # PUBLIC API
    # ==================================================

    def update_user(self, user: dict):
        """
        Update displayed user info.
        """
        self.user = user or {}
        self.user_label.setText(
            self.user.get("username", "SOC User")
        )
