"""
SOC Main Window Controller
--------------------------
Top-level application window for Log SOC Platform.

✔ EXE-safe
✔ Theme-safe
✔ Single-window lifecycle
✔ SOC-grade architecture
"""

import sys
from pathlib import Path

from PySide6.QtWidgets import QMainWindow, QStackedWidget

# ==================================================
# 🔒 BASE DIR (SOURCE vs EXE SAFE)
# ==================================================
def get_base_dir() -> Path:
    """
    Resolve base directory safely for:
    - Source run
    - PyInstaller EXE
    """
    if getattr(sys, "frozen", False):
        return Path(sys._MEIPASS)
    return Path(__file__).resolve().parents[1]


BASE_DIR = get_base_dir()

# ==================================================
# FRONTEND VIEWS
# ==================================================
from frontend.views.login_view import LoginView
from frontend.views.register_view import RegisterView
from frontend.views.dashboard_view import DashboardView

# ==================================================
# AUTH
# ==================================================
from auth.auth_manager import AuthManager

# ==================================================
# THEMES (EXE SAFE)
# ==================================================
THEMES_DIR = BASE_DIR / "frontend" / "themes"
DARK_THEME = THEMES_DIR / "dark.qss"
LIGHT_THEME = THEMES_DIR / "light.qss"


class MainWindow(QMainWindow):
    """
    Root application window.
    Only ONE window for entire app lifetime.
    """

    def __init__(self):
        super().__init__()

        # ------------------------------
        # Window basics
        # ------------------------------
        self.setWindowTitle("Log SOC Platform")
        self.setMinimumSize(1100, 700)

        # ------------------------------
        # Core state
        # ------------------------------
        self.auth = AuthManager()
        self.current_user: dict | None = None
        self.current_theme: str = "dark"

        # ------------------------------
        # Central stack
        # ------------------------------
        self.stack = QStackedWidget(self)
        self.setCentralWidget(self.stack)

        # ------------------------------
        # Views
        # ------------------------------
        self.login_view = LoginView()
        self.register_view = RegisterView()
        self.dashboard_view: DashboardView | None = None

        self.stack.addWidget(self.login_view)
        self.stack.addWidget(self.register_view)

        # ------------------------------
        # Signals
        # ------------------------------
        self._connect_auth_signals()

        # ------------------------------
        # Theme
        # ------------------------------
        self._apply_theme(self.current_theme)

        # ------------------------------
        # Initial route
        # ------------------------------
        self._initial_route()

    # ==================================================
    # ROUTING
    # ==================================================

    def _initial_route(self):
        if self.auth.is_registration_required():
            self._show_register(first_time=True)
        else:
            self._show_login()

    def _show_login(self):
        self.stack.setCurrentWidget(self.login_view)
        self.login_view.identifier_input.setFocus()

    def _show_register(self, first_time: bool = False):
        self.register_view.set_first_time(first_time)
        self.stack.setCurrentWidget(self.register_view)

    def _show_dashboard(self, user: dict):
        """
        Create dashboard ONCE and reuse.
        """
        self.current_user = user

        if self.dashboard_view is None:
            self.dashboard_view = DashboardView(user=user, parent=self)
            self.stack.addWidget(self.dashboard_view)

            # 🔑 Expose navigator (ProjectInfoView needs it)
            self.navigator = self.dashboard_view.navigator

            # Apply theme AFTER dashboard loads
            self._apply_theme(self.current_theme)

        self.stack.setCurrentWidget(self.dashboard_view)

    # ==================================================
    # AUTH SIGNALS
    # ==================================================

    def _connect_auth_signals(self):
        self.login_view.login_success.connect(self._show_dashboard)
        self.login_view.open_register.connect(
            lambda: self._show_register(first_time=False)
        )

        self.register_view.registration_success.connect(self._show_login)
        self.register_view.cancel_requested.connect(self._show_login)

    # ==================================================
    # LOGOUT
    # ==================================================

    def logout(self):
        self.current_user = None

        if self.dashboard_view:
            self.stack.removeWidget(self.dashboard_view)
            self.dashboard_view.deleteLater()
            self.dashboard_view = None

        self._show_login()

    # ==================================================
    # THEME MANAGEMENT
    # ==================================================

    def toggle_theme(self):
        self.current_theme = "light" if self.current_theme == "dark" else "dark"
        self._apply_theme(self.current_theme)

    def _apply_theme(self, theme: str):
        qss_file = DARK_THEME if theme == "dark" else LIGHT_THEME

        if not qss_file.exists():
            return  # Silent fail (SOC UX)

        with open(qss_file, "r", encoding="utf-8") as f:
            self.setStyleSheet(f.read())

    # ==================================================
    # WINDOW EVENTS
    # ==================================================

    def closeEvent(self, event):
        try:
            self.stack.setCurrentIndex(-1)
        finally:
            event.accept()
# =================================================