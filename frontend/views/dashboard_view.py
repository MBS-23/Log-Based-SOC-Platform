"""
SOC Dashboard View (PySide6)
---------------------------
Main dashboard container for the Log-Based SOC Platform.

Responsibilities:
- Layout header + sidebar + content
- Register all SOC views
- Route navigation events
- Wire analytics & SOC events
- Provide enterprise-grade structure

ENTERPRISE • SOC-GRADE • EXE-SAFE
"""

from PySide6.QtWidgets import (
    QWidget,
    QHBoxLayout,
    QVBoxLayout,
    QStackedWidget,
    QFrame
)
from PySide6.QtCore import Qt

# ---------------- CORE UI ----------------
from frontend.widgets.header import Header
from frontend.widgets.sidebar import Sidebar

# ---------------- NAVIGATION ----------------
from frontend.utils.navigation import NavigationManager

# ---------------- SOC VIEWS ----------------
from frontend.views.log_viewer_view import LogViewer
from frontend.views.live_log_view import LiveLogView
from frontend.views.analytics_view import AnalyticsView
from frontend.views.watchtower_view import WatchtowerView
from frontend.views.blocked_ips_view import BlockedIPsView
from frontend.views.rules_view import RulesViewer
from frontend.views.project_info_view import ProjectInfoView


class DashboardView(QWidget):
    """
    SOC Dashboard main container (PySide6).
    """

    def __init__(self, user: dict, parent: QWidget | None = None):
        super().__init__(parent)

        self.user = user or {}

        self._build_ui()
        self._register_views()
        self._connect_signals()
        self._wire_soc_events()

    # ==================================================
    # UI
    # ==================================================

    def _build_ui(self):
        self.setObjectName("DashboardRoot")

        root = QVBoxLayout(self)
        root.setContentsMargins(0, 0, 0, 0)
        root.setSpacing(0)

        # ---------------- HEADER ----------------
        self.header = Header(user=self.user)
        root.addWidget(self.header)

        # ---------------- BODY ----------------
        body = QHBoxLayout()
        body.setContentsMargins(0, 0, 0, 0)
        body.setSpacing(0)

        # Sidebar
        self.sidebar = Sidebar()
        body.addWidget(self.sidebar)

        # ---------------- CONTENT CONTAINER ----------------
        content_frame = QFrame()
        content_frame.setObjectName("DashboardContent")

        content_layout = QVBoxLayout(content_frame)
        content_layout.setContentsMargins(14, 14, 14, 14)
        content_layout.setSpacing(10)

        self.stack = QStackedWidget()
        content_layout.addWidget(self.stack)

        body.addWidget(content_frame, stretch=1)
        root.addLayout(body)

        # Navigation manager
        self.navigator = NavigationManager(self.stack)

    # ==================================================
    # VIEW REGISTRATION
    # ==================================================

    def _register_views(self):
        """
        Register all SOC views (single instance each).
        """

        # Dashboard landing
        self.navigator.register_view("dashboard", AnalyticsView, self)
        self.navigator.register_view("analytics", AnalyticsView, self)

        # Core SOC views
        self.navigator.register_view("log_viewer", LogViewer, self)
        self.navigator.register_view("live_logs", LiveLogView, self)
        self.navigator.register_view("watchtower", WatchtowerView, self)
        self.navigator.register_view("blocked_ips", BlockedIPsView, self)
        self.navigator.register_view("rules", RulesViewer, self)
        self.navigator.register_view("project_info", ProjectInfoView, self)

        # Default landing
        self.navigator.navigate("dashboard")

    # ==================================================
    # SIGNALS
    # ==================================================

    def _connect_signals(self):
        self.sidebar.navigate.connect(self.navigator.navigate)
        self.header.toggle_theme.connect(self._toggle_theme)
        self.header.logout_requested.connect(self._logout)

    # ==================================================
    # SOC EVENT WIRING (CRITICAL FIX)
    # ==================================================

    def _wire_soc_events(self):
        """
        Wire detection events → analytics & blocked IP panels.
        """

        analytics: AnalyticsView | None = self.navigator.get_view("analytics")
        blocked_ips: BlockedIPsView | None = self.navigator.get_view("blocked_ips")

        log_viewer: LogViewer | None = self.navigator.get_view("log_viewer")
        if log_viewer:
            # Detection → Analytics
            if analytics:
                log_viewer.analytics_ready.connect(analytics.update_analytics)

            # Detection → Blocked IPs refresh
            if blocked_ips:
                log_viewer.analytics_ready.connect(
                    lambda _: blocked_ips.load_blocked_ips()
                )

        live_logs: LiveLogView | None = self.navigator.get_view("live_logs")
        if live_logs and analytics:
            live_logs.analytics_ready.connect(analytics.update_analytics)

    # ==================================================
    # ACTION DELEGATION
    # ==================================================

    def _toggle_theme(self):
        self.window().toggle_theme()

    def _logout(self):
        self.window().logout()
