"""
SOC Analytics View (PySide6)
---------------------------
Displays statistics and charts for detected threats.

✔ Thread-safe
✔ EXE-safe
✔ Enterprise SOC dashboard
✔ KPI cards + charts
"""

from PySide6.QtWidgets import (
    QWidget,
    QLabel,
    QVBoxLayout,
    QHBoxLayout,
    QFrame,
    QSizePolicy
)
from PySide6.QtCore import Qt
from PySide6.QtGui import QFont

from analytics.stats import severity_counts, top_offender_ips
from analytics.charts import (
    severity_distribution_chart,
    top_offenders_chart
)

from matplotlib.backends.backend_qtagg import FigureCanvasQTAgg as FigureCanvas
import matplotlib.pyplot as plt


# ==================================================
# KPI CARD
# ==================================================

class KpiCard(QFrame):
    def __init__(self, title: str, accent_color: str):
        super().__init__()

        self.setObjectName("KpiCard")
        self.setProperty("accent", accent_color)
        self.setSizePolicy(QSizePolicy.Expanding, QSizePolicy.Fixed)

        layout = QVBoxLayout(self)
        layout.setContentsMargins(12, 10, 12, 10)
        layout.setSpacing(2)

        self.value_label = QLabel("0")
        self.value_label.setFont(QFont("Segoe UI", 18, QFont.Bold))
        self.value_label.setAlignment(Qt.AlignLeft)

        title_label = QLabel(title)
        title_label.setStyleSheet("color: #9ca3af;")

        layout.addWidget(self.value_label)
        layout.addWidget(title_label)

    def set_value(self, value: int):
        self.value_label.setText(str(value))


# ==================================================
# MAIN VIEW
# ==================================================

class AnalyticsView(QWidget):
    """
    SOC Analytics Dashboard View
    """

    def __init__(self, parent=None):
        super().__init__(parent)

        self._last_detections: list = []
        self._build_ui()

    # ==================================================
    # UI
    # ==================================================

    def _build_ui(self):
        main_layout = QVBoxLayout(self)
        main_layout.setSpacing(14)
        main_layout.setContentsMargins(12, 12, 12, 12)

        # ---------- TITLE ----------
        title = QLabel("SOC Threat Analytics")
        title.setFont(QFont("Segoe UI", 14, QFont.Bold))

        subtitle = QLabel("Real-time visibility into detected security threats")
        subtitle.setStyleSheet("color: #9ca3af;")

        # ---------- KPI CARDS ----------
        kpi_layout = QHBoxLayout()
        kpi_layout.setSpacing(10)

        self.critical_card = KpiCard("Critical", "#7f1d1d")
        self.high_card = KpiCard("High", "#92400e")
        self.medium_card = KpiCard("Medium", "#1e3a8a")
        self.low_card = KpiCard("Low", "#065f46")

        for card in (
            self.critical_card,
            self.high_card,
            self.medium_card,
            self.low_card
        ):
            kpi_layout.addWidget(card, stretch=1)

        # ---------- CHART CONTAINER ----------
        self.chart_container = QFrame()
        self.chart_container.setObjectName("AnalyticsCharts")

        self.chart_layout = QHBoxLayout(self.chart_container)
        self.chart_layout.setSpacing(10)
        self.chart_layout.setContentsMargins(10, 10, 10, 10)

        # ---------- EMPTY STATE ----------
        self.empty_label = QLabel(
            "No detections yet.\nRun log analysis to populate SOC analytics."
        )
        self.empty_label.setAlignment(Qt.AlignCenter)
        self.empty_label.setStyleSheet("color: #9ca3af;")

        # ---------- ASSEMBLE ----------
        main_layout.addWidget(title)
        main_layout.addWidget(subtitle)
        main_layout.addLayout(kpi_layout)
        main_layout.addWidget(self.chart_container)
        main_layout.addWidget(self.empty_label)

        self._set_empty_state(True)

    # ==================================================
    # PUBLIC API
    # ==================================================

    def update_analytics(self, detections: list):
        self._last_detections = detections or []
        self._render()

    def on_navigate(self):
        self._render()

    # ==================================================
    # RENDERING
    # ==================================================

    def _render(self):
        self._clear_charts()

        if not self._last_detections:
            self._set_empty_state(True)
            return

        self._set_empty_state(False)

        sev_counts = severity_counts(self._last_detections)

        self.critical_card.set_value(sev_counts.get("Critical", 0))
        self.high_card.set_value(sev_counts.get("High", 0))
        self.medium_card.set_value(sev_counts.get("Medium", 0))
        self.low_card.set_value(sev_counts.get("Low", 0))

        # ---------- CHARTS ----------
        fig1 = severity_distribution_chart(sev_counts)
        if fig1:
            canvas1 = FigureCanvas(fig1)
            self.chart_layout.addWidget(canvas1)
            canvas1.draw()
            plt.close(fig1)

        top_ips = top_offender_ips(self._last_detections)
        if top_ips:
            fig2 = top_offenders_chart(top_ips)
            if fig2:
                canvas2 = FigureCanvas(fig2)
                self.chart_layout.addWidget(canvas2)
                canvas2.draw()
                plt.close(fig2)

    # ==================================================
    # STATES
    # ==================================================

    def _set_empty_state(self, empty: bool):
        self.empty_label.setVisible(empty)
        self.chart_container.setVisible(not empty)

        if empty:
            self.critical_card.set_value(0)
            self.high_card.set_value(0)
            self.medium_card.set_value(0)
            self.low_card.set_value(0)

    # ==================================================
    # CLEANUP
    # ==================================================

    def _clear_charts(self):
        while self.chart_layout.count():
            item = self.chart_layout.takeAt(0)
            widget = item.widget()
            if widget:
                widget.setParent(None)
                widget.deleteLater()
