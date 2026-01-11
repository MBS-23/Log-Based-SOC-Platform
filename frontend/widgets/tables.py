"""
SOC Table Widgets
-----------------
Reusable, SOC-styled table components.

Features:
• Severity-aware row coloring
• IOC highlighting
• Read-only by default
• Scroll-safe
• PySide6 native

UI ONLY
"""

from PySide6.QtWidgets import (
    QTableWidget,
    QTableWidgetItem,
    QHeaderView,
)
from PySide6.QtCore import Qt
from PySide6.QtGui import QColor, QFont


# ==================================================
# COLOR MAPS (SOC STANDARD)
# ==================================================

SEVERITY_COLORS = {
    "Critical": QColor("#7f1d1d"),   # deep red
    "High": QColor("#b45309"),       # amber
    "Medium": QColor("#1d4ed8"),     # blue
    "Low": QColor("#065f46"),        # green
}

IOC_COLOR = QColor("#5b21b6")        # purple
DEFAULT_TEXT = QColor("#e5e7eb")


# ==================================================
# BASE SOC TABLE
# ==================================================

class SOCTable(QTableWidget):
    """
    Base SOC-styled table.
    """

    def __init__(self, parent=None):
        super().__init__(parent)

        self.setAlternatingRowColors(True)
        self.setShowGrid(False)
        self.setEditTriggers(QTableWidget.NoEditTriggers)
        self.setSelectionBehavior(QTableWidget.SelectRows)
        self.setSelectionMode(QTableWidget.SingleSelection)
        self.setWordWrap(False)

        self.verticalHeader().setVisible(False)

        header = self.horizontalHeader()
        header.setStretchLastSection(True)
        header.setSectionResizeMode(QHeaderView.Interactive)

        self._apply_style()

    # --------------------------------------------------
    # STYLE
    # --------------------------------------------------

    def _apply_style(self):
        self.setStyleSheet(
            """
            QTableWidget {
                background-color: #020617;
                color: #e5e7eb;
                border: none;
                gridline-color: #1e293b;
                font-size: 11px;
            }
            QHeaderView::section {
                background-color: #020617;
                color: #9ca3af;
                padding: 6px;
                border: none;
                border-bottom: 1px solid #1e293b;
                font-weight: bold;
            }
            QTableWidget::item:selected {
                background-color: #1e40af;
            }
            """
        )

    # ==================================================
    # CONFIGURATION
    # ==================================================

    def configure_columns(self, headers: list, widths: list | None = None):
        """
        Configure table headers and optional widths.
        """
        self.setColumnCount(len(headers))
        self.setHorizontalHeaderLabels(headers)

        if widths:
            for idx, width in enumerate(widths):
                self.setColumnWidth(idx, width)

    # ==================================================
    # INSERT ROW
    # ==================================================

    def insert_row(self, values: list):
        """
        Insert a generic row.
        """
        row = self.rowCount()
        self.insertRow(row)

        for col, value in enumerate(values):
            item = QTableWidgetItem(str(value))
            item.setForeground(DEFAULT_TEXT)
            item.setTextAlignment(Qt.AlignCenter)
            self.setItem(row, col, item)


# ==================================================
# ALERT TABLE (SEVERITY AWARE)
# ==================================================

class AlertTable(SOCTable):
    """
    SOC Alert Table with severity & IOC highlighting.
    """

    def insert_alert(self, alert: dict):
        """
        Insert alert row with severity styling.
        """
        row = self.rowCount()
        self.insertRow(row)

        severity = alert.get("severity", "Low")
        ioc_hit = alert.get("ioc_hit", False)

        values = [
            severity,
            alert.get("rule", ""),
            alert.get("ip", ""),
            alert.get("time", ""),
            "IOC" if ioc_hit else "",
        ]

        for col, value in enumerate(values):
            item = QTableWidgetItem(str(value))
            item.setTextAlignment(Qt.AlignCenter)

            # Severity coloring
            if col == 0:
                color = SEVERITY_COLORS.get(severity)
                if color:
                    item.setBackground(color)
                    item.setForeground(QColor("white"))
                    item.setFont(QFont("Segoe UI", 9, QFont.Bold))

            # IOC highlight
            if ioc_hit and col == 4:
                item.setForeground(IOC_COLOR)
                item.setFont(QFont("Segoe UI", 9, QFont.Bold))

            self.setItem(row, col, item)

        self.scrollToBottom()


# ==================================================
# LOG TABLE (RAW / LIVE LOGS)
# ==================================================

class LogTable(SOCTable):
    """
    SOC Log Table (raw or live).
    """

    def insert_log(self, log: dict):
        """
        Insert log row safely.
        """
        values = [
            log.get("time", ""),
            log.get("ip", ""),
            log.get("status", ""),
            log.get("normalized_request", ""),
        ]

        self.insert_row(values)
        self.scrollToBottom()

        # Prevent memory bloat
        if self.rowCount() > 1000:
            self.removeRow(0)
