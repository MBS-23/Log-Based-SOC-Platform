"""
Blocked IP History View (PySide6)
--------------------------------
Displays firewall-blocked IPs for SOC visibility.
Read-only forensic panel.

✔ EXE-safe
✔ Thread-safe
✔ SOC-grade UI
✔ Auto-refresh on navigation
"""

import json
from PySide6.QtWidgets import (
    QWidget, QLabel, QPushButton,
    QVBoxLayout, QHBoxLayout,
    QTableWidget, QTableWidgetItem,
    QMessageBox
)
from PySide6.QtCore import Qt
from PySide6.QtGui import QFont, QColor

from config.settings import BLOCKED_IPS_FILE


class BlockedIPsView(QWidget):
    """
    Read-only SOC firewall block history view.
    """

    def __init__(self, parent=None):
        super().__init__(parent)

        self._build_ui()
        self.load_blocked_ips()

    # ==================================================
    # UI
    # ==================================================

    def _build_ui(self):
        main_layout = QVBoxLayout(self)
        main_layout.setSpacing(10)
        main_layout.setContentsMargins(12, 12, 12, 12)

        # -------- HEADER --------
        header_layout = QHBoxLayout()

        title = QLabel("🔥 AUTO-BLOCKED IP HISTORY")
        title.setFont(QFont("Segoe UI", 13, QFont.Bold))

        refresh_btn = QPushButton("🔄 Refresh")
        refresh_btn.setFixedHeight(32)
        refresh_btn.clicked.connect(self.load_blocked_ips)

        header_layout.addWidget(title)
        header_layout.addStretch()
        header_layout.addWidget(refresh_btn)

        # -------- TABLE --------
        self.table = QTableWidget(0, 6)
        self.table.setHorizontalHeaderLabels([
            "IP ADDRESS",
            "REASON",
            "IOC",
            "BLOCKED AT (UTC)",
            "OS",
            "METHOD"
        ])

        self.table.setEditTriggers(QTableWidget.NoEditTriggers)
        self.table.setSelectionBehavior(QTableWidget.SelectRows)
        self.table.setSelectionMode(QTableWidget.SingleSelection)
        self.table.verticalHeader().setVisible(False)
        self.table.horizontalHeader().setStretchLastSection(True)
        self.table.setAlternatingRowColors(True)

        # -------- EMPTY STATE --------
        self.empty_label = QLabel(
            "No blocked IPs recorded.\nSystem has not auto-blocked any threats yet."
        )
        self.empty_label.setAlignment(Qt.AlignCenter)
        self.empty_label.setStyleSheet("color: #9ca3af;")

        # -------- ASSEMBLE --------
        main_layout.addLayout(header_layout)
        main_layout.addWidget(self.table)
        main_layout.addWidget(self.empty_label)

        self._set_empty_state(True)

    # ==================================================
    # DATA LOADING
    # ==================================================

    def load_blocked_ips(self):
        """
        Load firewall block history safely.
        """
        self.table.setRowCount(0)

        if not BLOCKED_IPS_FILE.exists():
            self._set_empty_state(True)
            return

        try:
            with open(BLOCKED_IPS_FILE, "r", encoding="utf-8") as f:
                data = json.load(f)

            if not data:
                self._set_empty_state(True)
                return

            # Sort newest → oldest
            sorted_items = sorted(
                data.items(),
                key=lambda item: item[1].get("blocked_at", ""),
                reverse=True
            )

            self.table.setRowCount(len(sorted_items))
            self._set_empty_state(False)

            for row, (ip, info) in enumerate(sorted_items):
                ioc = info.get("ioc_confirmed", False)

                self._set_item(row, 0, ip)
                self._set_item(row, 1, info.get("reason", "Unknown"))
                self._set_item(row, 2, "YES" if ioc else "NO", center=True)
                self._set_item(row, 3, info.get("blocked_at", "Unknown"))
                self._set_item(row, 4, info.get("os", "Unknown"), center=True)
                self._set_item(row, 5, info.get("method", "Unknown"), center=True)

                # 🔥 Highlight IOC-confirmed blocks
                if ioc:
                    for col in range(self.table.columnCount()):
                        item = self.table.item(row, col)
                        if item:
                            item.setBackground(QColor("#7f1d1d"))
                            item.setForeground(Qt.white)

        except Exception as exc:
            QMessageBox.critical(
                self,
                "Blocked IP History Error",
                f"Failed to load firewall history:\n{exc}"
            )

    # ==================================================
    # NAVIGATION HOOK
    # ==================================================

    def on_navigate(self):
        """
        Auto-refresh when user navigates to this view.
        """
        self.load_blocked_ips()

    # ==================================================
    # STATES
    # ==================================================

    def _set_empty_state(self, empty: bool):
        self.empty_label.setVisible(empty)
        self.table.setVisible(not empty)

    # ==================================================
    # HELPERS
    # ==================================================

    def _set_item(self, row, col, text, center=False):
        item = QTableWidgetItem(str(text))
        if center:
            item.setTextAlignment(Qt.AlignCenter)
        self.table.setItem(row, col, item)
