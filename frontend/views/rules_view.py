"""
Detection Rules Viewer (PySide6)
--------------------------------
Read-only window displaying all active SOC detection rules.

SOC-grade:
✔ Read-only
✔ Modal
✔ Scrollable
✔ Audit-friendly
✔ EXE-safe
"""

from PySide6.QtWidgets import (
    QWidget, QLabel, QPushButton,
    QVBoxLayout, QHBoxLayout,
    QTableWidget, QTableWidgetItem
)
from PySide6.QtCore import Qt
from PySide6.QtGui import QFont

from core.rules import DETECTION_RULES


class RulesViewer(QWidget):
    """
    Read-only SOC Detection Rules Viewer.
    """

    def __init__(self, parent=None):
        super().__init__(parent)

        self.setWindowTitle("SOC Detection Rules")
        self.setMinimumSize(900, 520)
        self.resize(980, 600)

        # Modal behavior (SOC UX)
        if parent:
            self.setWindowModality(Qt.ApplicationModal)

        self._build_ui()

    # ==================================================
    # UI
    # ==================================================

    def _build_ui(self):
        main_layout = QVBoxLayout(self)
        main_layout.setSpacing(10)
        main_layout.setContentsMargins(12, 12, 12, 12)

        # -------- HEADER --------
        header_layout = QHBoxLayout()

        title = QLabel("📜 Active Detection Rules (OWASP-Aligned)")
        title.setFont(QFont("Segoe UI", 14, QFont.Bold))

        count_label = QLabel(f"Total Rules: {len(DETECTION_RULES)}")
        count_label.setStyleSheet("color: gray; font-size: 11px;")

        close_btn = QPushButton("❌ Close")
        close_btn.setFixedHeight(32)
        close_btn.clicked.connect(self.close)

        header_layout.addWidget(title)
        header_layout.addStretch()
        header_layout.addWidget(count_label)
        header_layout.addSpacing(12)
        header_layout.addWidget(close_btn)

        # -------- TABLE --------
        self.table = QTableWidget()
        self.table.setColumnCount(2)
        self.table.setHorizontalHeaderLabels([
            "RULE NAME",
            "REGEX / INDICATOR"
        ])

        self.table.setEditTriggers(QTableWidget.NoEditTriggers)
        self.table.setSelectionBehavior(QTableWidget.SelectRows)
        self.table.setSelectionMode(QTableWidget.SingleSelection)
        self.table.verticalHeader().setVisible(False)
        self.table.horizontalHeader().setStretchLastSection(True)
        self.table.setAlternatingRowColors(True)

        # Column widths (SOC readability)
        self.table.setColumnWidth(0, 300)
        self.table.setColumnWidth(1, 620)

        # -------- LOAD DATA --------
        self._load_rules()

        # -------- ASSEMBLE --------
        main_layout.addLayout(header_layout)
        main_layout.addWidget(self.table)

    # ==================================================
    # DATA
    # ==================================================

    def _load_rules(self):
        self.table.setRowCount(len(DETECTION_RULES))

        for row, (rule, pattern) in enumerate(DETECTION_RULES.items()):
            self._set_item(row, 0, rule)
            self._set_item(row, 1, pattern)

    # ==================================================
    # HELPERS
    # ==================================================

    def _set_item(self, row: int, col: int, text: str):
        item = QTableWidgetItem(str(text))
        item.setTextAlignment(Qt.AlignLeft | Qt.AlignVCenter)
        self.table.setItem(row, col, item)
