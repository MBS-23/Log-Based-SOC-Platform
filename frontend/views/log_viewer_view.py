"""
SOC Log Viewer (PySide6)
-----------------------
Thread-safe, EXE-safe, enterprise SOC-grade log analysis view.

• Guided SOC detection workflow
• Severity-based visual feedback
• Non-blocking UI
• Proper alignment & live updates
• ONE PDF per detection run (SOC-accurate)
"""

import os

from PySide6.QtWidgets import (
    QWidget, QPushButton, QLabel, QFileDialog,
    QVBoxLayout, QHBoxLayout, QSplitter,
    QTableWidget, QTableWidgetItem, QMessageBox,
    QProgressBar, QHeaderView
)
from PySide6.QtCore import Qt, Signal, QThread
from PySide6.QtGui import QColor

from core.parser import parse_log_line
from core.normalizer import normalize_log_entry
from core.detector import DetectionEngine
from response.responder import ResponseEngine
from config.settings import PDF_REPORT_DIR

try:
    from intelligence.ioc_loader import get_ioc_engine
    IOC_AVAILABLE = True
except ImportError:
    IOC_AVAILABLE = False


# ==================================================
# BACKGROUND WORKERS
# ==================================================

class LogLoaderWorker(QThread):
    log_loaded = Signal(dict)
    finished = Signal(int)
    error = Signal(str)

    def __init__(self, path: str):
        super().__init__()
        self.path = path

    def run(self):
        count = 0
        try:
            with open(self.path, "r", encoding="utf-8", errors="ignore") as f:
                for line in f:
                    entry = normalize_log_entry(parse_log_line(line))
                    self.log_loaded.emit(entry)
                    count += 1
            self.finished.emit(count)
        except Exception as exc:
            self.error.emit(str(exc))


class DetectionWorker(QThread):
    detection_found = Signal(dict)
    finished = Signal(list)

    def __init__(self, entries, engine, responder):
        super().__init__()
        self.entries = entries
        self.engine = engine
        self.responder = responder
        self._seen = set()

    def run(self):
        detections = []

        for entry in self.entries:
            for d in self.engine.analyze_entry(entry):
                key = (d["severity"], d["rule"], d["ip"])
                if key in self._seen:
                    continue

                self._seen.add(key)
                detections.append(d)

                # 🔔 SOC response pipeline
                self.responder.handle_detection(d)
                self.detection_found.emit(d)

        self.finished.emit(detections)


# ==================================================
# MAIN VIEW
# ==================================================

class LogViewer(QWidget):
    """
    SOC Log Viewer Panel
    """

    analytics_ready = Signal(list)

    def __init__(self, parent=None):
        super().__init__(parent)

        ioc_engine = get_ioc_engine() if IOC_AVAILABLE else None
        self.engine = DetectionEngine(ioc_engine=ioc_engine)

        # 🔴 SINGLE ResponseEngine instance
        self.responder = ResponseEngine()

        self.parsed_logs = []

        self._build_ui()

    # ================= UI =================

    def _build_ui(self):
        root = QVBoxLayout(self)
        root.setContentsMargins(12, 12, 12, 12)
        root.setSpacing(10)

        # ---------- TOOLBAR ----------
        toolbar = QHBoxLayout()
        toolbar.setSpacing(10)

        self.open_btn = QPushButton("📂 Open Log File")
        self.run_btn = QPushButton("🚀 Run Detection")
        self.run_btn.setObjectName("PrimaryButton")
        self.pdf_btn = QPushButton("📄 Open Latest PDF")

        self.open_btn.clicked.connect(self.load_log_file)
        self.run_btn.clicked.connect(self.run_detection)
        self.pdf_btn.clicked.connect(self.open_latest_pdf)

        self.ioc_label = QLabel("🧠 IOC = Threat Intelligence Enabled")
        self.ioc_label.setStyleSheet("color: #8b5cf6; font-weight: 600;")

        toolbar.addWidget(self.open_btn)
        toolbar.addWidget(self.run_btn)
        toolbar.addWidget(self.pdf_btn)
        toolbar.addStretch()
        toolbar.addWidget(self.ioc_label)

        # ---------- STATUS ----------
        status = QHBoxLayout()

        self.status_label = QLabel("Idle — load logs to begin SOC analysis")
        self.status_label.setStyleSheet("color: #9ca3af;")

        self.progress = QProgressBar()
        self.progress.setVisible(False)
        self.progress.setFixedHeight(10)
        self.progress.setRange(0, 0)  # infinite

        status.addWidget(self.status_label)
        status.addStretch()
        status.addWidget(self.progress)

        # ---------- TABLES ----------
        splitter = QSplitter(Qt.Horizontal)

        # ---- LOG TABLE ----
        self.log_table = QTableWidget(0, 4)
        self.log_table.setHorizontalHeaderLabels(
            ["TIME", "IP", "STATUS", "REQUEST"]
        )
        self.log_table.setEditTriggers(QTableWidget.NoEditTriggers)
        self.log_table.setSelectionBehavior(QTableWidget.SelectRows)
        self.log_table.setSelectionMode(QTableWidget.SingleSelection)
        self.log_table.horizontalHeader().setSectionResizeMode(QHeaderView.Stretch)
        self.log_table.verticalHeader().setVisible(False)

        # ---- ALERT TABLE ----
        self.alert_table = QTableWidget(0, 5)
        self.alert_table.setHorizontalHeaderLabels(
            ["SEVERITY", "RULE", "IP", "TIME", "IOC"]
        )
        self.alert_table.setEditTriggers(QTableWidget.NoEditTriggers)
        self.alert_table.setSelectionBehavior(QTableWidget.SelectRows)
        self.alert_table.setSelectionMode(QTableWidget.SingleSelection)
        self.alert_table.horizontalHeader().setSectionResizeMode(QHeaderView.Stretch)
        self.alert_table.verticalHeader().setVisible(False)

        splitter.addWidget(self.log_table)
        splitter.addWidget(self.alert_table)
        splitter.setSizes([680, 520])

        # ---------- ASSEMBLE ----------
        root.addLayout(toolbar)
        root.addLayout(status)
        root.addWidget(splitter, stretch=1)

    # ================= FILE LOADING =================

    def load_log_file(self):
        path, _ = QFileDialog.getOpenFileName(
            self,
            "Select Log File",
            "",
            "Log Files (*.log *.txt);;All Files (*)"
        )
        if not path:
            return

        self.parsed_logs.clear()
        self.log_table.setRowCount(0)
        self.alert_table.setRowCount(0)

        self.status_label.setText("📥 Loading logs…")
        self.progress.setVisible(True)

        self.loader = LogLoaderWorker(path)
        self.loader.log_loaded.connect(self._insert_log_row)
        self.loader.finished.connect(self._on_log_loaded)
        self.loader.error.connect(self._on_error)
        self.loader.start()

    def _insert_log_row(self, entry: dict):
        self.parsed_logs.append(entry)

        row = self.log_table.rowCount()
        self.log_table.insertRow(row)

        for col, key in enumerate(
            ("time", "ip", "status", "normalized_request")
        ):
            self.log_table.setItem(
                row, col,
                QTableWidgetItem(str(entry.get(key, "")))
            )

    def _on_log_loaded(self, count: int):
        self.progress.setVisible(False)
        self.status_label.setText(f"✔ Loaded {count} log entries")

    # ================= DETECTION =================

    def run_detection(self):
        if not self.parsed_logs:
            QMessageBox.warning(self, "No Data", "Load a log file first.")
            return

        # 🔒 RESET PDF FLAG (CRITICAL FIX)
        self.responder._pdf_generated_for_run = False

        self.alert_table.setRowCount(0)
        self.run_btn.setEnabled(False)

        self.status_label.setText("🔍 Running SOC detection engine…")
        self.progress.setVisible(True)

        self.detector = DetectionWorker(
            self.parsed_logs,
            self.engine,
            self.responder
        )
        self.detector.detection_found.connect(self._insert_alert)
        self.detector.finished.connect(self._on_detection_complete)
        self.detector.start()

    def _insert_alert(self, d: dict):
        row = self.alert_table.rowCount()
        self.alert_table.insertRow(row)

        values = [
            d.get("severity"),
            d.get("rule"),
            d.get("ip"),
            d.get("time"),
            "IOC" if d.get("ioc_hit") else "",
        ]

        severity_colors = {
            "Critical": QColor("#7f1d1d"),
            "High": QColor("#b45309"),
            "Medium": QColor("#1e40af"),
            "Low": QColor("#166534"),
        }

        for col, val in enumerate(values):
            item = QTableWidgetItem(str(val))
            item.setTextAlignment(Qt.AlignCenter)

            # 🎯 Color ONLY severity column
            if col == 0 and val in severity_colors:
                item.setForeground(Qt.white)
                item.setBackground(severity_colors[val])

            self.alert_table.setItem(row, col, item)

    def _on_detection_complete(self, detections: list):
        self.progress.setVisible(False)
        self.run_btn.setEnabled(True)

        self.status_label.setText(
            "✔ No threats detected"
            if not detections
            else f"⚠ {len(detections)} threats identified"
        )

        # 🔔 Analytics update
        self.analytics_ready.emit(detections)

    # ================= PDF =================

    def open_latest_pdf(self):
        if not PDF_REPORT_DIR.exists():
            QMessageBox.warning(self, "PDF", "No PDF reports found.")
            return

        pdfs = sorted(
            PDF_REPORT_DIR.glob("incident_*.pdf"),
            key=lambda p: p.stat().st_mtime,
            reverse=True
        )

        if pdfs:
            os.startfile(str(pdfs[0]))

    # ================= ERROR =================

    def _on_error(self, msg: str):
        self.progress.setVisible(False)
        self.run_btn.setEnabled(True)
        QMessageBox.critical(self, "Error", msg)
