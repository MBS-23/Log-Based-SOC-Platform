"""
Live Log View (PySide6)
----------------------
SOC-grade real-time log streaming & detection view.

✔ Thread-safe
✔ No GUI freezes
✔ Parent-safe (NavigationManager compatible)
✔ Batch PDF + Email (NO SPAM)
✔ EXE-safe
✔ Enterprise-ready
"""

from PySide6.QtWidgets import (
    QWidget, QPushButton, QLabel, QFileDialog,
    QVBoxLayout, QHBoxLayout, QSplitter,
    QTableWidget, QTableWidgetItem, QMessageBox
)
from PySide6.QtCore import Qt, QThread, Signal

from monitoring.live_tail import LiveLogTailer
from core.parser import parse_log_line
from core.normalizer import normalize_log_entry
from core.detector import DetectionEngine
from response.responder import ResponseEngine

try:
    from intelligence.ioc_loader import get_ioc_engine
    IOC_AVAILABLE = True
except ImportError:
    IOC_AVAILABLE = False


# ==================================================
# LIVE TAIL WORKER (SOC-GRADE)
# ==================================================

class LiveTailWorker(QThread):
    """
    Background log tailer worker.
    Handles detection in BATCH to avoid alert spam.
    """

    new_entry = Signal(dict)
    detection_found = Signal(dict)
    analytics_update = Signal(list)
    status = Signal(str)

    def __init__(self, file_path: str):
        super().__init__()

        ioc_engine = get_ioc_engine() if IOC_AVAILABLE else None
        self.detector = DetectionEngine(ioc_engine=ioc_engine)
        self.responder = ResponseEngine()

        self.file_path = file_path
        self.tailer = None
        self.running = True

        self.seen_alerts: set[tuple] = set()
        self.detections: list[dict] = []

    def run(self):
        self.tailer = LiveLogTailer(
            file_path=self.file_path,
            callback=self._on_new_line
        )
        self.status.emit(f"Started live tailing: {self.file_path}")
        self.tailer.start()

    def stop(self):
        self.running = False
        if self.tailer:
            self.tailer.stop()
        self.quit()
        self.wait()

    # ---------------- CALLBACK ----------------

    def _on_new_line(self, line: str):
        if not self.running:
            return

        parsed = parse_log_line(line)
        normalized = normalize_log_entry(parsed)

        # UI update
        self.new_entry.emit(normalized)

        detections = self.detector.analyze_entry(normalized)
        new_detections: list[dict] = []

        for d in detections:
            key = (d["severity"], d["rule"], d["ip"])
            if key in self.seen_alerts:
                continue

            self.seen_alerts.add(key)
            self.detections.append(d)
            new_detections.append(d)

            self.detection_found.emit(d)

        # 🔨 SOC FIX: ONE INCIDENT → ONE PDF → ONE EMAIL
        if new_detections:
            self.responder.handle_bulk_detections(new_detections)
            self.analytics_update.emit(self.detections)


# ==================================================
# MAIN VIEW
# ==================================================

class LiveLogView(QWidget):
    """
    SOC Live Log Monitoring View
    """

    analytics_ready = Signal(list)

    def __init__(self, parent: QWidget | None = None):
        super().__init__(parent)

        self.worker: LiveTailWorker | None = None
        self._build_ui()

    # ==================================================
    # UI
    # ==================================================

    def _build_ui(self):
        main_layout = QVBoxLayout(self)
        main_layout.setSpacing(10)

        # ---------- TOOLBAR ----------
        toolbar = QHBoxLayout()

        self.select_btn = QPushButton("📂 Select Log File")
        self.stop_btn = QPushButton("⏹ Stop Live Tail")

        self.select_btn.clicked.connect(self.select_log_file)
        self.stop_btn.clicked.connect(self.stop_tail)

        ioc_label = QLabel("🧠 IOC = Threat Intelligence Confirmed")
        ioc_label.setStyleSheet("color: #6d28d9; font-weight: bold;")

        toolbar.addWidget(self.select_btn)
        toolbar.addWidget(self.stop_btn)
        toolbar.addStretch()
        toolbar.addWidget(ioc_label)

        # ---------- TABLES ----------
        splitter = QSplitter(Qt.Horizontal)

        # Live Logs
        self.log_table = QTableWidget(0, 3)
        self.log_table.setHorizontalHeaderLabels(
            ["TIME", "IP", "REQUEST"]
        )
        self.log_table.setEditTriggers(QTableWidget.NoEditTriggers)
        self.log_table.setSelectionBehavior(QTableWidget.SelectRows)

        # Alerts
        self.alert_table = QTableWidget(0, 5)
        self.alert_table.setHorizontalHeaderLabels(
            ["SEVERITY", "RULE", "IP", "TIME", "IOC"]
        )
        self.alert_table.setEditTriggers(QTableWidget.NoEditTriggers)
        self.alert_table.setSelectionBehavior(QTableWidget.SelectRows)

        splitter.addWidget(self.log_table)
        splitter.addWidget(self.alert_table)
        splitter.setSizes([700, 500])

        main_layout.addLayout(toolbar)
        main_layout.addWidget(splitter)

    # ==================================================
    # NAVIGATION LIFECYCLE (CRITICAL)
    # ==================================================

    def on_navigate(self):
        """
        Called automatically by NavigationManager.
        Prevents zombie threads when switching views.
        """
        self.stop_tail()

    # ==================================================
    # LIVE TAIL CONTROL
    # ==================================================

    def select_log_file(self):
        path, _ = QFileDialog.getOpenFileName(
            self,
            "Select Live Log File",
            "",
            "Log Files (*.log *.txt);;All Files (*)"
        )

        if path:
            self.start_tail(path)

    def start_tail(self, path: str):
        if self.worker:
            QMessageBox.information(
                self,
                "Live Tail",
                "Already tailing a file."
            )
            return

        self.log_table.setRowCount(0)
        self.alert_table.setRowCount(0)

        self.worker = LiveTailWorker(path)
        self.worker.new_entry.connect(self._insert_log_row)
        self.worker.detection_found.connect(self._insert_alert)
        self.worker.analytics_update.connect(self.analytics_ready.emit)
        self.worker.status.connect(self._show_status)

        self.worker.start()

    def stop_tail(self):
        if self.worker:
            self.worker.stop()
            self.worker = None

    # ==================================================
    # UI INSERT
    # ==================================================

    def _insert_log_row(self, entry: dict):
        self.log_table.insertRow(0)

        values = [
            entry.get("time"),
            entry.get("ip"),
            entry.get("normalized_request"),
        ]

        for col, val in enumerate(values):
            self.log_table.setItem(
                0, col,
                QTableWidgetItem(str(val))
            )

        if self.log_table.rowCount() > 500:
            self.log_table.removeRow(self.log_table.rowCount() - 1)

    def _insert_alert(self, d: dict):
        self.alert_table.insertRow(0)

        values = [
            d["severity"],
            d["rule"],
            d["ip"],
            d["time"],
            "🧠 IOC" if d.get("ioc_hit") else "",
        ]

        for col, val in enumerate(values):
            item = QTableWidgetItem(str(val))
            item.setTextAlignment(Qt.AlignCenter)
            self.alert_table.setItem(0, col, item)

        if self.alert_table.rowCount() > 200:
            self.alert_table.removeRow(self.alert_table.rowCount() - 1)

    # ==================================================
    # STATUS
    # ==================================================

    def _show_status(self, msg: str):
        QMessageBox.information(self, "Live Tail", msg)
