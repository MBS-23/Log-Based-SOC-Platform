"""
Watchtower View (PySide6)
------------------------
Real-time system monitoring panel.

SOC-grade:
- Thread-safe (QThread)
- Read-only
- Silent by default
- Parent-safe (NavigationManager compatible)
- EXE-safe
"""

from PySide6.QtWidgets import (
    QWidget, QPushButton, QVBoxLayout, QHBoxLayout,
    QTableWidget, QTableWidgetItem
)
from PySide6.QtCore import Qt, Signal, QThread

from monitoring.process_monitor import ProcessMonitor


# ==================================================
# BACKGROUND WORKER
# ==================================================

class WatchtowerWorker(QThread):
    event_received = Signal(dict)

    def __init__(self):
        super().__init__()
        self.monitor = None
        self.running = True

    def run(self):
        self.monitor = ProcessMonitor(callback=self._emit_event)
        self.monitor.start()

    def stop(self):
        self.running = False
        if self.monitor:
            self.monitor.stop()
        self.quit()
        self.wait()

    def _emit_event(self, event: dict):
        if self.running:
            self.event_received.emit(event)


# ==================================================
# MAIN VIEW
# ==================================================

class WatchtowerView(QWidget):
    """
    Real-time host monitoring panel.
    """

    def __init__(self, parent: QWidget | None = None):
        super().__init__(parent)

        self.worker: WatchtowerWorker | None = None
        self._last_event_cache: dict[tuple, str] = {}

        self._build_ui()

    # ==================================================
    # UI
    # ==================================================

    def _build_ui(self):
        layout = QVBoxLayout(self)
        layout.setSpacing(10)

        # -------- CONTROL BAR --------
        controls = QHBoxLayout()

        self.start_btn = QPushButton("▶ Start Monitoring")
        self.stop_btn = QPushButton("⏹ Stop Monitoring")

        self.stop_btn.setEnabled(False)

        self.start_btn.clicked.connect(self.start_monitoring)
        self.stop_btn.clicked.connect(self.stop_monitoring)

        controls.addWidget(self.start_btn)
        controls.addWidget(self.stop_btn)
        controls.addStretch()

        # -------- TABLE --------
        self.table = QTableWidget(0, 4)
        self.table.setHorizontalHeaderLabels(
            ["TYPE", "PID", "PROCESS", "DETAILS"]
        )

        self.table.setEditTriggers(QTableWidget.NoEditTriggers)
        self.table.setSelectionBehavior(QTableWidget.SelectRows)
        self.table.setAlternatingRowColors(True)
        self.table.verticalHeader().setVisible(False)

        self.table.setColumnWidth(0, 180)
        self.table.setColumnWidth(1, 80)
        self.table.setColumnWidth(2, 220)
        self.table.setColumnWidth(3, 200)

        layout.addLayout(controls)
        layout.addWidget(self.table)

    # ==================================================
    # NAVIGATION LIFECYCLE (CRITICAL)
    # ==================================================

    def on_navigate(self):
        """
        Called automatically by NavigationManager.
        Ensures no background monitor survives navigation.
        """
        self.stop_monitoring()

    # ==================================================
    # CONTROL
    # ==================================================

    def start_monitoring(self):
        if self.worker:
            return  # SOC silent behavior

        self.worker = WatchtowerWorker()
        self.worker.event_received.connect(self._handle_event_ui)
        self.worker.start()

        self.start_btn.setEnabled(False)
        self.stop_btn.setEnabled(True)

    def stop_monitoring(self):
        if not self.worker:
            return

        self.worker.stop()
        self.worker = None

        self.start_btn.setEnabled(True)
        self.stop_btn.setEnabled(False)

    # ==================================================
    # EVENT HANDLING
    # ==================================================

    def _handle_event_ui(self, event: dict):
        """
        Runs safely on Qt main thread.
        """
        event_type = event.get("type", "Unknown")
        pid = str(event.get("pid", ""))
        process = event.get("process", "")
        details = ""

        if event_type == "High Memory Usage":
            details = f'{event.get("memory_mb", "")} MB'

        # Deduplication (SOC-safe)
        key = (event_type, pid)
        if self._last_event_cache.get(key) == details:
            return

        self._last_event_cache[key] = details
        self._insert_row(event_type, pid, process, details)

    def _insert_row(self, event_type, pid, process, details):
        self.table.insertRow(0)

        values = [event_type, pid, process, details]
        for col, value in enumerate(values):
            item = QTableWidgetItem(str(value))
            item.setTextAlignment(Qt.AlignCenter)
            self.table.setItem(0, col, item)
