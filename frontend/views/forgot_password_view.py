"""
Forgot Password View (PySide6)
-----------------------------
Triggers secure password reset via email.

• Non-blocking (QThread)
• SOC-safe UX (no user enumeration)
• Modal & EXE-compatible

GUI ONLY
"""

from PySide6.QtWidgets import (
    QDialog, QLabel, QLineEdit, QPushButton,
    QVBoxLayout, QMessageBox
)
from PySide6.QtCore import Qt, QThread, Signal
from PySide6.QtGui import QFont

from auth.password_reset import PasswordResetService


# ==================================================
# WORKER THREAD
# ==================================================

class PasswordResetWorker(QThread):
    finished = Signal()

    def __init__(self, identifier: str):
        super().__init__()
        self.identifier = identifier
        self.service = PasswordResetService()

    def run(self):
        try:
            # SOC-safe: backend silently handles validity
            self.service.request_password_reset(self.identifier)
        except Exception:
            # NEVER leak backend errors
            pass
        self.finished.emit()


# ==================================================
# FORGOT PASSWORD VIEW
# ==================================================

class ForgotPasswordView(QDialog):
    """
    Modal password recovery dialog.
    """

    def __init__(self, parent=None):
        super().__init__(parent)

        self.setWindowTitle("Log SOC Platform — Password Recovery")
        self.setFixedSize(420, 260)
        self.setModal(True)

        self.worker = None

        self._build_ui()

    # ==================================================
    # UI
    # ==================================================

    def _build_ui(self):
        layout = QVBoxLayout(self)
        layout.setSpacing(12)
        layout.setContentsMargins(40, 30, 40, 30)

        title = QLabel("🔐 Password Recovery")
        title.setAlignment(Qt.AlignCenter)
        title.setFont(QFont("Segoe UI", 16, QFont.Bold))

        subtitle = QLabel("Enter your registered Username or Email")
        subtitle.setAlignment(Qt.AlignCenter)
        subtitle.setStyleSheet("color: gray; font-size: 11px;")

        self.identifier_input = QLineEdit()
        self.identifier_input.setPlaceholderText("Username or Email")
        self.identifier_input.setFixedHeight(32)
        self.identifier_input.setFocus()

        self.submit_btn = QPushButton("Send Reset Email")
        self.submit_btn.setFixedHeight(36)
        self.submit_btn.setStyleSheet(
            """
            QPushButton {
                background-color: #2563eb;
                color: white;
                font-weight: bold;
                border-radius: 6px;
            }
            QPushButton:hover {
                background-color: #1d4ed8;
            }
            """
        )
        self.submit_btn.clicked.connect(self._start_reset)

        layout.addWidget(title)
        layout.addWidget(subtitle)
        layout.addSpacing(10)
        layout.addWidget(self.identifier_input)
        layout.addSpacing(16)
        layout.addWidget(self.submit_btn)

    # ==================================================
    # HANDLER
    # ==================================================

    def _start_reset(self):
        identifier = self.identifier_input.text().strip()

        if not identifier:
            QMessageBox.warning(
                self,
                "Missing Field",
                "Username or Email is required"
            )
            return

        self.submit_btn.setEnabled(False)
        self.submit_btn.setText("Sending...")

        self.worker = PasswordResetWorker(identifier)
        self.worker.finished.connect(self._on_reset_complete)
        self.worker.start()

    # ==================================================
    # CALLBACK
    # ==================================================

    def _on_reset_complete(self):
        self.submit_btn.setEnabled(True)
        self.submit_btn.setText("Send Reset Email")

        QMessageBox.information(
            self,
            "Request Submitted",
            "If the account exists, password reset instructions\n"
            "have been sent to the registered email address."
        )

        self.accept()
