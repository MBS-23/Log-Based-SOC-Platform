"""
Reset Password View (PySide6)
----------------------------
Allows user to reset password using a valid reset token.

Flow:
Email → Token → Username → New Password → Update

GUI ONLY
EXE-safe
SOC-grade UX
"""

import re
from PySide6.QtWidgets import (
    QDialog, QLabel, QLineEdit, QPushButton,
    QVBoxLayout, QFormLayout, QMessageBox
)
from PySide6.QtCore import Qt, QThread, Signal
from PySide6.QtGui import QFont

from auth.password_reset import PasswordResetService


# ==================================================
# WORKER THREAD
# ==================================================

class ResetPasswordWorker(QThread):
    finished = Signal(dict)

    def __init__(self, username: str, token: str, password: str):
        super().__init__()
        self.username = username
        self.token = token
        self.password = password
        self.service = PasswordResetService()

    def run(self):
        try:
            result = self.service.reset_password(
                username=self.username,
                token=self.token,
                new_password=self.password
            )
        except Exception as exc:
            result = {
                "success": False,
                "error": "Password reset failed"
            }

        self.finished.emit(result)


# ==================================================
# RESET PASSWORD VIEW
# ==================================================

class ResetPasswordView(QDialog):
    """
    Modal password reset dialog.
    """

    def __init__(self, parent=None, token: str = ""):
        super().__init__(parent)

        self.prefill_token = token
        self.worker = None

        self.setWindowTitle("Log SOC Platform — Reset Password")
        self.setFixedSize(440, 360)
        self.setModal(True)

        self._build_ui()

    # ==================================================
    # UI
    # ==================================================

    def _build_ui(self):
        layout = QVBoxLayout(self)
        layout.setContentsMargins(40, 30, 40, 30)
        layout.setSpacing(12)

        title = QLabel("🔑 Reset Your Password")
        title.setAlignment(Qt.AlignCenter)
        title.setFont(QFont("Segoe UI", 16, QFont.Bold))

        layout.addWidget(title)
        layout.addSpacing(10)

        form = QFormLayout()
        form.setSpacing(10)

        self.username_input = QLineEdit()
        self.username_input.setPlaceholderText("Username")

        self.token_input = QLineEdit()
        self.token_input.setPlaceholderText("Reset Token")
        self.token_input.setText(self.prefill_token)

        self.password_input = QLineEdit()
        self.password_input.setEchoMode(QLineEdit.Password)
        self.password_input.setPlaceholderText("New Password")

        self.confirm_input = QLineEdit()
        self.confirm_input.setEchoMode(QLineEdit.Password)
        self.confirm_input.setPlaceholderText("Confirm Password")

        form.addRow("Username:", self.username_input)
        form.addRow("Reset Token:", self.token_input)
        form.addRow("New Password:", self.password_input)
        form.addRow("Confirm Password:", self.confirm_input)

        layout.addLayout(form)

        hint = QLabel(
            "Password must include upper, lower, number & symbol (min 8 chars)"
        )
        hint.setStyleSheet("color: gray; font-size: 10px;")
        hint.setAlignment(Qt.AlignCenter)

        layout.addWidget(hint)
        layout.addSpacing(12)

        self.submit_btn = QPushButton("Reset Password")
        self.submit_btn.setFixedHeight(36)
        self.submit_btn.setStyleSheet(
            """
            QPushButton {
                background-color: #16a34a;
                color: white;
                font-weight: bold;
                border-radius: 6px;
            }
            QPushButton:hover {
                background-color: #15803d;
            }
            """
        )
        self.submit_btn.clicked.connect(self._start_reset)

        layout.addWidget(self.submit_btn)

    # ==================================================
    # VALIDATION
    # ==================================================

    def _password_strong(self, password: str) -> bool:
        return all([
            len(password) >= 8,
            re.search(r"[A-Z]", password),
            re.search(r"[a-z]", password),
            re.search(r"\d", password),
            re.search(r"[!@#$%^&*()_+\-=\[\]{};':\"\\|,.<>/?]", password),
        ])

    # ==================================================
    # HANDLER
    # ==================================================

    def _start_reset(self):
        username = self.username_input.text().strip()
        token = self.token_input.text().strip()
        password = self.password_input.text()
        confirm = self.confirm_input.text()

        if not all([username, token, password, confirm]):
            QMessageBox.warning(
                self, "Missing Fields", "All fields are required"
            )
            return

        if password != confirm:
            QMessageBox.warning(
                self, "Password Mismatch", "Passwords do not match"
            )
            return

        if not self._password_strong(password):
            QMessageBox.warning(
                self,
                "Weak Password",
                "Password does not meet security requirements"
            )
            return

        self.submit_btn.setEnabled(False)
        self.submit_btn.setText("Updating...")

        self.worker = ResetPasswordWorker(username, token, password)
        self.worker.finished.connect(self._on_reset_complete)
        self.worker.start()

    # ==================================================
    # CALLBACK
    # ==================================================

    def _on_reset_complete(self, result: dict):
        self.submit_btn.setEnabled(True)
        self.submit_btn.setText("Reset Password")

        if result.get("success"):
            QMessageBox.information(
                self,
                "Password Updated",
                "Password reset successful.\nPlease login again."
            )
            self.accept()
        else:
            QMessageBox.critical(
                self,
                "Reset Failed",
                result.get("error", "Password reset failed")
            )
