"""
SOC Registration Interface (PySide6)
-----------------------------------
Secure user registration screen for Log SOC Platform.

• First-time & normal registration
• Cancel / Back to Login
• SOC-grade UX
"""

from PySide6.QtWidgets import (
    QWidget, QLabel, QLineEdit, QPushButton,
    QVBoxLayout, QHBoxLayout, QMessageBox
)
from PySide6.QtCore import Qt, Signal
from PySide6.QtGui import QFont

from auth.auth_manager import AuthManager


class RegisterView(QWidget):
    """
    User registration screen.
    """

    registration_success = Signal()
    cancel_requested = Signal()   # ✅ FIX (THIS WAS MISSING)

    def __init__(self):
        super().__init__()

        self.auth = AuthManager()
        self._first_time = False

        self.setWindowTitle("Log SOC Platform — User Registration")
        self.setFixedSize(460, 440)

        self._build_ui()

    # ==================================================
    # CONFIG
    # ==================================================

    def set_first_time(self, first_time: bool):
        self._first_time = first_time
        self.cancel_btn.setVisible(not first_time)

    # ==================================================
    # UI
    # ==================================================

    def _build_ui(self):
        layout = QVBoxLayout(self)
        layout.setContentsMargins(40, 30, 40, 30)
        layout.setSpacing(10)

        title = QLabel("SOC USER REGISTRATION")
        title.setAlignment(Qt.AlignCenter)
        title.setFont(QFont("Segoe UI", 16, QFont.Bold))

        subtitle = QLabel("Create a secure SOC operator account")
        subtitle.setAlignment(Qt.AlignCenter)
        subtitle.setStyleSheet("color: gray; font-size: 11px;")

        # ---------- INPUTS ----------
        self.username_input = QLineEdit()
        self.username_input.setPlaceholderText("Username")

        self.email_input = QLineEdit()
        self.email_input.setPlaceholderText("Email")

        self.password_input = QLineEdit()
        self.password_input.setPlaceholderText("Password")
        self.password_input.setEchoMode(QLineEdit.Password)

        self.confirm_input = QLineEdit()
        self.confirm_input.setPlaceholderText("Confirm Password")
        self.confirm_input.setEchoMode(QLineEdit.Password)

        # ---------- BUTTONS ----------
        register_btn = QPushButton("Register")
        register_btn.setFixedHeight(36)
        register_btn.setStyleSheet(
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
        register_btn.clicked.connect(self._handle_register)

        self.cancel_btn = QPushButton("← Back to Login")
        self.cancel_btn.setFlat(True)
        self.cancel_btn.setStyleSheet("color: gray;")
        self.cancel_btn.clicked.connect(self.cancel_requested.emit)

        # ---------- ASSEMBLE ----------
        layout.addWidget(title)
        layout.addWidget(subtitle)
        layout.addSpacing(10)

        layout.addWidget(self.username_input)
        layout.addWidget(self.email_input)
        layout.addWidget(self.password_input)
        layout.addWidget(self.confirm_input)

        layout.addSpacing(12)
        layout.addWidget(register_btn)
        layout.addWidget(self.cancel_btn, alignment=Qt.AlignCenter)

        layout.addStretch()

    # ==================================================
    # ACTIONS
    # ==================================================

    def _handle_register(self):
        username = self.username_input.text().strip()
        email = self.email_input.text().strip()
        password = self.password_input.text()
        confirm = self.confirm_input.text()

        if not all([username, email, password, confirm]):
            QMessageBox.warning(self, "Missing Fields", "All fields are required.")
            return

        if password != confirm:
            QMessageBox.warning(self, "Password Error", "Passwords do not match.")
            return

        result = self.auth.register_user(username, email, password)

        if result.get("success"):
            QMessageBox.information(
                self,
                "Registration Successful",
                "User registered successfully."
            )
            self.registration_success.emit()
        else:
            QMessageBox.critical(
                self,
                "Registration Failed",
                result.get("error", "Unable to register user.")
            )
