"""
SOC Login Interface (PySide6)
----------------------------
Secure authentication screen for Log SOC Platform.

• Username OR Email login
• Register New User
• Forgot Password
• SOC-grade UX
"""

from PySide6.QtWidgets import (
    QWidget, QLabel, QLineEdit, QPushButton,
    QVBoxLayout, QHBoxLayout, QMessageBox
)
from PySide6.QtCore import Qt, Signal
from PySide6.QtGui import QFont

from auth.auth_manager import AuthManager


class LoginView(QWidget):
    """
    Login screen widget.
    Emits signal on successful login.
    """

    login_success = Signal(dict)
    open_register = Signal()
    open_forgot_password = Signal()

    def __init__(self):
        super().__init__()

        self.auth = AuthManager()

        self.setWindowTitle("Log SOC Platform — Secure Login")
        self.setFixedSize(420, 360)

        self._build_ui()

    # ==================================================
    # UI
    # ==================================================

    def _build_ui(self):
        main_layout = QVBoxLayout(self)
        main_layout.setSpacing(12)
        main_layout.setContentsMargins(40, 30, 40, 30)

        title = QLabel("SOC OPERATOR LOGIN")
        title.setAlignment(Qt.AlignCenter)
        title.setFont(QFont("Segoe UI", 16, QFont.Bold))

        subtitle = QLabel("Access restricted to authorized SOC personnel")
        subtitle.setAlignment(Qt.AlignCenter)
        subtitle.setStyleSheet("color: gray; font-size: 11px;")

        # -------- FORM --------

        form_layout = QVBoxLayout()
        form_layout.setSpacing(8)

        self.identifier_input = QLineEdit()
        self.identifier_input.setPlaceholderText("Username or Email")
        self.identifier_input.setClearButtonEnabled(True)

        self.password_input = QLineEdit()
        self.password_input.setPlaceholderText("Password")
        self.password_input.setEchoMode(QLineEdit.Password)

        self.identifier_input.returnPressed.connect(self._handle_login)
        self.password_input.returnPressed.connect(self._handle_login)

        form_layout.addWidget(self.identifier_input)
        form_layout.addWidget(self.password_input)

        # -------- LOGIN BUTTON --------

        login_btn = QPushButton("Login")
        login_btn.setFixedHeight(36)
        login_btn.setStyleSheet(
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
        login_btn.clicked.connect(self._handle_login)

        # -------- ACTION LINKS --------

        actions_layout = QVBoxLayout()

        register_btn = QPushButton("➕ Register New User")
        register_btn.setFlat(True)
        register_btn.setStyleSheet("color: #2563eb;")
        register_btn.clicked.connect(self.open_register.emit)

        forgot_btn = QPushButton("🔑 Forgot Password?")
        forgot_btn.setFlat(True)
        forgot_btn.setStyleSheet("color: gray;")
        forgot_btn.clicked.connect(self.open_forgot_password.emit)

        actions_layout.addWidget(register_btn, alignment=Qt.AlignCenter)
        actions_layout.addWidget(forgot_btn, alignment=Qt.AlignCenter)

        # -------- ASSEMBLE --------

        main_layout.addWidget(title)
        main_layout.addSpacing(8)
        main_layout.addLayout(form_layout)
        main_layout.addSpacing(10)
        main_layout.addWidget(login_btn)
        main_layout.addLayout(actions_layout)
        main_layout.addStretch()
        main_layout.addWidget(subtitle)

        self.identifier_input.setFocus()

    # ==================================================
    # AUTH
    # ==================================================

    def _handle_login(self):
        identifier = self.identifier_input.text().strip()
        password = self.password_input.text()

        if not identifier or not password:
            QMessageBox.warning(
                self,
                "Missing Fields",
                "Please enter username/email and password."
            )
            return

        result = self.auth.authenticate(identifier, password)

        if result.get("success"):
            self.login_success.emit(result["user"])
        else:
            QMessageBox.critical(
                self,
                "Access Denied",
                result.get("error", "Authentication failed")
            )
