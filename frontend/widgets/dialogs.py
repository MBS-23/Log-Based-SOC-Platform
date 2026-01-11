"""
SOC Dialogs
-----------
Centralized dialog utilities for Log-Based SOC Platform.

• Consistent UI
• QSS-driven styling
• Modal & safe
• EXE-compatible
• SOC-grade messaging

UI ONLY
"""

from PySide6.QtWidgets import QMessageBox, QWidget
from PySide6.QtCore import Qt


# ==================================================
# BASE DIALOG FACTORY
# ==================================================

def _base_box(parent: QWidget | None) -> QMessageBox:
    """
    Create a base SOC dialog with safe defaults.
    """
    box = QMessageBox(parent)
    box.setWindowModality(Qt.ApplicationModal)
    box.setWindowFlag(Qt.WindowStaysOnTopHint)
    box.setMinimumWidth(360)
    return box


# ==================================================
# INFORMATION
# ==================================================

def info(parent: QWidget | None, title: str, message: str):
    box = _base_box(parent)
    box.setIcon(QMessageBox.Information)
    box.setWindowTitle(f"INFO — {title}")
    box.setText(message)
    box.setStandardButtons(QMessageBox.Ok)
    box.exec()


# ==================================================
# WARNING
# ==================================================

def warning(parent: QWidget | None, title: str, message: str):
    box = _base_box(parent)
    box.setIcon(QMessageBox.Warning)
    box.setWindowTitle(f"WARNING — {title}")
    box.setText(message)
    box.setStandardButtons(QMessageBox.Ok)
    box.exec()


# ==================================================
# ERROR
# ==================================================

def error(parent: QWidget | None, title: str, message: str):
    box = _base_box(parent)
    box.setIcon(QMessageBox.Critical)
    box.setWindowTitle(f"ERROR — {title}")
    box.setText(message)
    box.setStandardButtons(QMessageBox.Ok)
    box.exec()


# ==================================================
# CONFIRMATION
# ==================================================

def confirm(
    parent: QWidget | None,
    title: str,
    message: str,
    *,
    yes_text: str = "Yes",
    no_text: str = "No",
) -> bool:
    """
    Confirmation dialog.

    Returns:
        True if Yes pressed, False otherwise.
    """
    box = _base_box(parent)
    box.setIcon(QMessageBox.Question)
    box.setWindowTitle(f"CONFIRM — {title}")
    box.setText(message)

    yes_btn = box.addButton(yes_text, QMessageBox.YesRole)
    no_btn = box.addButton(no_text, QMessageBox.NoRole)
    box.setDefaultButton(no_btn)

    box.exec()
    return box.clickedButton() == yes_btn


# ==================================================
# CRITICAL SOC ALERT
# ==================================================

def critical_alert(parent: QWidget | None, title: str, message: str):
    """
    SOC Critical Alert dialog.

    Used for:
    - Confirmed attacks
    - Firewall block confirmation
    - System-level failures

    NOTE:
    This dialog intentionally overrides QSS
    to enforce maximum operator attention.
    """
    box = _base_box(parent)
    box.setIcon(QMessageBox.Critical)
    box.setWindowTitle(f"🚨 CRITICAL — {title}")
    box.setText(message)
    box.setStandardButtons(QMessageBox.Ok)

    # Intentional override (SOC emergency UX)
    box.setStyleSheet(
        """
        QMessageBox {
            background-color: #020617;
            color: white;
            font-family: "Segoe UI";
            font-size: 11px;
        }
        QMessageBox QLabel {
            color: white;
        }
        QMessageBox QPushButton {
            background-color: #dc2626;
            color: white;
            min-width: 100px;
            min-height: 32px;
            border-radius: 6px;
            font-weight: bold;
        }
        QMessageBox QPushButton:hover {
            background-color: #b91c1c;
        }
        """
    )

    box.exec()
