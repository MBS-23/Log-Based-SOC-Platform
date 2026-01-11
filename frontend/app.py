"""
Log SOC Platform — Application Entry Point (PySide6)
---------------------------------------------------
Bootstraps the SOC platform safely and launches the UI.

✔ EXE-safe
✔ Single QApplication
✔ Centralized base-path resolver
✔ PNG-based app icon
✔ Enterprise SOC standard
"""

import sys
import logging
from pathlib import Path

from PySide6.QtWidgets import QApplication
from PySide6.QtGui import QIcon

# =================================================
# 🔒 BASE PATH (SOURCE vs EXE SAFE)
# =================================================
def get_base_dir() -> Path:
    """
    Returns application base directory.
    - Source run → project root
    - EXE run    → PyInstaller _MEIPASS
    """
    if getattr(sys, "frozen", False):
        return Path(sys._MEIPASS)
    return Path(__file__).resolve().parent.parent


BASE_DIR = get_base_dir()
sys.path.insert(0, str(BASE_DIR))

# =================================================
# 🖼️ ICON RESOLUTION (PNG, EXE-SAFE)
# =================================================
def get_app_icon() -> QIcon:
    """
    Load application icon safely for both:
    - python run
    - PyInstaller EXE
    """
    icon_path = BASE_DIR / "assets" / "icons" / "logsoc.png"
    if icon_path.exists():
        return QIcon(str(icon_path))
    return QIcon()  # silent fallback


# =================================================
# CORE IMPORTS (AFTER PATH FIX)
# =================================================
from config.settings import (
    ensure_directories,
    APP_LOG_FILE,
    LOG_LEVEL,
)
from frontend.main_window import MainWindow

# =================================================
# METADATA
# =================================================
PROJECT_NAME = "Log SOC Platform"
ORG_NAME = "SOC Security"
MIN_PYTHON = (3, 9)

# =================================================
# ENV CHECK
# =================================================
def check_python_version():
    if sys.version_info < MIN_PYTHON:
        raise RuntimeError(
            f"{PROJECT_NAME} requires Python "
            f"{MIN_PYTHON[0]}.{MIN_PYTHON[1]}+"
        )

# =================================================
# LOGGING
# =================================================
def setup_logging():
    logging.basicConfig(
        level=getattr(logging, LOG_LEVEL, logging.INFO),
        format="%(asctime)s | %(levelname)s | %(name)s | %(message)s",
        handlers=[
            logging.StreamHandler(sys.stdout),
            logging.FileHandler(APP_LOG_FILE, encoding="utf-8"),
        ],
    )

# =================================================
# APPLICATION BOOTSTRAP
# =================================================
def main():
    # 1️⃣ Environment validation
    check_python_version()

    try:
        ensure_directories()
        setup_logging()
    except Exception as exc:
        print(f"[CRITICAL] Startup failed: {exc}")
        sys.exit(1)

    logging.info("=" * 60)
    logging.info("Starting %s", PROJECT_NAME)
    logging.info("Base Dir: %s", BASE_DIR)
    logging.info("OS: %s | Python: %s", sys.platform, sys.version.split()[0])
    logging.info("=" * 60)

    # 2️⃣ QApplication (SINGLE INSTANCE)
    app = QApplication(sys.argv)
    app.setApplicationName(PROJECT_NAME)
    app.setOrganizationName(ORG_NAME)
    app.setWindowIcon(get_app_icon())  # 🔥 GLOBAL APP ICON

    # 3️⃣ Launch Main Window
    try:
        window = MainWindow()
        window.setWindowIcon(get_app_icon())  # 🔥 WINDOW ICON
        window.show()
    except Exception:
        logging.exception("Failed to launch MainWindow")
        sys.exit(1)

    # 4️⃣ Event loop
    sys.exit(app.exec())


# =================================================
# ENTRY POINT
# =================================================
if __name__ == "__main__":
    main()
