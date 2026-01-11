"""
Global Configuration — Log SOC Platform
---------------------------------------
⚠ Configuration ONLY.
❌ No logic
❌ No imports from core / GUI

✔ SAFE to freeze into EXE
✔ SOC-compliant configuration layout
"""

from pathlib import Path

# =====================================================
# 1️⃣ PROJECT ROOT
# =====================================================

BASE_DIR = Path(__file__).resolve().parent.parent


# =====================================================
# 2️⃣ DATA DIRECTORIES
# =====================================================

DATA_DIR = BASE_DIR / "data"

LOGS_DIR = DATA_DIR / "logs"                 # Parsed / live logs
INCIDENT_DIR = DATA_DIR / "incidents"        # Incident JSON records
SAMPLE_LOG_DIR = DATA_DIR / "sample_logs"    # Test & demo logs

IOC_DIR = DATA_DIR / "iocs"                  # Threat intelligence feeds
CACHE_DIR = DATA_DIR / "cache"               # IOC + enrichment cache


# =====================================================
# 3️⃣ ASSETS
# =====================================================

ASSETS_DIR = BASE_DIR / "assets"
ICON_PATH = ASSETS_DIR / "icon.ico"
PROJECT_INFO_HTML = BASE_DIR / ASSETS_DIR / "project_info.html"



# =====================================================
# 4️⃣ REPORTING
# =====================================================

REPORT_DIR = BASE_DIR / "reports"
PDF_REPORT_DIR = REPORT_DIR / "pdf"
CSV_REPORT_DIR = REPORT_DIR / "csv"


# =====================================================
# 5️⃣ RESPONSE / PERSISTENCE
# =====================================================

BLOCKED_IPS_FILE = DATA_DIR / "blocked_ips.json"
IOC_CACHE_FILE = IOC_DIR / "reputation_cache.json"
IP_ENRICHMENT_CACHE = CACHE_DIR / "ip_enrichment_cache.json"


# =====================================================
# 6️⃣ FEATURE TOGGLES (SOC SAFE)
# =====================================================

FEATURES = {
    "EMAIL_ALERTS": True,
    "EMAIL_ALL_DETECTIONS": False,   # Avoid alert flooding during testing
    "FIREWALL_BLOCK": False,         # Disabled by default (safety)
    "IOC_CHECK": True,
    "GEO_IP_LOOKUP": True,
    "REALTIME_MONITORING": True,
    "PDF_REPORTS": True,
}


# =====================================================
# 7️⃣ DETECTION THRESHOLDS
# =====================================================

THRESHOLDS = {
    "FAILED_LOGINS": 5,
    "SCAN_REQUESTS": 30,
    "HIGH_CPU_USAGE": 90.0,   # %
    "HIGH_RAM_USAGE": 90.0,   # %
}


# =====================================================
# 8️⃣ AUTO-RESPONSE POLICY
# =====================================================

AUTO_BLOCK = {
    "ENABLED": False,          # Master kill-switch
    "MIN_SEVERITY": "Critical",
    "REQUIRE_IOC": True,       # SOC safety rule
}


# =====================================================
# 9️⃣ EMAIL CONFIGURATION
# =====================================================

EMAIL_CONFIG = {
    "SMTP_SERVER": "smtp.gmail.com",
    "SMTP_PORT": 587,

    # ⚠ IMPORTANT:
    # Use a Google APP PASSWORD (not your real Gmail password)
    # Google Account → Security → 2-Step Verification → App Passwords
    "SENDER_EMAIL": "your-email@gmail.com",
    "SENDER_PASSWORD": "your-app-password-here",

    # Default SOC admin / receiver
    "RECEIVER_EMAIL": "admin-security@company.com",

    "USE_TLS": True,
}


# =====================================================
# 🔟 LOGGING
# =====================================================

LOG_LEVEL = "INFO"
APP_LOG_FILE = BASE_DIR / "soc_platform.log"
APP_LOG_FILE.parent.mkdir(parents=True, exist_ok=True)
# =====================================================
# 11 INIT UTILITIES
# =====================================================

def ensure_directories():
    """
    Create required directories at application startup.

    ✔ Safe to call multiple times
    ✔ EXE compatible
    """
    paths = [
        DATA_DIR,
        LOGS_DIR,
        INCIDENT_DIR,
        SAMPLE_LOG_DIR,
        IOC_DIR,
        CACHE_DIR,
        REPORT_DIR,
        PDF_REPORT_DIR,
        CSV_REPORT_DIR,
        ASSETS_DIR,
    ]

    for path in paths:
        path.mkdir(parents=True, exist_ok=True)

    # Initialize blocked IP history
    if not BLOCKED_IPS_FILE.exists():
        BLOCKED_IPS_FILE.write_text("{}", encoding="utf-8")
