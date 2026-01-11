"""
Threat Severity Mapping
-----------------------
Defines standardized SOC severity classification
for detected threat types.

✔ Mapping ONLY
❌ No detection logic
❌ No regex
❌ No response / blocking logic

Used by:
- Detection engine
- Correlation logic
- Reporting (PDF / Dashboard)
"""

# =====================================================
# SEVERITY LEVELS (SOC STANDARD)
# =====================================================

SEVERITY_LEVELS = (
    "Critical",  # Immediate response / containment
    "High",      # High risk, analyst review required
    "Medium",    # Suspicious, context-dependent
    "Low",       # Informational / baseline noise
)


# =====================================================
# THREAT → SEVERITY MAP
# =====================================================

THREAT_SEVERITY_MAP = {

    # -------------------------------------------------
    # 🔴 CRITICAL — Immediate Action / Auto-Block Eligible
    # -------------------------------------------------
    "SQL Injection": "Critical",
    "SQLi - Tautology / OR 1=1": "Critical",
    "Command Injection / Shell": "Critical",
    "Sensitive File Access": "Critical",
    "SSRF / Internal Resource Access": "Critical",

    "Serialized Object Detected (Java)": "Critical",
    "Serialized Object Detected (Python)": "Critical",
    "Serialized Object Detected (.NET)": "Critical",

    "Malicious Package Download": "Critical",
    "CI/CD Script Execution": "Critical",
    "Unexpected Build Dependency Fetch": "Critical",

    # -------------------------------------------------
    # 🟠 HIGH — High Risk / Analyst Investigation Required
    # -------------------------------------------------
    "XSS": "High",
    "XSS - Advanced Payloads": "High",
    "Credential Stuffing Probe": "High",
    "Unauthorized Admin Access": "High",
    "Plaintext Credential Exposure": "High",

    # -------------------------------------------------
    # 🟡 MEDIUM — Suspicious / Context & Correlation Needed
    # -------------------------------------------------
    "IDOR / Object Access Violation": "Medium",
    "Brute Force Attempt": "Medium",
    "Sensitive Data Over HTTP": "Medium",
    "Debug / Error Exposure": "Medium",
    "API Rate Abuse / Resource Exhaustion": "Medium",
    "Unhandled Exception Exposure": "Medium",
    "Directory Traversal": "Medium",

    # -------------------------------------------------
    # 🟢 LOW — Informational / Baseline Noise
    # -------------------------------------------------
    "Failed Login": "Low",  # Escalates via correlation logic
    "Weak Crypto Indicator": "Low",
    "Excessive Data Exposure": "Low",
    "Repeated Error Without Alerting": "Low",
    "Discovery / Recon Probes": "Low",
}


# =====================================================
# HELPER
# =====================================================

def get_severity(threat_name: str) -> str:
    """
    Return SOC severity for a given threat name.

    • Defaults to 'Low' if unmapped
    • Prevents crashes on unknown detections
    """
    return THREAT_SEVERITY_MAP.get(threat_name.strip(), "Low")
