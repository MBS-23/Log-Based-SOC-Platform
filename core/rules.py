"""
Threat Detection Rules (OWASP-Aligned)
------------------------------------

Log-based detection rules mapped to:
- OWASP Web Top 10 (2013–2025)
- OWASP API Top 10

IMPORTANT:
• These rules detect INDICATORS in logs
• They are NOT proof of exploitation
• Correlation & escalation are handled elsewhere
"""

from collections import OrderedDict


DETECTION_RULES = OrderedDict({

    # =====================================================
    # A03 / A1 — INJECTION (SQL, OS, TEMPLATE)
    # =====================================================

    "SQL Injection":
        r"(\bunion\s+select\b|\bselect\s+\*\b|\bdrop\s+table\b|\binsert\s+into\b|--|\bor\b\s+.+?=.+?)",

    "SQLi - Tautology / OR 1=1":
        r"(\bor\b\s*1\s*=\s*1|'?\s*or\s*'?\s*1'\s*=\s*'1|\bunion\b.*\bselect\b)",

    "Command Injection / Shell":
        r"(\|\||&&|`|\$\(|\b(cmd|exec|system)\s*=|\bwget\b|\bcurl\b)",


    # =====================================================
    # A03 — CROSS-SITE SCRIPTING (XSS)
    # =====================================================

    "XSS":
        r"(<script\b|javascript:|onerror\s*=|onload\s*=)",

    "XSS - Advanced Payloads":
        r"(<svg\b|<iframe\b|document\.cookie|window\.location)",


    # =====================================================
    # A01 — BROKEN ACCESS CONTROL / IDOR
    # =====================================================

    "IDOR / Object Access Violation":
        r"(/api/[^ ]*/\d+|\b(id|user|account)\s*=\s*\d+)",

    "Unauthorized Admin Access":
        r"(/admin\b|/wp-admin\b|/manager/html)",


    # =====================================================
    # A07 — AUTHENTICATION FAILURES
    # =====================================================

    "Failed Login":
        r"(failed\s+login|invalid\s+password|authentication\s+failure|\b401\b)",

    "Credential Stuffing Probe":
        r"(\b(username|login|user)\b.{1,80}\b(password|pass|pwd)\b)",

    "Brute Force Attempt":
        r"(login).*?\b(401|403)\b",


    # =====================================================
    # A05 — SECURITY MISCONFIGURATION
    # =====================================================

    "Sensitive File Access":
        r"(/etc/passwd|/etc/shadow|\.env\b|\.git/|config\.php|web\.config)",

    "Debug / Error Exposure":
        r"(stack\s+trace|exception|traceback|fatal\s+error)",


    # =====================================================
    # A02 / A04 — CRYPTOGRAPHIC FAILURES (LOG INDICATORS)
    # =====================================================

    "Plaintext Credential Exposure":
        r"(password\s*=|passwd\s*=|secret\s*=|api[_-]?key\s*=)",

    "Weak Crypto Indicator":
        r"\b(md5|sha1|des|rc4)\b",

    "Sensitive Data Over HTTP":
        r"(http://).*?(token|password|session)",


    # =====================================================
    # A08 — INSECURE DESERIALIZATION
    # =====================================================

    "Serialized Object Detected (Java)":
        r"(rO0AB|java\.io\.ObjectInputStream)",

    "Serialized Object Detected (Python)":
        r"(pickle\.loads|__reduce__)",

    "Serialized Object Detected (.NET)":
        r"(BinaryFormatter|ObjectStateFormatter)",


    # =====================================================
    # A10 / API7 — SERVER-SIDE REQUEST FORGERY (SSRF)
    # =====================================================

    "SSRF / Internal Resource Access":
        r"(http://(127\.0\.0\.1|localhost|169\.254\.169\.254|0\.0\.0\.0))",


    # =====================================================
    # A08 / A03 (2025) — SUPPLY CHAIN ATTACK INDICATORS
    # =====================================================

    "Malicious Package Download":
        r"(pip\s+install|npm\s+install|curl|wget).*?(github\.com|raw\.githubusercontent\.com)",

    "CI/CD Script Execution":
        r"(bash\s+-c|powershell\s+-enc|sh\s+-c)",

    "Unexpected Build Dependency Fetch":
        r"(package\.json|requirements\.txt).*?(http|https)",


    # =====================================================
    # OWASP API TOP 10 — RESOURCE ABUSE
    # =====================================================

    "API Rate Abuse / Resource Exhaustion":
        r"(/api/).*?\b(429|too\s+many\s+requests)\b",

    "Excessive Data Exposure":
        r"\?.{300,}",


    # =====================================================
    # A09 — LOGGING & MONITORING FAILURES (META)
    # =====================================================

    "Repeated Error Without Alerting":
        r"\b(500|502|503|504)\b",


    # =====================================================
    # A10 (2025) — EXCEPTION HANDLING FAILURES
    # =====================================================

    "Unhandled Exception Exposure":
        r"\b(NullPointerException|IndexError|KeyError|ValueError)\b",
})
