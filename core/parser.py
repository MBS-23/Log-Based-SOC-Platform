"""
Log Parser Module
----------------

Responsible for:
- Parsing raw log lines
- Extracting structured fields (IP, Timestamp, Request)
- Preserving original log evidence for reporting

IMPORTANT:
• This module does NOT perform detection
• This module does NOT modify original log content
• Output is designed for normalization & detection stages
"""

import re
from typing import Dict, Any


# =================================================
# 1. COMPILED PATTERNS (Performance & Safety)
# =================================================

# Apache / Nginx Combined Log Format
# Example:
# 127.0.0.1 - - [10/Oct/2000:13:55:36 -0700] "GET /foo HTTP/1.1" 200 2326
APACHE_COMBINED_PATTERN = re.compile(
    r'(?P<ip>\d{1,3}(?:\.\d{1,3}){3})\s+'     # IP address
    r'-\s+-\s+'                               # Identity fields (ignored)
    r'\[(?P<time>[^\]]+)\]\s+'                # Timestamp
    r'"(?P<request>[^"]+)"\s+'                # Request line
    r'(?P<status>\d{3})',                     # HTTP status
    re.ASCII
)

# Generic fallback patterns
IP_PATTERN = re.compile(r"\d{1,3}(?:\.\d{1,3}){3}")
TIME_PATTERN = re.compile(
    r"\d{4}[-/]\d{2}[-/]\d{2}[ T]\d{2}:\d{2}:\d{2}"
)


# =================================================
# 2. PARSER LOGIC
# =================================================

def parse_log_line(line: str) -> Dict[str, Any]:
    """
    Parse a single raw log line into structured fields.

    Always returns a dictionary with safe defaults.
    """
    if not line or not isinstance(line, str):
        return {}

    line = line.strip()

    # -------------------------------------------------
    # Attempt 1: Standard Web Server Logs
    # -------------------------------------------------

    match = APACHE_COMBINED_PATTERN.search(line)
    if match:
        return {
            "time": match.group("time"),
            "ip": match.group("ip"),
            "request": match.group("request"),
            "status": match.group("status"),
            "raw": line,
        }

    # -------------------------------------------------
    # Attempt 2: Generic / Syslog / Application Logs
    # -------------------------------------------------

    ip_match = IP_PATTERN.search(line)
    time_match = TIME_PATTERN.search(line)

    return {
        "time": time_match.group(0) if time_match else "UNKNOWN",
        "ip": ip_match.group(0) if ip_match else "UNKNOWN",
        # Hard truncation for UI + memory safety
        "request": line[:200],
        "status": "UNKNOWN",
        "raw": line,
    }
