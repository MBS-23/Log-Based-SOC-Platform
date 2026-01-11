"""
Analytics: Statistics Engine
----------------------------
Aggregation utilities for SOC detections and incidents.

• Aggregation ONLY
• No detection logic
• No visualization
• Stateless
• EXE-safe
• SOC-hardened
"""

from collections import Counter
from typing import List, Dict


# -------------------------------------------------
# CONSTANTS
# -------------------------------------------------

VALID_SEVERITIES = {"Critical", "High", "Medium", "Low"}


# -------------------------------------------------
# SEVERITY COUNTS
# -------------------------------------------------

def severity_counts(detections: List[Dict]) -> Dict[str, int]:
    """
    Count detections grouped by SOC severity.

    Invalid or unknown severities are ignored.
    """
    if not isinstance(detections, list):
        return {}

    counter = Counter()

    for d in detections:
        if not isinstance(d, dict):
            continue

        severity = d.get("severity")
        if not isinstance(severity, str):
            continue

        severity = severity.strip().capitalize()

        if severity in VALID_SEVERITIES:
            counter[severity] += 1

    return dict(counter)


# -------------------------------------------------
# TOP OFFENDER IPS
# -------------------------------------------------

def top_offender_ips(detections: List[Dict], limit: int = 10) -> List[Dict]:
    """
    Identify top offending IP addresses by detection count.

    Invalid / UNKNOWN IPs are ignored.
    """
    if not isinstance(detections, list):
        return []

    counter = Counter()

    for d in detections:
        if not isinstance(d, dict):
            continue

        ip = d.get("ip")
        if not isinstance(ip, str):
            continue

        ip = ip.strip()

        if not ip or ip.upper() == "UNKNOWN":
            continue

        counter[ip] += 1

    return [
        {"ip": ip, "count": count}
        for ip, count in counter.most_common(limit)
    ]


# -------------------------------------------------
# INCIDENT SUMMARY
# -------------------------------------------------

def incident_summary(incidents: List[Dict]) -> Dict[str, int]:
    """
    Summarize incidents grouped by incident type.

    Invalid records are safely ignored.
    """
    if not isinstance(incidents, list):
        return {}

    counter = Counter()

    for i in incidents:
        if not isinstance(i, dict):
            continue

        incident_type = i.get("type")
        if not isinstance(incident_type, str):
            continue

        incident_type = incident_type.strip()

        if incident_type:
            counter[incident_type] += 1

    return dict(counter)
# -------------------------------------------------
# END OF FILE