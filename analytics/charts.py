"""
Analytics: Charts Engine
------------------------
Reusable matplotlib chart generators for
SOC dashboards and PDF reports.

• Visualization ONLY
• No analytics logic
• No state
• EXE-safe
• SOC-style visuals
"""

from typing import Dict, List
import matplotlib

# ✅ EXE / headless safe backend
matplotlib.use("Agg")

import matplotlib.pyplot as plt
import logging

logger = logging.getLogger("SOC.Charts")


# -------------------------------------------------
# CONSTANTS
# -------------------------------------------------

SEVERITY_ORDER = ["Critical", "High", "Medium", "Low"]

SEVERITY_COLORS = {
    "Critical": "#dc2626",  # red
    "High": "#ea580c",      # orange
    "Medium": "#2563eb",    # blue
    "Low": "#16a34a",       # green
}


# -------------------------------------------------
# SEVERITY DISTRIBUTION
# -------------------------------------------------

def severity_distribution_chart(severity_counts: Dict[str, int]):
    """
    Generate a bar chart showing threat severity distribution.

    Args:
        severity_counts (Dict[str, int])

    Returns:
        matplotlib.figure.Figure or None
    """
    if not isinstance(severity_counts, dict) or not severity_counts:
        return None

    # Enforce SOC order & sanitize values
    severities = []
    counts = []
    colors = []

    for sev in SEVERITY_ORDER:
        value = severity_counts.get(sev)
        if isinstance(value, (int, float)) and value > 0:
            severities.append(sev)
            counts.append(int(value))
            colors.append(SEVERITY_COLORS.get(sev, "#6b7280"))

    if not severities:
        return None

    fig, ax = plt.subplots(figsize=(6, 4))

    ax.bar(severities, counts, color=colors)

    ax.set_title("Threat Severity Distribution")
    ax.set_xlabel("Severity Level")
    ax.set_ylabel("Detection Count")

    ax.grid(axis="y", linestyle="--", alpha=0.4)

    fig.tight_layout()
    return fig


# -------------------------------------------------
# TOP OFFENDING IPS
# -------------------------------------------------

def top_offenders_chart(top_ips: List[Dict]):
    """
    Generate a bar chart of top offending IP addresses.

    Args:
        top_ips (List[Dict])

    Returns:
        matplotlib.figure.Figure or None
    """
    if not isinstance(top_ips, list) or not top_ips:
        return None

    ips = []
    counts = []

    for item in top_ips:
        if not isinstance(item, dict):
            continue

        ip = item.get("ip")
        count = item.get("count")

        if isinstance(ip, str) and isinstance(count, (int, float)) and count > 0:
            ips.append(ip)
            counts.append(int(count))

    if not ips:
        return None

    fig, ax = plt.subplots(figsize=(7, 4))

    ax.bar(ips, counts, color="#2563eb")

    ax.set_title("Top Attacker IPs")
    ax.set_xlabel("IP Address")
    ax.set_ylabel("Detection Count")

    ax.tick_params(axis="x", rotation=45)
    ax.grid(axis="y", linestyle="--", alpha=0.4)

    fig.tight_layout()
    return fig
