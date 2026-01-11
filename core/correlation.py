"""
Correlation Engine
------------------
Analyzes detected events over time to identify
attack patterns and escalate severity.

• Correlation ONLY
• No blocking
• No alerting
• No response logic
"""

from collections import defaultdict
from datetime import datetime, timedelta
from typing import List, Dict


class CorrelationEngine:
    """
    SOC correlation engine.
    """

    def __init__(self, time_window_minutes: int = 5):
        self.time_window = timedelta(minutes=time_window_minutes)

    # =================================================
    # PUBLIC INTERFACE
    # =================================================

    def correlate(self, detections: List[Dict]) -> List[Dict]:
        """
        Correlate raw detections into higher-level incidents.

        Args:
            detections (List[Dict]):
                Detection events with at least:
                ip, time, rule, severity

        Returns:
            List[Dict]:
                Correlated incident records.
        """
        if not detections:
            return []

        incidents: List[Dict] = []

        # Group detections by source IP
        grouped_by_ip = defaultdict(list)
        for d in detections:
            grouped_by_ip[d.get("ip", "UNKNOWN")].append(d)

        for ip, events in grouped_by_ip.items():
            # Sort events by timestamp (best effort)
            events.sort(key=lambda x: x.get("time", ""))

            recent_events = self._filter_time_window(events)
            incidents.extend(self._analyze_ip(ip, recent_events))

        return incidents

    # =================================================
    # INTERNAL HELPERS
    # =================================================

    def _filter_time_window(self, events: List[Dict]) -> List[Dict]:
        """
        Keep only events inside the configured correlation window.
        """
        if not events:
            return []

        try:
            latest_time = self._parse_time(events[-1].get("time"))
        except Exception:
            return events  # Safe fallback

        cutoff = latest_time - self.time_window

        filtered = []
        for e in events:
            try:
                event_time = self._parse_time(e.get("time"))
                if event_time >= cutoff:
                    filtered.append(e)
            except Exception:
                filtered.append(e)

        return filtered

    def _parse_time(self, time_str: str) -> datetime:
        """
        Best-effort timestamp parsing.
        Never raises.
        """
        if not time_str or time_str == "UNKNOWN":
            return datetime.utcnow()

        # Try ISO first
        try:
            return datetime.fromisoformat(time_str)
        except Exception:
            pass

        # Try Apache format: 10/Oct/2000:13:55:36 -0700
        try:
            return datetime.strptime(time_str.split(" ")[0], "%d/%b/%Y:%H:%M:%S")
        except Exception:
            return datetime.utcnow()


    # =================================================
    # IP-LEVEL ANALYSIS
    # =================================================

    def _analyze_ip(self, ip: str, events: List[Dict]) -> List[Dict]:
        """
        Analyze correlated events for a single IP.
        """
        incidents: List[Dict] = []

        if not events:
            return incidents

        # -------------------------------------------------
        # Brute Force Login Attack
        # -------------------------------------------------

        failed_logins = [
            e for e in events
            if "Failed Login" in e.get("rule", "")
        ]

        if len(failed_logins) >= 5:
            incidents.append({
                "ip": ip,
                "type": "Brute Force Login Attack",
                "severity": "High",
                "count": len(failed_logins),
                "ioc_confirmed": any(e.get("ioc_hit") for e in failed_logins),
                "evidence": failed_logins,
            })

        # -------------------------------------------------
        # Reconnaissance → Exploitation Chain
        # -------------------------------------------------

        scanner_hits = [
            e for e in events
            if "Scanner" in e.get("rule", "")
        ]

        exploit_hits = [
            e for e in events
            if e.get("severity") == "Critical"
        ]

        if scanner_hits and exploit_hits:
            incidents.append({
                "ip": ip,
                "type": "Reconnaissance Followed by Exploitation",
                "severity": "Critical",
                "count": len(scanner_hits) + len(exploit_hits),
                "ioc_confirmed": any(e.get("ioc_hit") for e in exploit_hits),
                "evidence": scanner_hits + exploit_hits,
            })

        # -------------------------------------------------
        # Repeated Critical Attacks
        # -------------------------------------------------

        if len(exploit_hits) >= 3:
            incidents.append({
                "ip": ip,
                "type": "Repeated Critical Attack Attempts",
                "severity": "Critical",
                "count": len(exploit_hits),
                "ioc_confirmed": any(e.get("ioc_hit") for e in exploit_hits),
                "evidence": exploit_hits,
            })

        # -------------------------------------------------
        # High Volume Suspicious Activity
        # -------------------------------------------------

        if len(events) >= 10:
            incidents.append({
                "ip": ip,
                "type": "High Volume Suspicious Activity",
                "severity": "Medium",
                "count": len(events),
                "ioc_confirmed": any(e.get("ioc_hit") for e in events),
                "evidence": events,
            })

        return incidents
