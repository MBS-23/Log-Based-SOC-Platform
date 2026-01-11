"""
Detection Engine
----------------
Applies normalized log entries against detection rules
and assigns SOC-standard severity.

IOC-aware
Deterministic
Audit-safe
"""

import re
from typing import List, Dict

from core.rules import DETECTION_RULES
from config.severity_map import get_severity, SEVERITY_LEVELS


class DetectionEngine:
    """
    Core detection engine for SOC platform.
    """

    def __init__(self, ioc_engine=None):
        """
        IOC engine MUST be injected.
        Prevents duplication & race conditions.
        """
        self.ioc_engine = ioc_engine

        self.compiled_rules = {
            name: re.compile(pattern, re.IGNORECASE)
            for name, pattern in DETECTION_RULES.items()
        }

    # ===============================
    # SINGLE ENTRY ANALYSIS
    # ===============================

    def analyze_entry(self, entry: Dict) -> List[Dict]:
        if not isinstance(entry, dict):
            return []

        detections = []
        seen_rules = set()

        payload = entry.get("normalized_request") or entry.get("message") or ""
        if not isinstance(payload, str):
            payload = ""

        ip = entry.get("ip", "UNKNOWN")
        timestamp = entry.get("time", "UNKNOWN")

        raw = (
            entry.get("raw")
            or entry.get("original")
            or entry.get("message", "")
        )

        # -------------------------------
        # IOC CHECK (SAFE)
        # -------------------------------
        ioc_hit = False
        if self.ioc_engine and ip and ip != "UNKNOWN":
            try:
                ioc_hit = bool(self.ioc_engine.is_malicious(ip))
            except Exception:
                ioc_hit = False

        # -------------------------------
        # RULE MATCHING
        # -------------------------------
        for rule_name, regex in self.compiled_rules.items():
            if rule_name in seen_rules:
                continue

            if regex.search(payload):
                seen_rules.add(rule_name)

                base_severity = get_severity(rule_name)
                severity = self._escalate_severity(base_severity, ioc_hit)

                detections.append({
                    "rule": rule_name,
                    "severity": severity,
                    "ip": ip,
                    "time": timestamp,
                    "payload": payload,
                    "raw": raw,
                    "ioc_hit": ioc_hit
                })

        # -------------------------------
        # IOC-ONLY DETECTION (STRICT)
        # -------------------------------
        if ioc_hit and not detections:
            detections.append({
                "rule": "Threat Intelligence Match",
                "severity": "Critical",
                "ip": ip,
                "time": timestamp,
                "payload": "N/A (IP Reputation Match)",
                "raw": raw,
                "ioc_hit": True
            })

        return detections

    # ===============================
    # SEVERITY ESCALATION
    # ===============================

    def _escalate_severity(self, severity: str, ioc_hit: bool) -> str:
        if not ioc_hit or severity not in SEVERITY_LEVELS:
            return severity

        escalation = {
            "Low": "Medium",
            "Medium": "High",
            "High": "Critical",
            "Critical": "Critical"
        }

        return escalation.get(severity, severity)

    # ===============================
    # BATCH ANALYSIS
    # ===============================

    def analyze_batch(self, entries: List[Dict]) -> List[Dict]:
        results = []
        for entry in entries:
            results.extend(self.analyze_entry(entry))
        return results
