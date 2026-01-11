"""
Response Controller
-------------------
Central hub for deciding how to react to alerts.

Flow:
Detection → Firewall → Email → PDF Report

✔ SOC-safe
✔ Deterministic
✔ Thread-safe
✔ Audit-friendly
✔ EXE-safe
"""

import threading
import logging
from datetime import datetime, timedelta

from PySide6.QtCore import QObject, Signal

from response.firewall import FirewallController
from response.alerting import AlertManager
from reporting.pdf_reporter import PDFIncidentReporter
from config.settings import AUTO_BLOCK, FEATURES


class ResponseEngine(QObject):
    """
    Central SOC response orchestrator.
    """

    # 🔔 UI SIGNAL
    ip_blocked = Signal()

    def __init__(self):
        super().__init__()

        self.firewall = FirewallController()
        self.alerter = AlertManager()
        self.reporter = PDFIncidentReporter()

        self.logger = logging.getLogger("SOC.Response")

        # Prevent duplicate responses
        self._handled_incidents = {}
        self._lock = threading.Lock()

        self._dedup_ttl = timedelta(minutes=10)

        # 🔒 HARD LIMIT → ONE PDF PER RUN
        self._pdf_generated_for_run = False

    # ==================================================
    # PUBLIC ENTRY POINT
    # ==================================================

    def handle_detection(self, detection: dict):
        if not detection:
            return

        severity = detection.get("severity", "Low")
        ip = detection.get("ip", "UNKNOWN")
        rule = detection.get("rule", "Unknown Threat")
        ioc_hit = bool(detection.get("ioc_hit", False))

        incident_key = (ip, rule, severity)
        now = datetime.utcnow()

        # =========================
        # 🔒 DEDUPLICATION
        # =========================
        with self._lock:
            self._cleanup_old_incidents(now)

            if incident_key in self._handled_incidents:
                return

            self._handled_incidents[incident_key] = now

        # =========================
        # 1️⃣ FIREWALL RESPONSE
        # =========================
        try:
            blocked = self._handle_firewall(severity, ip, rule, ioc_hit)
            if blocked:
                self.ip_blocked.emit()
        except Exception as exc:
            self.logger.error("Firewall response failed: %s", exc)

        # =========================
        # 2️⃣ EMAIL ALERT
        # =========================
        try:
            self._handle_email(severity, detection)
        except Exception as exc:
            self.logger.error("Email alert failed: %s", exc)

        # =========================
        # 3️⃣ PDF INCIDENT REPORT (ONE PER RUN)
        # =========================
        if not self._pdf_generated_for_run:
            try:
                report_path = self.reporter.generate(detection)
                self._pdf_generated_for_run = True
                self.logger.info(
                    "📄 Incident report generated → %s",
                    report_path.name
                )
            except Exception as exc:
                self.logger.error("PDF generation failed: %s", exc)

    # ==================================================
    # INTERNAL HANDLERS
    # ==================================================

    def _handle_firewall(
        self,
        severity: str,
        ip: str,
        rule: str,
        ioc_hit: bool
    ) -> bool:
        if not AUTO_BLOCK.get("ENABLED", False):
            return False

        if AUTO_BLOCK.get("REQUIRE_IOC", True):
            should_block = severity == "Critical" and ioc_hit
        else:
            should_block = severity == "Critical"

        if should_block and ip and ip != "UNKNOWN":
            self.firewall.block_ip(
                ip=ip,
                reason=rule,
                ioc_confirmed=ioc_hit
            )
            return True

        return False

    def _handle_email(self, severity: str, detection: dict):
        if not FEATURES.get("EMAIL_ALERTS", False):
            return

        if FEATURES.get("EMAIL_ALL_DETECTIONS", False):
            self.alerter.send_alert(detection)
        elif severity in ("High", "Critical"):
            self.alerter.send_alert(detection)

    # ==================================================
    # HOUSEKEEPING
    # ==================================================

    def _cleanup_old_incidents(self, now: datetime):
        expired = [
            key for key, ts in self._handled_incidents.items()
            if now - ts > self._dedup_ttl
        ]

        for key in expired:
            self._handled_incidents.pop(key, None)
