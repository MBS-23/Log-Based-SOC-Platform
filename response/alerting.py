"""
Alerting Module
---------------
Handles SOC alert notifications via Email.

✔ Batch-safe
✔ Rate-limited
✔ Thread-isolated
✔ Fail-silent (SOC UX)
✔ EXE-safe
✔ Demo-safe
"""

import smtplib
import logging
import threading
from datetime import datetime, timedelta
from email.message import EmailMessage
from email.utils import formatdate
from typing import List

from config.settings import FEATURES, EMAIL_CONFIG


class AlertManager:
    """
    SOC Email Alert Manager (Enterprise Grade)
    """

    def __init__(self):
        self.logger = logging.getLogger("SOC.Alerting")

        # 🔐 Feature flag (MASTER SWITCH)
        self.enabled = bool(FEATURES.get("EMAIL_ALERTS", False))

        # 🔍 Configuration validation
        self._config_valid = all([
            EMAIL_CONFIG.get("SMTP_SERVER"),
            EMAIL_CONFIG.get("SMTP_PORT"),
            EMAIL_CONFIG.get("SENDER_EMAIL"),
            EMAIL_CONFIG.get("RECEIVER_EMAIL"),
        ])

        # ⏱ Rate limiting (SOC standard)
        self._last_sent: datetime | None = None
        self._cooldown = timedelta(seconds=30)
        self._lock = threading.Lock()

        if self.enabled and not self._config_valid:
            self.logger.warning(
                "Email alerts ENABLED but EMAIL_CONFIG is incomplete"
            )

        if not self.enabled:
            self.logger.info("Email alerts DISABLED (safe demo mode)")

    # ==================================================
    # BACKWARD COMPATIBILITY
    # ==================================================

    def send_alert(self, detection: dict):
        """
        Backward-compatible API (single detection).
        Internally routed to batch handler.
        """
        if detection:
            self.send_batch_alerts([detection])

    # ==================================================
    # BATCH API (SOC STANDARD)
    # ==================================================

    def send_batch_alerts(self, detections: List[dict]):
        """
        Send ONE email for MULTIPLE detections.
        Fully rate-limited and thread-safe.
        """
        if not self.enabled:
            return

        if not self._config_valid:
            self.logger.debug("Email skipped (invalid configuration)")
            return

        if not detections:
            return

        threading.Thread(
            target=self._send_batch_safe,
            args=(detections,),
            daemon=True
        ).start()

    # ==================================================
    # INTERNAL — SMTP (THREAD + RATE SAFE)
    # ==================================================

    def _send_batch_safe(self, detections: List[dict]):
        try:
            # ⛔ Rate limiting
            with self._lock:
                now = datetime.utcnow()
                if self._last_sent and now - self._last_sent < self._cooldown:
                    self.logger.debug("Email suppressed (rate limit)")
                    return
                self._last_sent = now

            # 📨 Build message
            msg = EmailMessage()

            highest_sev = self._highest_severity(detections)

            msg["Subject"] = (
                f"[SOC ALERT] {len(detections)} Detection(s) | "
                f"Highest Severity: {highest_sev}"
            )

            msg["From"] = EMAIL_CONFIG["SENDER_EMAIL"]
            msg["To"] = EMAIL_CONFIG["RECEIVER_EMAIL"]
            msg["Date"] = formatdate(localtime=True)

            msg.set_content(self._format_batch_body(detections))

            # 🌐 SMTP
            with smtplib.SMTP(
                EMAIL_CONFIG["SMTP_SERVER"],
                EMAIL_CONFIG["SMTP_PORT"],
                timeout=10
            ) as server:

                if EMAIL_CONFIG.get("USE_TLS", True):
                    server.starttls()

                password = EMAIL_CONFIG.get("SENDER_PASSWORD")
                if password:
                    server.login(
                        EMAIL_CONFIG["SENDER_EMAIL"],
                        password
                    )

                server.send_message(msg)

            self.logger.info(
                "SOC email alert sent → %s (%d detections)",
                EMAIL_CONFIG["RECEIVER_EMAIL"],
                len(detections)
            )

        except Exception as exc:
            # 🔇 FAIL-SILENT (SOC UX)
            self.logger.warning(
                "Email alert skipped (non-fatal): %s",
                exc
            )

    # ==================================================
    # FORMATTERS
    # ==================================================

    def _format_batch_body(self, detections: List[dict]) -> str:
        """
        SOC-style structured batch email.
        """
        lines = [
            "SOC SECURITY ALERT",
            "=" * 50,
            f"Total Detections: {len(detections)}",
            ""
        ]

        for i, d in enumerate(detections[:10], start=1):
            lines.extend([
                f"[{i}]",
                f"Time      : {d.get('time', 'N/A')}",
                f"Threat   : {d.get('rule', 'N/A')}",
                f"Severity : {d.get('severity', 'N/A')}",
                f"IP       : {d.get('ip', 'UNKNOWN')}",
                f"IOC Hit  : {'YES' if d.get('ioc_hit') else 'NO'}",
                "-" * 40,
            ])

        if len(detections) > 10:
            lines.append("Additional detections omitted for brevity.")

        lines.extend([
            "",
            "Generated by Log-Based SOC Platform",
            "Automated SOC Alert"
        ])

        return "\n".join(lines)

    def _highest_severity(self, detections: List[dict]) -> str:
        priority = {"Critical": 4, "High": 3, "Medium": 2, "Low": 1}
        return max(
            (d.get("severity", "Low") for d in detections),
            key=lambda s: priority.get(s, 1),
            default="Low"
        )
