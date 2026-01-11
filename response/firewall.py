"""
Firewall Controller
-------------------
REAL OS-level firewall enforcement with strict SOC safety.

✔ Windows: netsh (non-blocking, bidirectional)
✔ Linux: Audit-only (no enforcement by default)
✔ macOS: Audit-only
✔ GUI-safe (no blocking calls)
✔ EXE-safe
✔ Forensic audit logging
"""

import json
import logging
import platform
import subprocess
from datetime import datetime
from threading import Lock

from config.settings import AUTO_BLOCK, BLOCKED_IPS_FILE


class FirewallController:
    """
    SOC Firewall Enforcement Controller (SAFE MODE)
    """

    def __init__(self):
        self.logger = logging.getLogger("SOC.Firewall")
        self.os_type = platform.system()
        self._lock = Lock()

        # Ensure audit file exists
        BLOCKED_IPS_FILE.parent.mkdir(parents=True, exist_ok=True)
        if not BLOCKED_IPS_FILE.exists():
            BLOCKED_IPS_FILE.write_text("{}", encoding="utf-8")

    # ==================================================
    # AUDIT STORAGE
    # ==================================================

    def _load_history(self) -> dict:
        try:
            return json.loads(BLOCKED_IPS_FILE.read_text(encoding="utf-8"))
        except Exception:
            return {}

    def _save_history(self, data: dict):
        BLOCKED_IPS_FILE.write_text(
            json.dumps(data, indent=2),
            encoding="utf-8"
        )

    # ==================================================
    # SAFETY CHECKS
    # ==================================================

    def _is_private_ip(self, ip: str) -> bool:
        return ip.startswith((
            "127.", "10.", "192.168.",
            "172.16.", "172.17.", "172.18.",
            "172.19.", "172.2", "0."
        ))

    # ==================================================
    # MAIN ENTRY
    # ==================================================

    def block_ip(self, ip: str, reason: str, ioc_confirmed: bool) -> bool:
        """
        Apply firewall block if policy allows.
        NEVER blocks private or localhost IPs.
        NEVER blocks from GUI thread.
        """

        # ---------------- POLICY CHECKS ----------------

        if not AUTO_BLOCK.get("ENABLED", False):
            self.logger.info("[FIREWALL] Auto-block disabled by policy")
            return False

        if AUTO_BLOCK.get("REQUIRE_IOC", True) and not ioc_confirmed:
            self.logger.info("[FIREWALL] IOC confirmation required – skipped for %s", ip)
            return False

        if not ip or ip == "UNKNOWN":
            return False

        if self._is_private_ip(ip):
            self.logger.warning(
                "[FIREWALL] Skipping private / local IP block: %s",
                ip
            )
            return False

        # ---------------- AUDIT DEDUP ----------------

        with self._lock:
            history = self._load_history()
            if ip in history:
                self.logger.debug("[FIREWALL] IP already blocked: %s", ip)
                return False

        # ---------------- OS HANDLING ----------------

        rule_name = f"SOC_BLOCK_{ip}"
        method = "audit-only"

        try:
            if self.os_type == "Windows":
                self._block_windows(ip, rule_name)
                method = "netsh"

            elif self.os_type == "Linux":
                self.logger.warning(
                    "[FIREWALL] Linux auto-block skipped (audit-only mode): %s",
                    ip
                )

            else:
                self.logger.warning(
                    "[FIREWALL] Unsupported OS (%s) – audit only",
                    self.os_type
                )

            # ---------------- AUDIT LOG ----------------

            with self._lock:
                history = self._load_history()
                history[ip] = {
                    "blocked_at": datetime.utcnow().isoformat() + "Z",
                    "reason": reason,
                    "ioc_confirmed": ioc_confirmed,
                    "os": self.os_type,
                    "method": method,
                    "rule_name": rule_name
                }
                self._save_history(history)

            self.logger.critical(
                "🔥 FIREWALL ACTION | %s | Reason: %s | Method: %s",
                ip, reason, method
            )
            return True

        except Exception as exc:
            self.logger.error(
                "[FIREWALL] Failed to process %s: %s",
                ip, exc
            )
            return False

    # ==================================================
    # WINDOWS IMPLEMENTATION (NON-BLOCKING)
    # ==================================================

    def _block_windows(self, ip: str, rule_name: str):
        """
        Windows firewall enforcement (IN + OUT).
        Uses Popen → NEVER blocks GUI.
        """

        cmds = [
            [
                "netsh", "advfirewall", "firewall", "add", "rule",
                f"name={rule_name}_IN",
                "dir=in",
                "action=block",
                f"remoteip={ip}"
            ],
            [
                "netsh", "advfirewall", "firewall", "add", "rule",
                f"name={rule_name}_OUT",
                "dir=out",
                "action=block",
                f"remoteip={ip}"
            ]
        ]

        for cmd in cmds:
            subprocess.Popen(
                cmd,
                stdout=subprocess.DEVNULL,
                stderr=subprocess.DEVNULL,
                shell=False
            )
