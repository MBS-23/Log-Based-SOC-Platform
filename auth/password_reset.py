"""
Password Reset Manager
----------------------
Handles secure password reset flow.

✔ Token-based reset with expiry
✔ Email-based reset (non-blocking)
✔ Secure password update
✔ SOC-safe logging
✔ EXE-safe
"""

import logging
import smtplib
import threading
import time
import re
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart

from auth.user_store import (
    get_user_by_username,
    get_user_by_email,
    create_reset_token,
    validate_reset_token,
    update_password
)

from config.settings import EMAIL_CONFIG

logger = logging.getLogger("SOC.PasswordReset")

# -------------------------------------------------
# BASIC RATE LIMIT (IN-MEMORY, SOC-SAFE)
# -------------------------------------------------
_RESET_REQUEST_CACHE = {}
_RESET_WINDOW_SECONDS = 300   # 5 minutes
_RESET_MAX_ATTEMPTS = 3


class PasswordResetService:
    """
    Handles password reset workflow.
    """

    # ================= REQUEST RESET =================

    def request_password_reset(self, identifier: str) -> dict:
        if not identifier:
            return {"success": False, "error": "Username or email is required"}

        identifier = identifier.strip().lower()

        # ---- Rate limiting (soft protection) ----
        now = time.time()
        attempts, last_time = _RESET_REQUEST_CACHE.get(identifier, (0, 0))

        if now - last_time < _RESET_WINDOW_SECONDS and attempts >= _RESET_MAX_ATTEMPTS:
            logger.warning("Password reset rate-limited for identifier: %s", identifier)
            return {
                "success": False,
                "error": "Too many reset attempts. Please try again later."
            }

        _RESET_REQUEST_CACHE[identifier] = (
            attempts + 1 if now - last_time < _RESET_WINDOW_SECONDS else 1,
            now
        )

        # ---- Identify user ----
        user = (
            get_user_by_email(identifier)
            if "@" in identifier
            else get_user_by_username(identifier)
        )

        # IMPORTANT: Do NOT reveal whether user exists
        if not user:
            logger.info("Password reset requested for unknown identifier")
            return {
                "success": True,
                "message": "If the account exists, a reset email has been sent"
            }

        username, email, _, _ = user

        # ---- Generate token ----
        token = create_reset_token(username)

        # ---- Send email asynchronously ----
        threading.Thread(
            target=self._send_reset_email_safe,
            args=(email, username, token),
            daemon=True
        ).start()

        logger.info("Password reset flow triggered for user: %s", username)

        return {
            "success": True,
            "message": "If the account exists, a reset email has been sent"
        }

    # ================= APPLY RESET =================

    def reset_password(self, username: str, token: str, new_password: str) -> dict:
        if not username or not token or not new_password:
            return {"success": False, "error": "All fields are required"}

        # ---- Password strength enforcement ----
        if not self._is_password_strong(new_password):
            return {
                "success": False,
                "error": (
                    "Password must be at least 8 characters long and include "
                    "uppercase, lowercase, number, and special character"
                )
            }

        if not validate_reset_token(username, token):
            logger.warning("Invalid or expired reset token for user: %s", username)
            return {"success": False, "error": "Invalid or expired reset token"}

        update_password(username, new_password)

        logger.info("Password successfully reset for user: %s", username)

        return {"success": True, "message": "Password updated successfully"}

    # ================= EMAIL =================

    def _send_reset_email_safe(self, email: str, username: str, token: str):
        """
        Wrapper to prevent thread crashes.
        """
        try:
            self._send_reset_email(email, username, token)
        except Exception as exc:
            logger.error("Password reset email failed: %s", exc)

    def _send_reset_email(self, email: str, username: str, token: str):
        """
        Send password reset email via SMTP.
        """

        for key in ("SMTP_SERVER", "SMTP_PORT", "SENDER_EMAIL", "SENDER_PASSWORD"):
            if not EMAIL_CONFIG.get(key):
                raise RuntimeError(f"EMAIL_CONFIG missing required key: {key}")

        reset_message = f"""
Hello {username},

A password reset request was initiated for your Log SOC Platform account.

🔐 Reset Token:
{token}

⏰ This token is valid for 15 minutes only.

If you did NOT request this reset, please ignore this email.

— Log SOC Platform Security Team
""".strip()

        msg = MIMEMultipart()
        msg["From"] = EMAIL_CONFIG["SENDER_EMAIL"]
        msg["To"] = email
        msg["Subject"] = "🔐 Log SOC Platform – Password Reset"
        msg.attach(MIMEText(reset_message, "plain"))

        server = None
        try:
            server = smtplib.SMTP(
                EMAIL_CONFIG["SMTP_SERVER"],
                EMAIL_CONFIG["SMTP_PORT"],
                timeout=15
            )
            server.ehlo()

            if EMAIL_CONFIG.get("USE_TLS", True):
                server.starttls()
                server.ehlo()

            server.login(
                EMAIL_CONFIG["SENDER_EMAIL"],
                EMAIL_CONFIG["SENDER_PASSWORD"]
            )

            server.send_message(msg)
            logger.info("Password reset email delivered to %s", email)

        finally:
            try:
                if server:
                    server.quit()
            except Exception:
                pass

    # ================= PASSWORD POLICY =================

    def _is_password_strong(self, password: str) -> bool:
        """
        Enforce SOC-grade password policy.
        """
        if len(password) < 8:
            return False

        patterns = [
            r"[A-Z]",      # uppercase
            r"[a-z]",      # lowercase
            r"\d",         # digit
            r"[^\w\s]"     # special char
        ]

        return all(re.search(p, password) for p in patterns)
