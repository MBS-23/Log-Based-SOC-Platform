"""
Auth Manager
------------
High-level authentication controller for Log SOC Platform.

✔ User registration validation
✔ Login authentication
✔ SOC-grade password policy
✔ Enumeration-safe responses
✔ EXE-safe, deterministic

NO GUI
NO SMTP
NO DB LOGIC
"""

import re
import logging
from typing import Dict

from auth import user_store

logger = logging.getLogger("SOC.Auth")


class AuthManager:
    """
    SOC Authentication Controller
    """

    # =================================================
    # REGISTRATION FLOW
    # =================================================

    def is_registration_required(self) -> bool:
        """
        True if no users exist (first-time setup).
        """
        try:
            return not user_store.user_exists()
        except Exception as exc:
            logger.error("User existence check failed: %s", exc)
            # Fail-safe: allow registration
            return True

    def register_user(self, username: str, email: str, password: str) -> Dict:
        """
        Register a new SOC user.
        """
        if not username or not email or not password:
            return {"success": False, "error": "All fields are required"}

        username = username.strip()
        email = email.strip().lower()

        if not self._is_password_strong(password):
            return {
                "success": False,
                "error": (
                    "Password must be at least 8 characters long and include:\n"
                    "• Uppercase letter\n"
                    "• Lowercase letter\n"
                    "• Number\n"
                    "• Symbol"
                )
            }

        try:
            user_store.create_user(username, email, password)
            logger.info("New user registered: %s", username)
            return {"success": True}

        except Exception as exc:
            # ⚠ Prevent user enumeration
            logger.warning("User registration failed: %s", exc)
            return {
                "success": False,
                "error": "Registration failed. Please try a different username or email."
            }

    # =================================================
    # LOGIN FLOW
    # =================================================

    def authenticate(self, identifier: str, password: str) -> Dict:
        """
        Authenticate user using username OR email.
        """
        if not identifier or not password:
            return {"success": False, "error": "Missing credentials"}

        identifier = identifier.strip()
        identifier_lookup = identifier.lower() if "@" in identifier else identifier

        try:
            valid = user_store.verify_credentials(identifier_lookup, password)
        except Exception as exc:
            logger.error("Credential verification failed: %s", exc)
            return {
                "success": False,
                "error": "Authentication service unavailable"
            }

        if not valid:
            return {
                "success": False,
                "error": "Invalid username/email or password"
            }

        try:
            if "@" in identifier_lookup:
                user = user_store.get_user_by_email(identifier_lookup)
            else:
                user = user_store.get_user_by_username(identifier_lookup)

            return {
                "success": True,
                "user": {
                    "username": user[0],
                    "email": user[1],
                }
            }

        except Exception as exc:
            logger.error("User fetch failed after authentication: %s", exc)
            return {
                "success": False,
                "error": "Authentication failed"
            }

    # =================================================
    # PASSWORD POLICY (SOC STANDARD)
    # =================================================

    def _is_password_strong(self, password: str) -> bool:
        """
        SOC password policy:
        - ≥ 8 characters
        - Uppercase
        - Lowercase
        - Digit
        - Symbol
        """
        if len(password) < 8:
            return False

        checks = [
            r"[A-Z]",        # Uppercase
            r"[a-z]",        # Lowercase
            r"\d",           # Digit
            r"[^\w\s]"       # Symbol
        ]

        return all(re.search(p, password) for p in checks)
