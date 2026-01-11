"""
Log Normalizer Module
--------------------
Decodes, cleans, and stabilizes log payloads for detection.

SOC-safe
EXE-safe
Detection-agnostic
"""

import html
import urllib.parse
from typing import Dict


# =================================================
# CONSTANTS
# =================================================

MAX_LEN = 2000
HALF_LEN = MAX_LEN // 2


# =================================================
# UTILITIES
# =================================================

def _strip_control_chars(text: str) -> str:
    """
    Remove non-printable control characters
    (PDF / regex / UI safety).
    """
    return "".join(ch for ch in text if ch.isprintable())


def recursive_decode(text: str, max_depth: int = 3) -> str:
    """
    Recursively decode URL-encoded and HTML-encoded text.

    Example:
        %2527 → %27 → '
    """
    if not isinstance(text, str) or not text:
        return ""

    current = text

    for _ in range(max_depth):
        try:
            decoded = urllib.parse.unquote_plus(current)
            decoded = html.unescape(decoded)

            if decoded == current:
                break

            current = decoded

        except Exception:
            break

    return current


# =================================================
# MAIN NORMALIZER
# =================================================

def normalize_log_entry(entry: Dict[str, str]) -> Dict[str, str]:
    """
    Normalize a parsed log entry for detection.

    Returns a NEW dictionary containing:
    - normalized_request
    - normalized_raw
    """
    if not isinstance(entry, dict):
        return {}

    normalized = dict(entry)

    request = entry.get("request", "") or ""
    raw = entry.get("raw", "") or ""

    # -------------------------------
    # 1️⃣ Recursive decoding
    # -------------------------------
    decoded_request = recursive_decode(request)
    decoded_raw = recursive_decode(raw)

    # -------------------------------
    # 2️⃣ Strip control characters
    # -------------------------------
    decoded_request = _strip_control_chars(decoded_request)
    decoded_raw = _strip_control_chars(decoded_raw)

    # -------------------------------
    # 3️⃣ Normalize case
    # -------------------------------
    decoded_request = decoded_request.lower()
    decoded_raw = decoded_raw.lower()

    # -------------------------------
    # 4️⃣ Length guard (memory safe)
    # -------------------------------
    if len(decoded_request) > MAX_LEN:
        decoded_request = (
            decoded_request[:HALF_LEN] + "..." + decoded_request[-HALF_LEN:]
        )

    if len(decoded_raw) > MAX_LEN:
        decoded_raw = (
            decoded_raw[:HALF_LEN] + "..." + decoded_raw[-HALF_LEN:]
        )

    # -------------------------------
    # FINAL ASSIGNMENT
    # -------------------------------
    normalized["normalized_request"] = decoded_request
    normalized["normalized_raw"] = decoded_raw

    return normalized
