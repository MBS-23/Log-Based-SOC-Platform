"""
IP Enrichment Module
-------------------
Enterprise-grade IP intelligence enrichment.

✔ Thread-safe
✔ Cache-safe
✔ Offline-safe
✔ EXE-safe
✔ SOC-compliant
"""

import ipaddress
import json
import time
import logging
import requests
from typing import Dict

from config.settings import FEATURES, IP_ENRICHMENT_CACHE

logger = logging.getLogger("SOC.IPEnrichment")

# -------------------------------
# CONFIGURATION
# -------------------------------

IPINFO_URL = "https://ipinfo.io/{ip}/json"
REQUEST_TIMEOUT = 3
CACHE_TTL_SECONDS = 24 * 60 * 60
MAX_CACHE_ENTRIES = 5000

HEADERS = {
    "User-Agent": "LogSOC-IPEnrichment/1.0"
}

# -------------------------------
# CACHE UTILITIES (ATOMIC)
# -------------------------------

def _load_cache() -> dict:
    if not IP_ENRICHMENT_CACHE.exists():
        return {}

    try:
        with open(IP_ENRICHMENT_CACHE, "r", encoding="utf-8") as f:
            return json.load(f)
    except Exception as exc:
        logger.warning("IP enrichment cache unreadable: %s", exc)
        return {}


def _save_cache(cache: dict):
    IP_ENRICHMENT_CACHE.parent.mkdir(parents=True, exist_ok=True)

    # Cache size guard
    if len(cache) > MAX_CACHE_ENTRIES:
        cache = dict(
            sorted(
                cache.items(),
                key=lambda item: item[1].get("timestamp", 0),
                reverse=True
            )[:MAX_CACHE_ENTRIES]
        )

    tmp_file = IP_ENRICHMENT_CACHE.with_suffix(".tmp")

    try:
        with open(tmp_file, "w", encoding="utf-8") as f:
            json.dump(cache, f, indent=2)

        tmp_file.replace(IP_ENRICHMENT_CACHE)

    except Exception as exc:
        logger.error("Failed to save IP enrichment cache: %s", exc)


# -------------------------------
# HELPERS
# -------------------------------

def is_private_ip(ip: str) -> bool:
    try:
        return ipaddress.ip_address(ip).is_private
    except Exception:
        return False


# -------------------------------
# MAIN ENRICHMENT FUNCTION
# -------------------------------

def enrich_ip(ip: str) -> Dict:
    """
    Enrich an IP address with geo & ASN intelligence.

    NEVER raises exceptions.
    """
    if not FEATURES.get("GEO_IP_LOOKUP", True):
        return {"ip": ip, "disabled": True}

    # Validate IP
    try:
        ip_obj = ipaddress.ip_address(ip)
    except Exception:
        return {
            "ip": ip,
            "is_private": False,
            "error": "Invalid IP address",
            "source": "INVALID"
        }

    result = {
        "ip": ip,
        "is_private": ip_obj.is_private,
        "country": "UNKNOWN",
        "region": "UNKNOWN",
        "city": "UNKNOWN",
        "org": "UNKNOWN",
        "asn": "UNKNOWN",
        "source": "NONE",
        "error": None,
    }

    # Private IPs never go external
    if ip_obj.is_private:
        result.update({
            "source": "LOCAL",
            "org": "Private / Internal Network"
        })
        return result

    # ---- Cache Check ----
    cache = _load_cache()
    cached = cache.get(ip)

    if cached:
        age = time.time() - cached.get("timestamp", 0)
        if age < CACHE_TTL_SECONDS:
            data = dict(cached.get("data", {}))
            data["source"] = "CACHE"
            return data

    # ---- External Lookup ----
    try:
        response = requests.get(
            IPINFO_URL.format(ip=ip),
            timeout=REQUEST_TIMEOUT,
            headers=HEADERS
        )

        if response.status_code != 200:
            raise RuntimeError(f"HTTP {response.status_code}")

        data = response.json()

        asn_value = data.get("asn", "UNKNOWN")
        if isinstance(asn_value, dict):
            asn_value = asn_value.get("asn", "UNKNOWN")

        result.update({
            "country": data.get("country", "UNKNOWN"),
            "region": data.get("region", "UNKNOWN"),
            "city": data.get("city", "UNKNOWN"),
            "org": data.get("org", "UNKNOWN"),
            "asn": asn_value,
            "source": "ipinfo.io",
        })

        cache[ip] = {
            "timestamp": time.time(),
            "data": result
        }
        _save_cache(cache)

    except Exception as exc:
        logger.debug("IP enrichment failed for %s: %s", ip, exc)
        result["error"] = str(exc)

    return result
