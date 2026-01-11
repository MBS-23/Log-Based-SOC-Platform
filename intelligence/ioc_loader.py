"""
IOC Loader & Reputation Engine
------------------------------
SOC-grade, offline-first IOC engine.

✔ Stable feeds
✔ Cache-first
✔ No network calls during detection
✔ EXE-safe
"""

import json
import time
import logging
from pathlib import Path
from typing import Set, Optional

import requests

from config.settings import IOC_CACHE_FILE

logger = logging.getLogger("SOC.IOC")

# ==================================================
# CONFIG
# ==================================================

IOC_FEEDS = {
    # Stable community feed
    "firehol_level1": (
        "https://raw.githubusercontent.com/firehol/blocklist-ipsets/"
        "master/firehol_level1.netset"
    )
}

CACHE_TTL_SECONDS = 24 * 60 * 60  # 24 hours
REQUEST_TIMEOUT = 6
USER_AGENT = "LogSOC-IOC-Engine/1.0"


# ==================================================
# ENGINE
# ==================================================

class IOCEngine:
    def __init__(self):
        self.iocs: Set[str] = set()
        self.last_updated: float = 0.0

        self._load_from_cache()

        # Initial population only once
        if not self.iocs:
            self._safe_update_once()

    # -------------------------------------------------
    # PUBLIC API (DETECTION SAFE)
    # -------------------------------------------------

    def is_malicious(self, ip: str) -> bool:
        if not ip or ip == "UNKNOWN":
            return False
        return ip in self.iocs

    # -------------------------------------------------
    # UPDATE (MANUAL / SCHEDULED ONLY)
    # -------------------------------------------------

    def _safe_update_once(self):
        try:
            self.update_iocs()
        except Exception as exc:
            logger.warning("IOC update skipped: %s", exc)

    def update_iocs(self):
        now = time.time()

        # Hard throttle (never spam feeds)
        if now - self.last_updated < 3600:
            return

        logger.info("Updating IOC feeds...")
        collected = set()
        headers = {"User-Agent": USER_AGENT}

        for name, url in IOC_FEEDS.items():
            try:
                resp = requests.get(url, timeout=REQUEST_TIMEOUT, headers=headers)
                resp.raise_for_status()

                for line in resp.text.splitlines():
                    line = line.strip()
                    if line and not line.startswith("#"):
                        collected.add(line)

                logger.info("IOC feed loaded: %s (%d IPs)", name, len(collected))

            except Exception as exc:
                logger.warning("IOC feed failed (%s): %s", name, exc)

        if collected:
            self.iocs = collected
            self.last_updated = now
            self._save_cache()
        else:
            logger.warning(
                "No IOC data loaded — continuing with cached data (%d entries)",
                len(self.iocs)
            )

    # -------------------------------------------------
    # CACHE
    # -------------------------------------------------

    def _load_from_cache(self):
        if not IOC_CACHE_FILE.exists():
            return

        try:
            data = json.loads(IOC_CACHE_FILE.read_text(encoding="utf-8"))
            self.iocs = set(data.get("iocs", []))
            self.last_updated = float(data.get("last_updated", 0))
            logger.info("IOC cache loaded (%d entries)", len(self.iocs))
        except Exception as exc:
            logger.warning("IOC cache invalid: %s", exc)
            self.iocs = set()
            self.last_updated = 0

    def _save_cache(self):
        IOC_CACHE_FILE.parent.mkdir(parents=True, exist_ok=True)
        tmp = IOC_CACHE_FILE.with_suffix(".tmp")

        tmp.write_text(
            json.dumps(
                {
                    "iocs": list(self.iocs),
                    "last_updated": self.last_updated
                },
                indent=2
            ),
            encoding="utf-8"
        )

        tmp.replace(IOC_CACHE_FILE)
        logger.info("IOC cache saved (%d entries)", len(self.iocs))


# ==================================================
# SINGLETON
# ==================================================

_ioc_engine: Optional[IOCEngine] = None


def get_ioc_engine() -> IOCEngine:
    global _ioc_engine
    if _ioc_engine is None:
        _ioc_engine = IOCEngine()
    return _ioc_engine
