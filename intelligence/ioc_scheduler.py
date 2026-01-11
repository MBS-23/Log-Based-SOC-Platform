"""
IOC Update Scheduler
--------------------
Background thread to periodically refresh IOC feeds.

• Non-blocking
• EXE-safe
• SOC-grade (silent & resilient)
"""

import threading
import time
import logging

from intelligence.ioc_loader import get_ioc_engine
from config.settings import SCHEDULER

logger = logging.getLogger("SOC.IOC.Scheduler")

# Prevent duplicate scheduler threads
_scheduler_started = False
_lock = threading.Lock()


def start_ioc_scheduler():
    """
    Start background IOC refresh scheduler.
    Safe to call multiple times.
    """

    global _scheduler_started

    with _lock:
        if _scheduler_started:
            logger.debug("IOC scheduler already running")
            return
        _scheduler_started = True

    interval_hours = SCHEDULER.get("IOC_REFRESH_HOURS", 0)

    # Disabled if interval invalid
    if not isinstance(interval_hours, (int, float)) or interval_hours <= 0:
        logger.info("IOC scheduler disabled by configuration")
        return

    def _scheduler_loop():
        engine = get_ioc_engine()

        logger.info(
            "IOC scheduler started (interval=%s hours)",
            interval_hours
        )

        while True:
            try:
                engine.update_iocs()
            except Exception as exc:
                logger.warning(
                    "IOC scheduled update failed: %s",
                    exc
                )

            # Sleep safely (convert hours → seconds)
            time.sleep(interval_hours * 3600)

    thread = threading.Thread(
        target=_scheduler_loop,
        name="IOC-Scheduler",
        daemon=True
    )
    thread.start()
