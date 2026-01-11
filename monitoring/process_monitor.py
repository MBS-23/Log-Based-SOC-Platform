"""
Process Monitoring Engine
-------------------------
Thread-safe, GUI-agnostic, SOC-grade
"""

import time
import psutil
import logging
from typing import Callable


class ProcessMonitor:
    """
    Host-based process monitor.
    Emits events ONLY — never touches GUI.
    """

    def __init__(
        self,
        callback: Callable[[dict], None],
        poll_interval: float = 1.0,
        memory_threshold_mb: int = 500
    ):
        self.callback = callback
        self.poll_interval = poll_interval
        self.memory_threshold = memory_threshold_mb * 1024 * 1024
        self._running = False
        self._known_pids = set()
        self._memory_alerted = set()
        self.logger = logging.getLogger("SOC.ProcessMonitor")

    # ==================================================
    # CONTROL
    # ==================================================

    def start(self):
        self._running = True
        self.logger.info("Process monitor started")

        try:
            self._known_pids = {p.pid for p in psutil.process_iter()}
        except Exception:
            self._known_pids = set()

        while self._running:
            try:
                current_pids = set()

                for proc in psutil.process_iter(
                    attrs=["pid", "name", "memory_info"]
                ):
                    try:
                        pid = proc.info["pid"]
                        current_pids.add(pid)

                        mem_info = proc.info.get("memory_info")
                        if mem_info:
                            mem = mem_info.rss
                            if (
                                mem > self.memory_threshold
                                and pid not in self._memory_alerted
                            ):
                                self._emit({
                                    "type": "High Memory Usage",
                                    "pid": pid,
                                    "process": proc.info.get("name"),
                                    "memory_mb": round(mem / (1024 * 1024), 1)
                                })
                                self._memory_alerted.add(pid)

                    except (psutil.NoSuchProcess, psutil.AccessDenied, psutil.ZombieProcess):
                        continue

                for pid in current_pids - self._known_pids:
                    try:
                        p = psutil.Process(pid)
                        self._emit({
                            "type": "New Process Started",
                            "pid": pid,
                            "process": p.name()
                        })
                    except (psutil.NoSuchProcess, psutil.AccessDenied):
                        continue

                for pid in self._known_pids - current_pids:
                    self._emit({
                        "type": "Process Terminated",
                        "pid": pid
                    })
                    self._memory_alerted.discard(pid)

                self._known_pids = current_pids
                time.sleep(self.poll_interval)

            except Exception as exc:
                self.logger.error("Process monitor error: %s", exc)
                time.sleep(1)

        self.logger.info("Process monitor stopped")

    def stop(self):
        self._running = False

    # ==================================================
    # INTERNAL
    # ==================================================

    def _emit(self, event: dict):
        """
        Emit event safely.
        GUI must NEVER be here.
        """
        try:
            self.callback(event)
        except Exception as exc:
            self.logger.error("Callback failed: %s", exc)
