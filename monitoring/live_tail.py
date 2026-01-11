"""
Live Log Tailing Engine
----------------------
Monitors a log file in real-time and emits new log lines
for downstream processing.

SOC-safe
EXE-safe
Rotation-aware
Immediate shutdown
"""

import time
import logging
import os
from typing import Callable


class LiveLogTailer:
    """
    Real-time log file tailer.
    """

    def __init__(
        self,
        file_path: str,
        callback: Callable[[str], None],
        poll_interval: float = 0.5
    ):
        self.file_path = file_path
        self.callback = callback
        self.poll_interval = poll_interval
        self._running = False
        self.logger = logging.getLogger("SOC.LiveTailer")

        self._file = None
        self._last_inode = None
        self._last_size = 0

    # ==================================================
    # CONTROL
    # ==================================================

    def start(self):
        """
        Start tailing the log file.
        """
        self._running = True
        self.logger.info("Started live log tailing: %s", self.file_path)

        while self._running:
            try:
                self._open_if_needed()

                line = self._file.readline()
                if line:
                    try:
                        self.callback(line.rstrip("\n"))
                    except Exception as exc:
                        self.logger.error("Callback failed: %s", exc)
                else:
                    time.sleep(self.poll_interval)

            except FileNotFoundError:
                self.logger.warning(
                    "Log file not found, waiting: %s",
                    self.file_path
                )
                self._close_file()
                time.sleep(1)

            except Exception as exc:
                self.logger.error("Live tailer error: %s", exc)
                self._close_file()
                time.sleep(1)

        self._close_file()
        self.logger.info("Stopped live log tailing")

    def stop(self):
        """
        Stop tailing the log file (immediate).
        """
        self._running = False

    # ==================================================
    # INTERNAL
    # ==================================================

    def _open_if_needed(self):
        """
        Open file or reopen if rotated.
        """
        stat = os.stat(self.file_path)
        inode = (stat.st_ino, stat.st_size)

        # File opened first time or rotated
        if self._file is None or inode != self._last_inode:
            self._close_file()
            self._file = open(
                self.file_path,
                "r",
                encoding="utf-8",
                errors="ignore"
            )
            self._file.seek(0, os.SEEK_END)
            self._last_inode = inode
            self._last_size = stat.st_size

    def _close_file(self):
        """
        Safely close file handle.
        """
        if self._file:
            try:
                self._file.close()
            except Exception:
                pass
            self._file = None
            self._last_inode = None
            self._last_size = 0
