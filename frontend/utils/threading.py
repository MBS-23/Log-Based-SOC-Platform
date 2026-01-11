"""
Threading Utilities (PySide6)
----------------------------
Centralized background task utilities for SOC GUI.

Responsibilities:
- Run heavy tasks without blocking UI
- Communicate results safely via signals
- Prevent crashes & race conditions

NO UI LOGIC
NO BUSINESS LOGIC
"""

from PySide6.QtCore import QObject, QThread, Signal
from typing import Callable, Any, Optional, List
import logging


# ==================================================
# WORKER SIGNALS
# ==================================================

class WorkerSignals(QObject):
    """
    Signals available from a running worker thread.
    """
    finished = Signal()
    error = Signal(str)
    result = Signal(object)
    progress = Signal(int)


# ==================================================
# GENERIC WORKER
# ==================================================

class Worker(QObject):
    """
    Generic worker object to execute a callable in a background thread.
    """

    def __init__(self, fn: Callable, *args, **kwargs):
        super().__init__()
        self.fn = fn
        self.args = args
        self.kwargs = kwargs
        self.signals = WorkerSignals()

    def run(self):
        """
        Execute the task safely.
        """
        try:
            # Optional progress callback support
            if "progress_callback" in self.fn.__code__.co_varnames:
                self.kwargs["progress_callback"] = self.signals.progress

            result = self.fn(*self.args, **self.kwargs)
            self.signals.result.emit(result)

        except Exception as exc:
            self.signals.error.emit(str(exc))

        finally:
            self.signals.finished.emit()


# ==================================================
# THREAD CONTROLLER
# ==================================================

class ThreadManager:
    """
    SOC-grade thread controller.

    - Prevents premature thread destruction
    - Tracks active threads
    - EXE-safe
    """

    def __init__(self):
        self._threads: List[QThread] = []
        self.logger = logging.getLogger("SOC.Threads")

    def run(
        self,
        fn: Callable,
        *,
        on_result: Optional[Callable] = None,
        on_error: Optional[Callable] = None,
        on_finished: Optional[Callable] = None,
        args: tuple = (),
        kwargs: Optional[dict] = None,
        thread_name: Optional[str] = None,
    ):
        """
        Run a function in a background thread.

        Args:
            fn (Callable): Function to execute
            on_result (Callable): Callback for result
            on_error (Callable): Callback for error
            on_finished (Callable): Callback when finished
        """
        if kwargs is None:
            kwargs = {}

        thread = QThread()
        if thread_name:
            thread.setObjectName(thread_name)

        worker = Worker(fn, *args, **kwargs)
        worker.moveToThread(thread)

        # ---------------- SIGNAL WIRING ----------------

        thread.started.connect(worker.run)
        worker.signals.finished.connect(thread.quit)
        worker.signals.finished.connect(worker.deleteLater)
        thread.finished.connect(thread.deleteLater)

        if on_result:
            worker.signals.result.connect(on_result)

        if on_error:
            worker.signals.error.connect(on_error)

        if on_finished:
            worker.signals.finished.connect(on_finished)

        # Cleanup reference
        thread.finished.connect(lambda: self._cleanup(thread))

        self._threads.append(thread)
        self.logger.debug("Thread started: %s", thread.objectName() or "unnamed")

        thread.start()

    # ==================================================
    # INTERNAL
    # ==================================================

    def _cleanup(self, thread: QThread):
        """
        Remove finished thread safely.
        """
        if thread in self._threads:
            self._threads.remove(thread)
            self.logger.debug(
                "Thread cleaned up: %s",
                thread.objectName() or "unnamed"
            )
