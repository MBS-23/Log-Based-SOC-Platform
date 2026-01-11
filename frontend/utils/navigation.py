"""
Navigation Controller
---------------------
Centralized navigation manager for SOC GUI.

Responsibilities:
- Register views
- Switch views safely
- Prevent duplicate widget creation
- Maintain clean navigation state
- Trigger view lifecycle hooks

SOC-GRADE • EXE-SAFE • DETERMINISTIC
"""

from PySide6.QtWidgets import QWidget, QStackedWidget
from typing import Dict, Type, Optional
import inspect
import logging


class NavigationManager:
    """
    Central navigation controller using QStackedWidget.

    Design guarantees:
    - One instance per view
    - Safe constructor handling
    - Deterministic navigation
    - Lifecycle awareness
    """

    def __init__(self, container: QStackedWidget):
        self.container = container
        self._views: Dict[str, QWidget] = {}
        self._current_view_name: Optional[str] = None
        self.logger = logging.getLogger("SOC.Navigation")

    # ==================================================
    # VIEW REGISTRATION
    # ==================================================

    def register_view(
        self,
        name: str,
        view_cls: Type[QWidget],
        parent: Optional[QWidget] = None
    ):
        """
        Register a view ONCE and keep it alive.

        The view is instantiated exactly one time.
        """
        if name in self._views:
            self.logger.debug("View already registered: %s", name)
            return

        try:
            # ---------- SAFE CONSTRUCTOR HANDLING ----------
            sig = inspect.signature(view_cls.__init__)
            params = list(sig.parameters.values())[1:]  # drop self

            if params:
                view = view_cls(parent)
            else:
                view = view_cls()

            self._views[name] = view
            self.container.addWidget(view)

            self.logger.info("View registered: %s", name)

        except Exception as exc:
            self.logger.error(
                "Failed to register view '%s': %s",
                name,
                exc,
                exc_info=True
            )

    # ==================================================
    # NAVIGATION
    # ==================================================

    def navigate(self, name: str):
        """
        Switch to a registered view with lifecycle hooks.
        """
        if name not in self._views:
            self.logger.error("Unknown view requested: %s", name)
            return

        # ---------- EXIT HOOK (OLD VIEW) ----------
        if self._current_view_name:
            old_view = self._views.get(self._current_view_name)
            if old_view and hasattr(old_view, "on_leave"):
                try:
                    old_view.on_leave()
                except Exception as exc:
                    self.logger.warning(
                        "on_leave() failed for '%s': %s",
                        self._current_view_name,
                        exc
                    )

        # ---------- ENTER NEW VIEW ----------
        view = self._views[name]
        self.container.setCurrentWidget(view)
        self._current_view_name = name

        # ---------- ENTER HOOK (NEW VIEW) ----------
        if hasattr(view, "on_navigate"):
            try:
                view.on_navigate()
            except Exception as exc:
                self.logger.warning(
                    "on_navigate() failed for '%s': %s",
                    name,
                    exc
                )

        self.logger.debug("Navigated to view: %s", name)

    # ==================================================
    # HELPERS
    # ==================================================

    def current_view(self) -> Optional[str]:
        return self._current_view_name

    def get_view(self, name: str) -> Optional[QWidget]:
        return self._views.get(name)

    def has_view(self, name: str) -> bool:
        return name in self._views
