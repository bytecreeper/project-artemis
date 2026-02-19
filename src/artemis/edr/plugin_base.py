"""EDR plugin base class and loader.

Each plugin is a self-contained module that:
1. Declares what events it produces and consumes
2. Registers itself with the event bus on start
3. Can be enabled/disabled independently
"""

from __future__ import annotations

import abc
import importlib
import logging
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from artemis.core.events import EventBus, EventType

logger = logging.getLogger("artemis.edr")

# Plugin registry — plugins register themselves on import
_registry: dict[str, type[EDRPlugin]] = {}


class EDRPlugin(abc.ABC):
    """Base class for all EDR plugins."""

    name: str = "unnamed"
    description: str = ""
    produces: list[EventType] = []
    consumes: list[EventType] = []

    def __init_subclass__(cls, **kwargs: object) -> None:
        """Auto-register plugins when they're defined."""
        super().__init_subclass__(**kwargs)
        if cls.name != "unnamed":
            _registry[cls.name] = cls
            logger.debug("Registered EDR plugin: %s", cls.name)

    def configure(self, config: dict) -> None:
        """Optional: receive config dict before start. Override if needed."""

    @abc.abstractmethod
    async def start(self, bus: EventBus) -> None:
        """Start the plugin — subscribe to events, begin monitoring."""

    @abc.abstractmethod
    async def stop(self) -> None:
        """Graceful shutdown."""

    @abc.abstractmethod
    async def status(self) -> dict:
        """Return current plugin status for health checks."""


def load_plugins(names: list[str]) -> list[type[EDRPlugin]]:
    """Import and return plugin classes by name.
    
    Plugins live in artemis.edr.plugins.<name> and auto-register
    via __init_subclass__ when imported.
    """
    loaded = []
    for name in names:
        try:
            importlib.import_module(f"artemis.edr.plugins.{name}")
            if name in _registry:
                loaded.append(_registry[name])
                logger.info("Loaded EDR plugin: %s", name)
            else:
                logger.warning("Plugin module '%s' imported but didn't register", name)
        except ImportError:
            logger.error("Failed to import EDR plugin: %s", name, exc_info=True)
    return loaded


def get_registry() -> dict[str, type[EDRPlugin]]:
    """Return the current plugin registry."""
    return _registry.copy()
