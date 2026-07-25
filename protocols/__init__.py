"""Protocol backend registry and auto-discovery."""

from __future__ import annotations

import importlib
import pkgutil

from .base import ProtocolBackend


_BACKENDS: dict[str, type[ProtocolBackend]] = {}
_DISCOVERED = False


def register_protocol(protocol_name: str):
    """Register a backend class under a protocol name."""

    def decorator(cls: type[ProtocolBackend]) -> type[ProtocolBackend]:
        _BACKENDS[protocol_name] = cls
        cls.protocol_name = protocol_name
        return cls

    return decorator


def discover_protocol_backends() -> dict[str, type[ProtocolBackend]]:
    global _DISCOVERED
    if not _DISCOVERED:
        for module in pkgutil.iter_modules(__path__):
            if module.name.startswith("_") or module.name == "base":
                continue
            importlib.import_module(f"{__name__}.{module.name}")
        _DISCOVERED = True
    return dict(_BACKENDS)
