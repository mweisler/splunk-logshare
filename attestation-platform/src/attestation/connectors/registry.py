"""Connector registry. Connectors register themselves with @register; the worker
looks them up by ``connector_type``."""

from __future__ import annotations

from .base import Connector

_REGISTRY: dict[str, type[Connector]] = {}


def register(cls: type[Connector]) -> type[Connector]:
    if not getattr(cls, "connector_type", None):
        raise ValueError(f"{cls.__name__} must define connector_type")
    if cls.connector_type in _REGISTRY:
        raise ValueError(f"duplicate connector_type: {cls.connector_type}")
    _REGISTRY[cls.connector_type] = cls
    return cls


def get(connector_type: str) -> type[Connector]:
    return _REGISTRY[connector_type]


def all_types() -> list[str]:
    return sorted(_REGISTRY)
