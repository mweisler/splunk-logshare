"""The connector contract every integration implements.

A connector is a dumb collector: authenticate, discover subjects, poll & yield
normalized ``ControlFact`` objects, and hand back a resume cursor. It declares
which ``control_key`` values it can satisfy via ``capabilities`` so the rest of
the platform stays vendor-agnostic.

Adding connector #10 means implementing this interface and registering it --
nothing in core changes.
"""

from __future__ import annotations

import abc
from collections.abc import Iterator
from dataclasses import dataclass
from typing import Any

from ..core.models import ControlFact, Cursor, FactStatus, Pillar, Subject


class Session(abc.ABC):
    """An authenticated handle to a vendor API. Holds the live session only --
    never the long-lived secret, which stays in the vault."""


@dataclass
class CollectionContext:
    """Identity threaded through a collection run. Its ``fact`` helper stamps the
    org/connector/run ids so connectors don't repeat that boilerplate."""

    insured_org_id: str
    connector_id: str
    connector_type: str
    collector_run_id: str

    def fact(
        self,
        *,
        pillar: Pillar,
        control_key: str,
        subject: Subject,
        observed_value: dict[str, Any],
        status: FactStatus,
        source_event_time: Any = None,
        evidence_ref: str | None = None,
    ) -> ControlFact:
        return ControlFact(
            insured_org_id=self.insured_org_id,
            connector_id=self.connector_id,
            connector_type=self.connector_type,
            pillar=pillar,
            control_key=control_key,
            subject=subject,
            observed_value=observed_value,
            status=status,
            source_event_time=source_event_time,
            evidence_ref=evidence_ref,
            collector_run_id=self.collector_run_id,
        )


class Connector(abc.ABC):
    # Unique key, e.g. 'm365', 'sentinelone'. Matches connectors.connector_type.
    connector_type: str
    # control_keys this connector can produce facts for.
    capabilities: frozenset[str]

    @abc.abstractmethod
    def authenticate(
        self, config: dict[str, Any], secret: dict[str, Any]
    ) -> Session:
        """Exchange non-secret config (tenant id, endpoints, ...) and a vault
        secret (client secret, refresh token, ...) for a live API session."""

    @abc.abstractmethod
    def discover(self, session: Session) -> list[Subject]:
        """Enumerate the subjects this connector reasons about (endpoints,
        users, policies, ...). Used to compute coverage denominators."""

    @abc.abstractmethod
    def collect(
        self, session: Session, cursor: Cursor, ctx: CollectionContext
    ) -> Iterator[ControlFact]:
        """Poll the vendor and yield normalized facts. Resume from ``cursor``."""

    @abc.abstractmethod
    def checkpoint(self) -> Cursor:
        """Return the resume token to persist after a successful run."""
