"""Reference connector. Implements the full contract against fake data so the
Phase 0 pipeline (collect -> ingest -> ledger -> verify) can run end-to-end with
no external dependency. Real connectors (m365, sentinelone, ...) follow this
exact shape.
"""

from __future__ import annotations

from collections.abc import Iterator
from typing import Any

from ..core.models import ControlFact, Cursor, FactStatus, Pillar, Subject
from .base import CollectionContext, Connector, Session
from .registry import register


class _NoopSession(Session):
    pass


@register
class NoopConnector(Connector):
    connector_type = "noop"
    capabilities = frozenset({"identity.mfa_enforced"})

    def __init__(self) -> None:
        self._cursor = Cursor()

    def authenticate(
        self, config: dict[str, Any], secret: dict[str, Any]
    ) -> Session:
        return _NoopSession()

    def discover(self, session: Session) -> list[Subject]:
        return [
            Subject("user", "u1", "alice@example.com"),
            Subject("user", "u2", "bob@example.com"),
        ]

    def collect(
        self, session: Session, cursor: Cursor, ctx: CollectionContext
    ) -> Iterator[ControlFact]:
        for subject in self.discover(session):
            yield ctx.fact(
                pillar=Pillar.IDENTITY,
                control_key="identity.mfa_enforced",
                subject=subject,
                observed_value={"mfa_enforced": True, "method": "totp"},
                status=FactStatus.PASS,
            )
        self._cursor = Cursor({"last_page": 1})

    def checkpoint(self) -> Cursor:
        return self._cursor
