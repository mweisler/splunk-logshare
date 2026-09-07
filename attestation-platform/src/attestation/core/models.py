"""Normalized domain model shared by connectors, the evaluation engine, and the
ledger. These mirror the SQL types in migrations/0003_control_model.sql.

The key idea: connectors emit ``ControlFact`` and nothing else. Every vendor,
no matter how different its API, normalizes down to this one record so that
everything downstream (evaluation, drift, evidence) is vendor-agnostic.
"""

from __future__ import annotations

import datetime as dt
import enum
import uuid
from dataclasses import dataclass, field
from typing import Any


class Pillar(str, enum.Enum):
    EDR = "edr"
    IDENTITY = "identity"
    EMAIL = "email"
    LOGGING = "logging"
    BACKUP = "backup"


class FactStatus(str, enum.Enum):
    PASS = "pass"
    FAIL = "fail"
    DEGRADED = "degraded"
    UNKNOWN = "unknown"


class ControlState(str, enum.Enum):
    """Rolled-up posture for one (insured, control). Mirrors the SQL
    control_state_kind enum in migrations/0003_control_model.sql."""

    COMPLIANT = "compliant"
    DRIFTED = "drifted"
    DEGRADED = "degraded"
    UNKNOWN = "unknown"
    STALE = "stale"


def _utcnow() -> dt.datetime:
    return dt.datetime.now(dt.timezone.utc)


@dataclass(frozen=True)
class Subject:
    """What a fact is about: an endpoint, user, policy, index, backup job, ..."""

    type: str
    id: str
    label: str | None = None

    def to_dict(self) -> dict[str, Any]:
        return {"type": self.type, "id": self.id, "label": self.label}


@dataclass(frozen=True)
class ControlFact:
    """One normalized observation tied to a single control and subject."""

    insured_org_id: str
    connector_id: str
    connector_type: str
    pillar: Pillar
    control_key: str
    subject: Subject
    observed_value: dict[str, Any]
    status: FactStatus
    collector_run_id: str
    source_event_time: dt.datetime | None = None
    collected_at: dt.datetime = field(default_factory=_utcnow)
    evidence_ref: str | None = None
    fact_id: str = field(default_factory=lambda: str(uuid.uuid4()))

    def to_dict(self) -> dict[str, Any]:
        return {
            "fact_id": self.fact_id,
            "insured_org_id": self.insured_org_id,
            "connector_id": self.connector_id,
            "connector_type": self.connector_type,
            "pillar": self.pillar.value,
            "control_key": self.control_key,
            "subject": self.subject.to_dict(),
            "observed_value": self.observed_value,
            "status": self.status.value,
            "source_event_time": self.source_event_time,
            "collected_at": self.collected_at,
            "evidence_ref": self.evidence_ref,
            "collector_run_id": self.collector_run_id,
        }


@dataclass
class Cursor:
    """Opaque resume token persisted on the connector row between runs.

    Same role as ``last_ray_id`` in the Splunk Cloudflare modular input: it lets
    the next poll pick up where the last one stopped.
    """

    data: dict[str, Any] = field(default_factory=dict)
