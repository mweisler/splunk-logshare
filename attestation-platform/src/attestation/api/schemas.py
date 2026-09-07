"""Response models for the portal API.

Every endpoint returns one of these -- so the OpenAPI schema at /openapi.json
is a complete, typed contract the portal team can codegen a client from
(openapi-typescript, orval, etc.). If a shape needs to change, change it here
and the docs, the client, and the tests all update in lockstep.
"""

from __future__ import annotations

import datetime as dt
from typing import Any, Literal

from pydantic import BaseModel, Field


# --- identity -------------------------------------------------------------
class Membership(BaseModel):
    org_id: str
    org_name: str
    org_type: str
    role: str


class Me(BaseModel):
    id: str
    email: str
    display_name: str | None = None
    is_platform_super: bool = False
    memberships: list[Membership] = []


# --- org tree -------------------------------------------------------------
class Insured(BaseModel):
    id: str
    name: str
    parent_id: str | None = None
    parent_name: str | None = None


# --- posture --------------------------------------------------------------
class PillarRollup(BaseModel):
    pillar: str
    compliant: int = 0
    drifted: int = 0
    degraded: int = 0
    unknown: int = 0
    stale: int = 0


class Posture(BaseModel):
    insured_id: str
    as_of: dt.datetime
    overall_state: Literal["compliant", "degraded", "drifted", "unknown"]
    by_pillar: list[PillarRollup]
    open_drift_events: int
    controls_evaluated: int


class ControlRow(BaseModel):
    control_key: str
    title: str
    pillar: str
    severity: str
    state: str
    coverage_pct: float | None = None
    failing_subjects: list[Any] = []
    last_evaluated: dt.datetime | None = None
    drift_since: dt.datetime | None = None


class DriftEvent(BaseModel):
    id: str
    control_key: str
    from_state: str
    to_state: str
    severity: str
    detected_at: dt.datetime
    resolved_at: dt.datetime | None = None
    root_cause_facts: list[Any] = []


# --- questionnaires -------------------------------------------------------
class Questionnaire(BaseModel):
    id: str
    key: str
    name: str
    version: str
    origin: Literal["builtin", "custom"]
    is_baseline: bool = False
    item_count: int = 0


class Answer(BaseModel):
    item_key: str
    category: str
    prompt: str
    required: bool
    control_key: str | None = None
    state: str | None = None
    coverage_pct: float | None = None
    answer: Literal["yes", "no", "unknown", "manual"]


class AnswerSheet(BaseModel):
    insured_id: str
    questionnaire_key: str
    answers: list[Answer]


# --- connectors -----------------------------------------------------------
class Connector(BaseModel):
    id: str
    connector_type: str
    display_name: str
    status: str
    last_run_at: dt.datetime | None = None
    last_success_at: dt.datetime | None = None
