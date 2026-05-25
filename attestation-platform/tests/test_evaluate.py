"""Unit tests for the pure evaluation logic (aggregation + grace debounce).
No database or crypto required."""

from __future__ import annotations

import datetime as dt

from attestation.core.evaluate import aggregate, decide
from attestation.core.models import ControlState, FactStatus

P, F, D, U = (
    FactStatus.PASS,
    FactStatus.FAIL,
    FactStatus.DEGRADED,
    FactStatus.UNKNOWN,
)
NOW = dt.datetime(2026, 5, 25, 12, 0, tzinfo=dt.timezone.utc)


# --- aggregate ------------------------------------------------------------
def test_aggregate_empty_is_unknown():
    assert aggregate([], "all") == (ControlState.UNKNOWN, None)


def test_aggregate_all_pass_is_compliant():
    assert aggregate([P, P, P], "all") == (ControlState.COMPLIANT, 1.0)


def test_aggregate_any_fail_drifts_for_all_method():
    state, cov = aggregate([P, P, F], "ratio")
    assert state == ControlState.DRIFTED
    assert round(cov, 4) == round(2 / 3, 4)


def test_aggregate_soft_only_is_degraded():
    assert aggregate([P, D], "all")[0] == ControlState.DEGRADED


def test_aggregate_any_method_needs_one_pass():
    assert aggregate([F, F, P], "any")[0] == ControlState.COMPLIANT
    assert aggregate([F, F], "any")[0] == ControlState.DRIFTED
    assert aggregate([D, U], "any")[0] == ControlState.DEGRADED


# --- decide (grace debounce) ----------------------------------------------
def test_first_observation_compliant_transitions_from_unknown():
    d = decide(None, None, ControlState.COMPLIANT, NOW, grace_minutes=60)
    assert d.state == ControlState.COMPLIANT
    assert d.from_state == ControlState.UNKNOWN
    assert d.transitioned is True


def test_compliant_to_bad_is_held_during_grace():
    d = decide(ControlState.COMPLIANT, None, ControlState.DRIFTED, NOW, grace_minutes=60)
    assert d.state == ControlState.COMPLIANT  # held
    assert d.drift_since == NOW
    assert d.transitioned is False


def test_drift_fires_after_grace_elapses():
    started = NOW - dt.timedelta(minutes=61)
    d = decide(ControlState.COMPLIANT, started, ControlState.DRIFTED, NOW, grace_minutes=60)
    assert d.state == ControlState.DRIFTED
    assert d.transitioned is True


def test_unknown_to_bad_alarms_immediately():
    d = decide(ControlState.UNKNOWN, None, ControlState.DRIFTED, NOW, grace_minutes=60)
    assert d.state == ControlState.DRIFTED
    assert d.transitioned is True


def test_recovery_clears_drift_since():
    started = NOW - dt.timedelta(hours=2)
    d = decide(ControlState.DRIFTED, started, ControlState.COMPLIANT, NOW, grace_minutes=60)
    assert d.state == ControlState.COMPLIANT
    assert d.drift_since is None
    assert d.transitioned is True


def test_stale_is_treated_as_bad():
    d = decide(ControlState.COMPLIANT, NOW - dt.timedelta(days=1), ControlState.STALE, NOW, grace_minutes=0)
    assert d.state == ControlState.STALE
    assert d.transitioned is True
