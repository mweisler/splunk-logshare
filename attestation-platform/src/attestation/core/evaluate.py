"""Pure evaluation logic: combine per-subject fact statuses into a control
state, and decide state transitions with grace-period debounce.

These functions are deliberately DB-free and side-effect-free so the policy is
unit-testable in isolation. The DB-integrated driver lives in
attestation.engine.evaluator.

Design principle: the *connector* decides pass/fail per subject (it knows the
vendor semantics and any thresholds). The engine only aggregates those statuses
and manages transitions -- so adding a connector never touches this logic.
"""

from __future__ import annotations

import datetime as dt
from dataclasses import dataclass

from .models import ControlState, FactStatus

_BAD = {ControlState.DRIFTED, ControlState.DEGRADED, ControlState.STALE}


def aggregate(
    latest_statuses: list[FactStatus], method: str
) -> tuple[ControlState, float | None]:
    """Reduce the latest status of each subject to a control state + coverage.

    method:
      all | ratio | threshold -> every subject must PASS (coverage = pass/total)
      any                     -> at least one subject must PASS
    """
    total = len(latest_statuses)
    if total == 0:
        return ControlState.UNKNOWN, None

    passes = sum(1 for s in latest_statuses if s == FactStatus.PASS)
    fails = sum(1 for s in latest_statuses if s == FactStatus.FAIL)
    soft = total - passes - fails  # degraded / unknown
    coverage = passes / total

    if method == "any":
        if passes > 0:
            return ControlState.COMPLIANT, coverage
        if fails == 0 and soft > 0:
            return ControlState.DEGRADED, coverage
        return ControlState.DRIFTED, coverage

    # all / ratio / threshold: require every subject to pass
    if fails > 0:
        return ControlState.DRIFTED, coverage
    if soft > 0:
        return ControlState.DEGRADED, coverage
    return ControlState.COMPLIANT, coverage


@dataclass
class Decision:
    state: ControlState
    drift_since: dt.datetime | None
    from_state: ControlState
    transitioned: bool


def decide(
    prev_state: ControlState | None,
    prev_drift_since: dt.datetime | None,
    raw_state: ControlState,
    now: dt.datetime,
    grace_minutes: int,
) -> Decision:
    """Apply grace-period debounce to a freshly computed raw state.

    A control that *was compliant* is held compliant until the failing condition
    has persisted for grace_minutes -- this absorbs transient blips (an endpoint
    rebooting, a brief API hiccup) without false drift alarms. A control that was
    never compliant (UNKNOWN) alarms immediately on first failure.
    """
    prev = prev_state or ControlState.UNKNOWN
    grace = dt.timedelta(minutes=grace_minutes)
    drift_since = prev_drift_since

    if raw_state in _BAD:
        if drift_since is None:
            drift_since = now
        if prev == ControlState.COMPLIANT and (now - drift_since) < grace:
            new = ControlState.COMPLIANT  # still inside grace window
        else:
            new = raw_state
    elif raw_state == ControlState.COMPLIANT:
        drift_since = None
        new = ControlState.COMPLIANT
    else:  # UNKNOWN
        drift_since = None
        new = ControlState.UNKNOWN

    return Decision(
        state=new,
        drift_since=drift_since,
        from_state=prev,
        transitioned=(new != prev),
    )
