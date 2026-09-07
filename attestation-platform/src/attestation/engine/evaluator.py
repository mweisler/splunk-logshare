"""DB-integrated evaluation driver.

For each control it: pulls the latest fact per subject, aggregates to a raw
state, applies staleness + grace-period debounce, then persists the rolled-up
control_states row. On a state transition it records a drift_event and appends a
signed 'state_change' entry to the evidence ledger -- so every change to posture
is itself tamper-evident evidence.

``now`` is injectable so schedules and tests can reason about elapsed time.
"""

from __future__ import annotations

import datetime as dt
import json
from typing import Any

from ..core.evaluate import Decision, aggregate, decide
from ..core.ledger import Signer, append_entry
from ..core.models import ControlState, FactStatus


def _utcnow() -> dt.datetime:
    return dt.datetime.now(dt.timezone.utc)


def _latest_facts(conn: Any, insured: str, control_key: str):
    """Latest status per subject for a control, plus the newest collection time."""
    with conn.cursor() as cur:
        cur.execute(
            """
            SELECT DISTINCT ON (subject->>'id')
                   subject->>'id' AS sid, status, collected_at
            FROM control_facts
            WHERE insured_org_id = %s AND control_key = %s
            ORDER BY subject->>'id', collected_at DESC
            """,
            (insured, control_key),
        )
        rows = cur.fetchall()
    statuses = [FactStatus(r[1]) for r in rows]
    failing = [r[0] for r in rows if r[1] != FactStatus.PASS.value]
    newest = max((r[2] for r in rows), default=None)
    return statuses, failing, newest


def _freshness(conn: Any, insured: str, now: dt.datetime, stale_minutes: int):
    """Liveness of the insured's connectors -- backs logging.feed_liveness."""
    with conn.cursor() as cur:
        cur.execute(
            "SELECT status, last_success_at FROM connectors WHERE insured_org_id = %s",
            (insured,),
        )
        rows = cur.fetchall()
    active = [r for r in rows if r[0] == "active"]
    if not active:
        return ControlState.UNKNOWN, None, []
    cutoff = now - dt.timedelta(minutes=stale_minutes)
    stale = [r for r in active if r[1] is None or r[1] < cutoff]
    coverage = (len(active) - len(stale)) / len(active)
    state = ControlState.DRIFTED if stale else ControlState.COMPLIANT
    return state, coverage, []


def _load_prev(conn: Any, insured: str, control_key: str):
    with conn.cursor() as cur:
        cur.execute(
            "SELECT state, drift_since FROM control_states WHERE insured_org_id = %s AND control_key = %s",
            (insured, control_key),
        )
        row = cur.fetchone()
    if row is None:
        return None, None
    return ControlState(row[0]), row[1]


def evaluate_control(
    conn: Any,
    insured: str,
    cdef: dict[str, Any],
    signer: Signer,
    now: dt.datetime | None = None,
) -> Decision | None:
    """Evaluate one control for one insured. Returns the Decision, or None if
    there's nothing to evaluate yet (no facts for a non-freshness control)."""
    now = now or _utcnow()
    control_key = cdef["control_key"]
    method = cdef["aggregation"]
    grace = cdef["grace_period_minutes"]
    stale_after = cdef["stale_after_minutes"]

    if method == "freshness":
        raw, coverage, failing = _freshness(conn, insured, now, stale_after)
        if raw == ControlState.UNKNOWN:
            return None
    else:
        statuses, failing, newest = _latest_facts(conn, insured, control_key)
        if not statuses:
            return None  # nothing observed yet -> leave absent (reads as 'unknown')
        raw, coverage = aggregate(statuses, method)
        if newest is not None and (now - newest) > dt.timedelta(minutes=stale_after):
            raw = ControlState.STALE  # data too old to trust

    prev_state, prev_drift_since = _load_prev(conn, insured, control_key)
    dec = decide(prev_state, prev_drift_since, raw, now, grace)

    with conn.transaction():
        with conn.cursor() as cur:
            cur.execute(
                """
                INSERT INTO control_states
                    (insured_org_id, control_key, state, coverage_pct,
                     failing_subjects, last_evaluated, drift_since)
                VALUES (%s, %s, %s, %s, %s, %s, %s)
                ON CONFLICT (insured_org_id, control_key) DO UPDATE SET
                    state = EXCLUDED.state,
                    coverage_pct = EXCLUDED.coverage_pct,
                    failing_subjects = EXCLUDED.failing_subjects,
                    last_evaluated = EXCLUDED.last_evaluated,
                    drift_since = EXCLUDED.drift_since
                """,
                (
                    insured,
                    control_key,
                    dec.state.value,
                    coverage,
                    json.dumps(failing),
                    now,
                    dec.drift_since,
                ),
            )

            if dec.transitioned:
                cur.execute(
                    """
                    INSERT INTO drift_events
                        (insured_org_id, control_key, from_state, to_state,
                         severity, root_cause_facts, detected_at)
                    VALUES (%s, %s, %s, %s, %s, %s, %s)
                    """,
                    (
                        insured,
                        control_key,
                        dec.from_state.value,
                        dec.state.value,
                        cdef["severity"],
                        json.dumps(failing),
                        now,
                    ),
                )
                if dec.state == ControlState.COMPLIANT:
                    cur.execute(
                        """
                        UPDATE drift_events SET resolved_at = %s
                        WHERE insured_org_id = %s AND control_key = %s
                          AND resolved_at IS NULL AND detected_at < %s
                        """,
                        (now, insured, control_key, now),
                    )

        if dec.transitioned:
            append_entry(
                conn,
                insured,
                "state_change",
                {
                    "control_key": control_key,
                    "from_state": dec.from_state.value,
                    "to_state": dec.state.value,
                    "coverage_pct": coverage,
                    "failing_subjects": failing,
                    "severity": cdef["severity"],
                    "detected_at": now,
                },
                signer,
            )

    return dec


def evaluate_insured(
    conn: Any, insured: str, signer: Signer, now: dt.datetime | None = None
) -> dict[str, str]:
    """Evaluate every defined control for an insured. Returns control_key -> state
    for those that were evaluated."""
    now = now or _utcnow()
    with conn.cursor() as cur:
        cur.execute(
            """
            SELECT control_key, pillar, aggregation, expression,
                   grace_period_minutes, stale_after_minutes, severity
            FROM control_definitions
            """
        )
        cols = [d[0] for d in cur.description]
        defs = [dict(zip(cols, row)) for row in cur.fetchall()]

    results: dict[str, str] = {}
    for cdef in defs:
        dec = evaluate_control(conn, insured, cdef, signer, now)
        if dec is not None:
            results[cdef["control_key"]] = dec.state.value
    return results
