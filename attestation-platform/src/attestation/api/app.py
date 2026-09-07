"""Client-portal HTTP API.

Nine JSON endpoints, one FastAPI app. Every request:
  1. reads ``Authorization: Bearer <users.id>``
  2. opens a psycopg connection
  3. binds ``app.current_user_id`` on that connection so RLS filters everything
  4. runs the route
  5. closes the connection

Because RLS runs at the database, the API can be small: routes just query
what they want, and the DB won't hand back another tenant's rows. The
portal never has to remember to filter -- forgetting is impossible.

Serve:            uvicorn attestation.api.app:app --reload
Interactive docs: http://localhost:8000/docs
OpenAPI schema:   http://localhost:8000/openapi.json  (feed to your codegen)

v1 auth is a Bearer token whose value IS the users.id UUID -- deliberately
trivial for the portal team's first integration. Swap ``current_user_id``
for a JWT/cookie resolver in production; nothing else changes.
"""

from __future__ import annotations

import datetime as dt
import uuid
from collections.abc import Iterator
from typing import Any

from fastapi import Depends, FastAPI, Header, HTTPException, Query
from fastapi.middleware.cors import CORSMiddleware

from ..core.ledger import HmacSigner, Signer
from ..db import connect
from ..packet import build_packet
from . import schemas as S

app = FastAPI(
    title="Attestation Platform API",
    version="0.1",
    description=(
        "Posture, questionnaire answers, and signed attestation packets for "
        "the client portal. All access is scoped by Row-Level Security in the "
        "database, keyed off the Bearer token's user id."
    ),
)
# Portal runs on a different origin; tighten this list in production.
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_methods=["*"],
    allow_headers=["*"],
    allow_credentials=False,
)


# --- signer (KMS-backed in prod; HMAC keeps dev/CI trivial) ---------------
_signer: Signer = HmacSigner()


def signer_dep() -> Signer:
    return _signer


# --- auth + per-request DB session ---------------------------------------
def current_user_id(authorization: str = Header(default="")) -> str:
    """v1 auth: ``Authorization: Bearer <users.id UUID>``.
    Swap this dependency for a JWT/cookie resolver in production."""
    prefix = "Bearer "
    if not authorization.startswith(prefix):
        raise HTTPException(status_code=401, detail="missing bearer token")
    token = authorization[len(prefix):].strip()
    try:
        uuid.UUID(token)
    except ValueError:
        raise HTTPException(status_code=401, detail="bearer token is not a uuid")
    return token


def db(user_id: str = Depends(current_user_id)) -> Iterator[Any]:
    conn = connect()
    try:
        # Postgres SET doesn't take parameters, but set_config() does.
        # user_id has already been UUID-validated by current_user_id.
        with conn.cursor() as cur:
            cur.execute("SELECT set_config('app.current_user_id', %s, false)", (user_id,))
        yield conn
    finally:
        conn.close()


def _require_insured(conn: Any, insured_id: str) -> None:
    """RLS returns zero rows for orgs the caller can't see; that's a 404."""
    with conn.cursor() as cur:
        cur.execute("SELECT 1 FROM orgs WHERE id = %s AND type = 'INSURED'", (insured_id,))
        if cur.fetchone() is None:
            raise HTTPException(status_code=404, detail="insured not found")


# --- 1. health -----------------------------------------------------------
@app.get("/health", tags=["meta"])
def health() -> dict[str, bool]:
    return {"ok": True}


# --- 2. me ---------------------------------------------------------------
@app.get("/me", response_model=S.Me, tags=["identity"])
def me(uid: str = Depends(current_user_id), conn: Any = Depends(db)) -> S.Me:
    with conn.cursor() as cur:
        cur.execute(
            "SELECT id, email, display_name, is_platform_super FROM users WHERE id = %s",
            (uid,),
        )
        row = cur.fetchone()
        if row is None:
            raise HTTPException(status_code=401, detail="user not found")
        cur.execute(
            "SELECT m.org_id, o.name, o.type, m.role "
            "FROM memberships m JOIN orgs o ON o.id = m.org_id "
            "WHERE m.user_id = %s",
            (uid,),
        )
        memberships = [
            S.Membership(org_id=str(r[0]), org_name=r[1], org_type=r[2], role=r[3])
            for r in cur.fetchall()
        ]
    return S.Me(
        id=str(row[0]), email=row[1], display_name=row[2],
        is_platform_super=row[3], memberships=memberships,
    )


# --- 3. insureds list ----------------------------------------------------
@app.get("/insureds", response_model=list[S.Insured], tags=["insureds"])
def list_insureds(conn: Any = Depends(db)) -> list[S.Insured]:
    with conn.cursor() as cur:
        cur.execute(
            "SELECT o.id, o.name, o.parent_id, p.name "
            "FROM orgs o LEFT JOIN orgs p ON p.id = o.parent_id "
            "WHERE o.type = 'INSURED' "
            "ORDER BY o.name"
        )
        return [
            S.Insured(id=str(r[0]), name=r[1],
                      parent_id=str(r[2]) if r[2] else None,
                      parent_name=r[3])
            for r in cur.fetchall()
        ]


# --- 4. posture rollup ---------------------------------------------------
@app.get("/insureds/{insured_id}/posture", response_model=S.Posture, tags=["insureds"])
def posture(insured_id: str, conn: Any = Depends(db)) -> S.Posture:
    _require_insured(conn, insured_id)
    with conn.cursor() as cur:
        cur.execute(
            """
            SELECT cd.pillar,
                   count(*) FILTER (WHERE cs.state = 'compliant') AS compliant,
                   count(*) FILTER (WHERE cs.state = 'drifted')   AS drifted,
                   count(*) FILTER (WHERE cs.state = 'degraded')  AS degraded,
                   count(*) FILTER (WHERE cs.state = 'unknown')   AS unknown,
                   count(*) FILTER (WHERE cs.state = 'stale')     AS stale
            FROM control_states cs
            JOIN control_definitions cd USING (control_key)
            WHERE cs.insured_org_id = %s
            GROUP BY cd.pillar
            ORDER BY cd.pillar
            """,
            (insured_id,),
        )
        by_pillar = [
            S.PillarRollup(pillar=r[0], compliant=r[1], drifted=r[2],
                           degraded=r[3], unknown=r[4], stale=r[5])
            for r in cur.fetchall()
        ]
        cur.execute(
            "SELECT count(*) FROM drift_events "
            "WHERE insured_org_id = %s AND resolved_at IS NULL",
            (insured_id,),
        )
        open_drift = int(cur.fetchone()[0])

    total = sum(p.compliant + p.drifted + p.degraded + p.unknown + p.stale for p in by_pillar)
    # worst-of rollup: any drifted -> drifted; else any degraded -> degraded; else compliant/unknown
    if any(p.drifted or p.stale for p in by_pillar):
        overall = "drifted"
    elif any(p.degraded for p in by_pillar):
        overall = "degraded"
    elif total == 0:
        overall = "unknown"
    else:
        overall = "compliant"
    return S.Posture(
        insured_id=insured_id, as_of=dt.datetime.now(dt.timezone.utc),
        overall_state=overall, by_pillar=by_pillar,
        open_drift_events=open_drift, controls_evaluated=total,
    )


# --- 5. controls list ----------------------------------------------------
@app.get("/insureds/{insured_id}/controls", response_model=list[S.ControlRow], tags=["insureds"])
def list_controls(insured_id: str, conn: Any = Depends(db)) -> list[S.ControlRow]:
    _require_insured(conn, insured_id)
    with conn.cursor() as cur:
        cur.execute(
            """
            SELECT cd.control_key, cd.title, cd.pillar, cd.severity,
                   cs.state, cs.coverage_pct, cs.failing_subjects,
                   cs.last_evaluated, cs.drift_since
            FROM control_definitions cd
            LEFT JOIN control_states cs
              ON cs.control_key = cd.control_key AND cs.insured_org_id = %s
            ORDER BY cd.pillar, cd.control_key
            """,
            (insured_id,),
        )
        return [
            S.ControlRow(
                control_key=r[0], title=r[1], pillar=r[2], severity=r[3],
                state=r[4] or "unknown",
                coverage_pct=float(r[5]) if r[5] is not None else None,
                failing_subjects=r[6] or [],
                last_evaluated=r[7], drift_since=r[8],
            )
            for r in cur.fetchall()
        ]


# --- 6. drift feed -------------------------------------------------------
@app.get("/insureds/{insured_id}/drift-events", response_model=list[S.DriftEvent], tags=["insureds"])
def drift_events(
    insured_id: str,
    open_only: bool = Query(default=False, description="Return only unresolved events."),
    limit: int = Query(default=100, ge=1, le=500),
    conn: Any = Depends(db),
) -> list[S.DriftEvent]:
    _require_insured(conn, insured_id)
    q = (
        "SELECT event_id, control_key, from_state, to_state, severity, "
        "       detected_at, resolved_at, root_cause_facts "
        "FROM drift_events WHERE insured_org_id = %s "
    )
    params: list[Any] = [insured_id]
    if open_only:
        q += "AND resolved_at IS NULL "
    q += "ORDER BY detected_at DESC LIMIT %s"
    params.append(limit)
    with conn.cursor() as cur:
        cur.execute(q, params)
        return [
            S.DriftEvent(
                id=str(r[0]), control_key=r[1], from_state=r[2], to_state=r[3],
                severity=r[4], detected_at=r[5], resolved_at=r[6],
                root_cause_facts=r[7] or [],
            )
            for r in cur.fetchall()
        ]


# --- 7. questionnaires ---------------------------------------------------
@app.get("/questionnaires", response_model=list[S.Questionnaire], tags=["questionnaires"])
def list_questionnaires(conn: Any = Depends(db)) -> list[S.Questionnaire]:
    with conn.cursor() as cur:
        cur.execute(
            """
            SELECT q.id, q.key, q.name, q.version, q.origin, q.is_baseline,
                   (SELECT count(*) FROM questionnaire_items WHERE questionnaire_id = q.id)
            FROM questionnaires q
            ORDER BY q.is_baseline DESC, q.name
            """
        )
        return [
            S.Questionnaire(
                id=str(r[0]), key=r[1], name=r[2], version=r[3], origin=r[4],
                is_baseline=r[5], item_count=int(r[6]),
            )
            for r in cur.fetchall()
        ]


# --- 8. answers ----------------------------------------------------------
@app.get(
    "/insureds/{insured_id}/questionnaires/{key}/answers",
    response_model=S.AnswerSheet, tags=["questionnaires"],
)
def answers(insured_id: str, key: str, conn: Any = Depends(db)) -> S.AnswerSheet:
    _require_insured(conn, insured_id)
    with conn.cursor() as cur:
        # confirm the questionnaire is visible to this caller (RLS-filtered)
        cur.execute("SELECT 1 FROM questionnaires WHERE key = %s", (key,))
        if cur.fetchone() is None:
            raise HTTPException(status_code=404, detail="questionnaire not found")
        cur.execute(
            "SELECT item_key, category, prompt, required, control_key, "
            "       state, coverage_pct, answer "
            "FROM questionnaire_answers(%s, %s)",
            (insured_id, key),
        )
        rows = cur.fetchall()
    return S.AnswerSheet(
        insured_id=insured_id, questionnaire_key=key,
        answers=[
            S.Answer(
                item_key=r[0], category=r[1], prompt=r[2], required=r[3],
                control_key=r[4], state=r[5],
                coverage_pct=float(r[6]) if r[6] is not None else None,
                answer=r[7],
            )
            for r in rows
        ],
    )


# --- 9. signed attestation packet ----------------------------------------
@app.post(
    "/insureds/{insured_id}/questionnaires/{key}/packet",
    tags=["packets"],
    summary="Build a signed attestation packet",
    description=(
        "Assembles the insured's posture into a portable, signed JSON document "
        "the broker can hand to a carrier. Independently verifiable via "
        "``verify_packet()`` and the platform's public key."
    ),
)
def packet(
    insured_id: str, key: str,
    conn: Any = Depends(db), signer: Signer = Depends(signer_dep),
) -> dict[str, Any]:
    _require_insured(conn, insured_id)
    try:
        return build_packet(conn, insured_id, key, signer)
    except LookupError as e:
        raise HTTPException(status_code=404, detail=str(e))


# --- 10. connectors ------------------------------------------------------
@app.get("/insureds/{insured_id}/connectors", response_model=list[S.Connector], tags=["insureds"])
def list_connectors(insured_id: str, conn: Any = Depends(db)) -> list[S.Connector]:
    _require_insured(conn, insured_id)
    with conn.cursor() as cur:
        cur.execute(
            "SELECT id, connector_type, display_name, status, last_run_at, last_success_at "
            "FROM connectors WHERE insured_org_id = %s ORDER BY display_name",
            (insured_id,),
        )
        return [
            S.Connector(
                id=str(r[0]), connector_type=r[1], display_name=r[2],
                status=r[3], last_run_at=r[4], last_success_at=r[5],
            )
            for r in cur.fetchall()
        ]
