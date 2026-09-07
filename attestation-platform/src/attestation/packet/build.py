"""Attestation packet: the deliverable a broker hands to a carrier.

A packet is a single signed JSON document that combines, for one insured and
one questionnaire, four things:

  * ``header``       -- who / what / when / issuer key id
  * ``answers``      -- one row per questionnaire item (yes/no/unknown/manual)
                        with the underlying control state and coverage
  * ``evidence``     -- rolled-up posture for each control referenced by the
                        questionnaire (last_evaluated, drift_since, failing
                        subjects) plus a small drift-history summary
  * ``ledger_proof`` -- continuity proof for the insured's evidence chain:
                        first hash, last hash, entry count, verified flag

The signature covers the canonical JSON of everything except the signature
itself, using the same canonicalization the ledger uses -- so a carrier can
verify a packet with the same key material that signs ledger entries.

The packet is deliberately self-contained: no back-references to the platform
DB, so a carrier can archive it and re-verify years later.
"""

from __future__ import annotations

import base64
import datetime as dt
from typing import Any

from ..core.ledger import GENESIS_HASH, Signer, canonical_json, verify_chain

PACKET_VERSION = "1"


def _utcnow_iso() -> str:
    return dt.datetime.now(dt.timezone.utc).isoformat()


def _fetch_insured(conn: Any, insured_id: str) -> dict[str, Any]:
    with conn.cursor() as cur:
        cur.execute("SELECT id, name, type FROM orgs WHERE id = %s", (insured_id,))
        row = cur.fetchone()
    if row is None:
        raise LookupError(f"insured {insured_id!r} not found")
    return {"id": str(row[0]), "name": row[1], "type": row[2]}


def _fetch_questionnaire(conn: Any, key: str) -> dict[str, Any]:
    with conn.cursor() as cur:
        cur.execute(
            "SELECT id, key, name, version, origin FROM questionnaires WHERE key = %s",
            (key,),
        )
        row = cur.fetchone()
    if row is None:
        raise LookupError(f"questionnaire {key!r} not found")
    return {"id": str(row[0]), "key": row[1], "name": row[2], "version": row[3], "origin": row[4]}


def _fetch_answers(conn: Any, insured_id: str, key: str) -> list[dict[str, Any]]:
    with conn.cursor() as cur:
        cur.execute(
            "SELECT item_key, category, prompt, required, control_key, state, "
            "       coverage_pct, answer "
            "FROM questionnaire_answers(%s, %s)",
            (insured_id, key),
        )
        cols = [d[0] for d in cur.description]
        rows = [dict(zip(cols, r)) for r in cur.fetchall()]
    for row in rows:  # Postgres numeric -> Decimal; make the packet plain-JSON
        if row.get("coverage_pct") is not None:
            row["coverage_pct"] = float(row["coverage_pct"])
    return rows


def _fetch_evidence(
    conn: Any, insured_id: str, control_keys: list[str]
) -> dict[str, dict[str, Any]]:
    """Rolled-up state + a summary of recent drift for each referenced control."""
    if not control_keys:
        return {}
    with conn.cursor() as cur:
        cur.execute(
            """
            SELECT control_key, state, coverage_pct, failing_subjects,
                   last_evaluated, drift_since
            FROM control_states
            WHERE insured_org_id = %s AND control_key = ANY(%s)
            """,
            (insured_id, control_keys),
        )
        state_by_key = {}
        for row in cur.fetchall():
            state_by_key[row[0]] = {
                "state": row[1],
                "coverage_pct": float(row[2]) if row[2] is not None else None,
                "failing_subjects": row[3] or [],
                "last_evaluated": row[4].isoformat() if row[4] else None,
                "drift_since": row[5].isoformat() if row[5] else None,
            }

        cur.execute(
            """
            SELECT control_key,
                   count(*)                    AS total,
                   count(*) FILTER (WHERE resolved_at IS NULL) AS open,
                   max(detected_at)            AS last_detected
            FROM drift_events
            WHERE insured_org_id = %s AND control_key = ANY(%s)
            GROUP BY control_key
            """,
            (insured_id, control_keys),
        )
        drift_by_key = {}
        for row in cur.fetchall():
            drift_by_key[row[0]] = {
                "total_events": int(row[1]),
                "open_events": int(row[2]),
                "last_detected_at": row[3].isoformat() if row[3] else None,
            }

    return {
        k: {**state_by_key.get(k, {}), "drift_history": drift_by_key.get(k, {"total_events": 0, "open_events": 0})}
        for k in control_keys
    }


def _fetch_ledger_proof(conn: Any, insured_id: str, signer: Signer) -> dict[str, Any]:
    """Verify the chain and summarize it. `verified` here is the same guarantee
    the platform gives internally -- carriers can independently re-verify by
    replaying the chain if the platform ever exposes it."""
    with conn.cursor() as cur:
        cur.execute(
            """
            SELECT count(*), min(seq), max(seq),
                   min(entry_hash) FILTER (WHERE seq = 0) AS first_hash
            FROM evidence_ledger
            WHERE insured_org_id = %s
            """,
            (insured_id,),
        )
        count, min_seq, max_seq, first_hash = cur.fetchone()
        cur.execute(
            """
            SELECT entry_hash, signer_key_id
            FROM evidence_ledger
            WHERE insured_org_id = %s
            ORDER BY seq DESC LIMIT 1
            """,
            (insured_id,),
        )
        tail = cur.fetchone()

    verified = verify_chain(conn, insured_id, signer) if count else True
    return {
        "entry_count": int(count),
        "first_hash": first_hash if first_hash is not None else GENESIS_HASH,
        "last_hash": tail[0] if tail else GENESIS_HASH,
        "signer_key_id": tail[1] if tail else signer.key_id,
        "verified": bool(verified),
    }


def build_packet(
    conn: Any,
    insured_id: str,
    questionnaire_key: str,
    signer: Signer,
) -> dict[str, Any]:
    """Assemble and sign an attestation packet."""
    header = {
        "packet_version": PACKET_VERSION,
        "issued_at": _utcnow_iso(),
        "insured": _fetch_insured(conn, insured_id),
        "questionnaire": _fetch_questionnaire(conn, questionnaire_key),
    }
    answers = _fetch_answers(conn, insured_id, questionnaire_key)
    control_keys = sorted({a["control_key"] for a in answers if a["control_key"]})
    evidence = _fetch_evidence(conn, insured_id, control_keys)
    ledger_proof = _fetch_ledger_proof(conn, insured_id, signer)

    body = {
        "header": header,
        "answers": answers,
        "evidence": evidence,
        "ledger_proof": ledger_proof,
    }
    signature = base64.b64encode(signer.sign(canonical_json(body))).decode("ascii")
    return {
        **body,
        "signature": {
            "algorithm": signer.__class__.__name__,
            "key_id": signer.key_id,
            "value": signature,
        },
    }


def verify_packet(packet: dict[str, Any], signer: Signer) -> bool:
    """Independent verification: recompute the canonical body, check the sig."""
    sig = packet.get("signature")
    if not isinstance(sig, dict) or "value" not in sig:
        return False
    body = {k: packet[k] for k in ("header", "answers", "evidence", "ledger_proof") if k in packet}
    return signer.verify(canonical_json(body), base64.b64decode(sig["value"]))
