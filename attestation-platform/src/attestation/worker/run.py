"""Connector run harness: load a connector row, run the connector, ingest each
fact (which also appends to the ledger), then persist the resume cursor.

This is the in-process version. In production the same body runs as a Temporal/
Celery task per connector on a schedule, with retries and backoff -- the same
poll/checkpoint loop as the Splunk Cloudflare modular input.
"""

from __future__ import annotations

import json
import uuid
from typing import Any

from ..connectors import get
from ..connectors.base import CollectionContext
from ..core.ledger import Signer
from ..core.models import Cursor
from ..core.facts import ingest_fact


def run_connector(conn: Any, connector_id: str, signer: Signer) -> dict[str, Any]:
    with conn.cursor() as cur:
        cur.execute(
            """
            SELECT insured_org_id, connector_type, secret_ref, cursor
            FROM connectors WHERE id = %s
            """,
            (connector_id,),
        )
        row = cur.fetchone()
    if row is None:
        raise LookupError(f"connector {connector_id} not found")
    insured_org_id, connector_type, secret_ref, cursor_data = row

    connector = get(connector_type)()
    # TODO: resolve secret_ref against the vault; noop ignores it.
    secret = {"secret_ref": secret_ref}
    session = connector.authenticate(secret)

    run_id = str(uuid.uuid4())
    ctx = CollectionContext(
        insured_org_id=str(insured_org_id),
        connector_id=str(connector_id),
        connector_type=connector_type,
        collector_run_id=run_id,
    )

    count = 0
    for fact in connector.collect(session, Cursor(cursor_data or {}), ctx):
        ingest_fact(conn, fact, signer)
        count += 1

    new_cursor = connector.checkpoint()
    with conn.transaction():
        with conn.cursor() as cur:
            cur.execute(
                """
                UPDATE connectors
                SET cursor = %s, last_run_at = now(), last_success_at = now()
                WHERE id = %s
                """,
                (json.dumps(new_cursor.data), connector_id),
            )

    return {"run_id": run_id, "facts_ingested": count}
