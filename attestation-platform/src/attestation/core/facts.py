"""Fact ingestion: persist a ControlFact and append it to the evidence ledger
in a single transaction, so a fact can never exist without its ledger proof.
"""

from __future__ import annotations

import json
from typing import Any

from .ledger import Signer, append_entry
from .models import ControlFact


def ingest_fact(conn: Any, fact: ControlFact, signer: Signer) -> dict[str, Any]:
    """Write the fact row and its 'fact' ledger entry atomically."""
    payload = fact.to_dict()
    with conn.transaction():
        with conn.cursor() as cur:
            cur.execute(
                """
                INSERT INTO control_facts
                    (fact_id, insured_org_id, connector_id, connector_type, pillar,
                     control_key, subject, observed_value, status, source_event_time,
                     collected_at, evidence_ref, collector_run_id)
                VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s)
                """,
                (
                    fact.fact_id,
                    fact.insured_org_id,
                    fact.connector_id,
                    fact.connector_type,
                    fact.pillar.value,
                    fact.control_key,
                    json.dumps(fact.subject.to_dict()),
                    json.dumps(fact.observed_value),
                    fact.status.value,
                    fact.source_event_time,
                    fact.collected_at,
                    fact.evidence_ref,
                    fact.collector_run_id,
                ),
            )
        ledger_ref = append_entry(
            conn, fact.insured_org_id, "fact", payload, signer
        )
    return ledger_ref
