"""End-to-end demo of the evaluation engine against a live Postgres.

  1. seed Platform > Carrier > Insured + a noop connector
  2. run the connector -> ingest MFA 'pass' facts (also ledgered)
  3. evaluate -> identity.mfa_enforced becomes 'compliant' (unknown->compliant)
  4. ingest a 'fail' fact for one user (simulating an account losing MFA)
  5. re-evaluate past the grace window -> 'drifted', a drift_event + ledger entry
  6. show the baseline questionnaire answers flip, and verify the chain

Uses HmacSigner so it runs without the asymmetric crypto backend. Run:
    DATABASE_URL=postgres://.../attestation python scripts/demo_evaluate.py
"""

from __future__ import annotations

import datetime as dt
import uuid

from attestation.connectors.base import CollectionContext
from attestation.connectors import get
from attestation.core.facts import ingest_fact
from attestation.core.ledger import HmacSigner, verify_chain
from attestation.core.models import Cursor, FactStatus, Pillar, Subject
from attestation.db import connect
from attestation.engine import evaluate_insured
from attestation.worker.run import run_connector

CONTROL = "identity.mfa_enforced"


def _answer(conn, insured, item_key):
    with conn.cursor() as cur:
        cur.execute(
            "SELECT answer FROM questionnaire_answers(%s, 'baseline-v1') WHERE item_key = %s",
            (insured, item_key),
        )
        return cur.fetchone()[0]


def main() -> None:
    signer = HmacSigner()
    conn = connect()
    conn.autocommit = False

    with conn.cursor() as cur:
        cur.execute("INSERT INTO orgs (type,name) VALUES ('PLATFORM','core-infosec') RETURNING id")
        platform = cur.fetchone()[0]
        cur.execute("INSERT INTO orgs (parent_id,type,name) VALUES (%s,'CARRIER','Acme Cyber') RETURNING id", (platform,))
        carrier = cur.fetchone()[0]
        cur.execute("INSERT INTO orgs (parent_id,type,name) VALUES (%s,'INSURED','Bob Auto LLC') RETURNING id", (carrier,))
        insured = cur.fetchone()[0]
        cur.execute(
            "INSERT INTO connectors (insured_org_id,connector_type,display_name) VALUES (%s,'noop','Reference') RETURNING id",
            (insured,),
        )
        connector_id = cur.fetchone()[0]
    conn.commit()
    insured = str(insured)

    # 2 + 3: ingest pass facts, then evaluate
    run_connector(conn, connector_id, signer)
    res = evaluate_insured(conn, insured, signer)
    print(f"after first run:  {CONTROL} = {res[CONTROL]}   | baseline 'mfa.all_users' answer = {_answer(conn, insured, 'mfa.all_users')}")

    # 4: one user loses MFA
    ctx = CollectionContext(insured, str(connector_id), "noop", str(uuid.uuid4()))
    bad = ctx.fact(
        pillar=Pillar.IDENTITY,
        control_key=CONTROL,
        subject=Subject("user", "u2", "bob@example.com"),
        observed_value={"mfa_enforced": False},
        status=FactStatus.FAIL,
    )
    ingest_fact(conn, bad, signer)

    # 5: the grace clock starts when an evaluation first SEES the bad state.
    # First observation -> held compliant; 61 min later -> drift fires.
    base = dt.datetime.now(dt.timezone.utc)
    res = evaluate_insured(conn, insured, signer, now=base)
    print(f"inside grace:     {CONTROL} = {res[CONTROL]}   (held compliant during 60m grace)")

    res = evaluate_insured(conn, insured, signer, now=base + dt.timedelta(minutes=61))
    print(f"past grace:       {CONTROL} = {res[CONTROL]}   | baseline 'mfa.all_users' answer = {_answer(conn, insured, 'mfa.all_users')}")

    # 6: show the drift event + ledger
    with conn.cursor() as cur:
        cur.execute(
            "SELECT from_state, to_state, severity FROM drift_events WHERE insured_org_id=%s ORDER BY detected_at",
            (insured,),
        )
        print("drift events:    ", [tuple(r) for r in cur.fetchall()])
        cur.execute("SELECT entry_type, count(*) FROM evidence_ledger WHERE insured_org_id=%s GROUP BY entry_type ORDER BY entry_type", (insured,))
        print("ledger entries:  ", dict(cur.fetchall()))

    ok = verify_chain(conn, insured, signer)
    print(f"evidence chain verified: {ok}")
    conn.close()
    assert ok and res[CONTROL] == "drifted", "demo assertions failed"


if __name__ == "__main__":
    main()
