"""End-to-end demo tying everything together:

  1. seed Platform > Carrier > Insured + an m365 connector
  2. run the M365 connector against a FAKE Graph transport (canned tenant)
  3. evaluate all controls -> control_states + drift_events + ledger entries
  4. build a signed attestation packet against the baseline questionnaire
  5. verify the packet, then tamper with one answer and re-verify (must fail)

Uses HmacSigner + fake Graph transport, so it runs with no external services.
"""

from __future__ import annotations

import json

from attestation.connectors.m365 import M365Connector
from attestation.core.ledger import HmacSigner
from attestation.db import connect
from attestation.engine import evaluate_insured
from attestation.packet import build_packet, verify_packet
from attestation.worker.run import run_connector
from tests.test_m365 import FakeTransport, PAGE_1, PAGE_2  # reuse fixtures


def main() -> None:
    signer = HmacSigner()
    conn = connect()
    conn.autocommit = False

    with conn.cursor() as cur:
        cur.execute("INSERT INTO orgs (type,name) VALUES ('PLATFORM','core-infosec') RETURNING id")
        platform = cur.fetchone()[0]
        cur.execute("INSERT INTO orgs (parent_id,type,name) VALUES (%s,'CARRIER','Acme Cyber') RETURNING id", (platform,))
        carrier = cur.fetchone()[0]
        cur.execute(
            "INSERT INTO orgs (parent_id,type,name) VALUES (%s,'INSURED','Bob Auto LLC') RETURNING id",
            (carrier,),
        )
        insured = cur.fetchone()[0]
        cur.execute(
            """
            INSERT INTO connectors (insured_org_id, connector_type, display_name,
                                    config, secret_ref, status)
            VALUES (%s, 'm365', 'Bob Auto M365',
                    %s::jsonb, 'json:{"client_secret":"fake-secret"}', 'active')
            RETURNING id
            """,
            (insured, json.dumps({"tenant_id": "tid", "client_id": "cid"})),
        )
        connector_id = cur.fetchone()[0]
    conn.commit()
    insured = str(insured)

    # 2: run M365 with a fake Graph transport (3 users, 2 admins, 1 non-registered)
    fake = FakeTransport(report_pages=[PAGE_1, PAGE_2])
    result = run_connector(conn, connector_id, signer,
                           connector_instance=M365Connector(transport=fake))
    print(f"M365 run: {result['facts_ingested']} facts ingested")

    # 3: evaluate -> control_states + drift_events + ledger entries
    states = evaluate_insured(conn, insured, signer)
    print(f"evaluated {len(states)} controls: {states}")

    # 4: build the signed packet
    pkt = build_packet(conn, insured, "baseline-v1", signer)
    print("\n--- packet summary ---")
    print(f"insured:       {pkt['header']['insured']['name']}")
    print(f"questionnaire: {pkt['header']['questionnaire']['key']}  v{pkt['header']['questionnaire']['version']}")
    print(f"answers:       {len(pkt['answers'])} items")
    print(f"  yes:     {sum(1 for a in pkt['answers'] if a['answer']=='yes')}")
    print(f"  no:      {sum(1 for a in pkt['answers'] if a['answer']=='no')}")
    print(f"  unknown: {sum(1 for a in pkt['answers'] if a['answer']=='unknown')}")
    print(f"  manual:  {sum(1 for a in pkt['answers'] if a['answer']=='manual')}")
    print(f"ledger:        {pkt['ledger_proof']['entry_count']} entries, verified={pkt['ledger_proof']['verified']}")
    print(f"signer:        {pkt['signature']['algorithm']} / {pkt['signature']['key_id']}")

    # 5: verification + tamper test
    ok = verify_packet(pkt, signer)
    print(f"\nverify (untampered):    {ok}")

    tampered = json.loads(json.dumps(pkt))
    a = next(a for a in tampered["answers"] if a["item_key"] == "mfa.all_users")
    a["answer"] = "yes"; a["state"] = "compliant"
    ok_tampered = verify_packet(tampered, signer)
    print(f"verify (answer flipped): {ok_tampered}")

    assert ok is True and ok_tampered is False, "packet verification contract broken"
    conn.close()


if __name__ == "__main__":
    main()
