"""End-to-end verification of the client-portal API against real Postgres.

Applies migrations, seeds a two-carrier / two-insured tenant tree, ingests
facts via the noop connector, evaluates, then drives every API endpoint via
the FastAPI TestClient as two different users -- proving that RLS scopes the
API's view exactly the way the DB scopes queries."""

from __future__ import annotations

import json
import os

from fastapi.testclient import TestClient


def seed(conn):
    """Build: PLATFORM -> {Carrier A -> Insured A1 (+noop connector),
                          Carrier B -> Insured B1}
       and users: a1_admin (INSURED_ADMIN on A1), a_carrier (CARRIER_ADMIN on Carrier A)."""
    with conn.cursor() as cur:
        cur.execute("INSERT INTO orgs (type,name) VALUES ('PLATFORM','core-infosec') RETURNING id")
        p = cur.fetchone()[0]
        cur.execute("INSERT INTO orgs (parent_id,type,name) VALUES (%s,'CARRIER','Carrier A') RETURNING id", (p,))
        cA = cur.fetchone()[0]
        cur.execute("INSERT INTO orgs (parent_id,type,name) VALUES (%s,'CARRIER','Carrier B') RETURNING id", (p,))
        cB = cur.fetchone()[0]
        cur.execute("INSERT INTO orgs (parent_id,type,name) VALUES (%s,'INSURED','Insured A1') RETURNING id", (cA,))
        iA = cur.fetchone()[0]
        cur.execute("INSERT INTO orgs (parent_id,type,name) VALUES (%s,'INSURED','Insured B1') RETURNING id", (cB,))
        iB = cur.fetchone()[0]
        cur.execute(
            "INSERT INTO connectors (insured_org_id, connector_type, display_name) "
            "VALUES (%s, 'noop', 'Reference') RETURNING id", (iA,))
        connA = cur.fetchone()[0]

        cur.execute("INSERT INTO users (email, display_name) VALUES ('a1@e.com','A1 Admin') RETURNING id")
        ua = cur.fetchone()[0]
        cur.execute("INSERT INTO users (email, display_name) VALUES ('carrierA@e.com','Carrier A') RETURNING id")
        uca = cur.fetchone()[0]
        cur.execute("INSERT INTO memberships (user_id,org_id,role) VALUES (%s,%s,'INSURED_ADMIN')", (ua, iA))
        cur.execute("INSERT INTO memberships (user_id,org_id,role) VALUES (%s,%s,'CARRIER_ADMIN')", (uca, cA))
    conn.commit()
    return {"platform": str(p), "carrier_a": str(cA), "carrier_b": str(cB),
            "insured_a": str(iA), "insured_b": str(iB),
            "connector_a": str(connA), "user_a1": str(ua), "user_carrier_a": str(uca)}


def prime_posture(conn, connector_id):
    from attestation.core.ledger import HmacSigner
    from attestation.engine import evaluate_insured
    from attestation.worker.run import run_connector
    signer = HmacSigner()
    run_connector(conn, connector_id, signer)
    with conn.cursor() as cur:
        cur.execute("SELECT insured_org_id FROM connectors WHERE id = %s", (connector_id,))
        insured = str(cur.fetchone()[0])
    evaluate_insured(conn, insured, signer)


def main() -> None:
    import psycopg
    dsn_super = os.environ["DSN_SUPER"]    # postgres superuser (seeds + creates role)
    dsn_app = os.environ["DSN_APP"]        # attest_app (RLS enforces here)
    os.environ["DATABASE_URL"] = dsn_app   # API opens connections via this

    # Seed and prime as superuser.
    with psycopg.connect(dsn_super) as sconn:
        ids = seed(sconn)
        prime_posture(sconn, ids["connector_a"])

    # Late import so DATABASE_URL is already set.
    from attestation.api.app import app
    client = TestClient(app)

    A1 = ids["user_a1"]; CA = ids["user_carrier_a"]
    def as_(uid): return {"Authorization": f"Bearer {uid}"}
    ins_a = ids["insured_a"]; ins_b = ids["insured_b"]

    print("=== unauthenticated ===")
    r = client.get("/me")
    print(f"  GET /me without token -> {r.status_code}  (expect 401)")
    assert r.status_code == 401

    print("\n=== as Insured A1 admin ===")
    r = client.get("/me", headers=as_(A1)); print(f"  /me -> {r.status_code}  memberships={len(r.json()['memberships'])}")
    assert r.status_code == 200

    r = client.get("/insureds", headers=as_(A1))
    names = [i["name"] for i in r.json()]
    print(f"  /insureds -> {names}  (expect only ['Insured A1'])")
    assert names == ["Insured A1"], names

    r = client.get(f"/insureds/{ins_b}/posture", headers=as_(A1))
    print(f"  /insureds/<B1>/posture -> {r.status_code}  (expect 404, hidden by RLS)")
    assert r.status_code == 404

    r = client.get(f"/insureds/{ins_a}/posture", headers=as_(A1))
    body = r.json()
    print(f"  /insureds/<A1>/posture -> overall={body['overall_state']}  pillars={len(body['by_pillar'])}  controls={body['controls_evaluated']}")
    assert r.status_code == 200

    r = client.get(f"/insureds/{ins_a}/controls", headers=as_(A1))
    print(f"  /insureds/<A1>/controls -> {len(r.json())} rows (definitions + any observed states)")
    assert r.status_code == 200 and len(r.json()) > 0

    r = client.get(f"/insureds/{ins_a}/drift-events?open_only=true", headers=as_(A1))
    print(f"  /insureds/<A1>/drift-events?open_only=true -> {len(r.json())} open events")

    r = client.get("/questionnaires", headers=as_(A1))
    keys = [q["key"] for q in r.json()]
    print(f"  /questionnaires -> {keys}")
    assert "baseline-v1" in keys

    r = client.get(f"/insureds/{ins_a}/questionnaires/baseline-v1/answers", headers=as_(A1))
    body = r.json()
    counts = {}
    for a in body["answers"]:
        counts[a["answer"]] = counts.get(a["answer"], 0) + 1
    print(f"  /insureds/<A1>/questionnaires/baseline-v1/answers -> {sum(counts.values())} items {counts}")

    r = client.post(f"/insureds/{ins_a}/questionnaires/baseline-v1/packet", headers=as_(A1))
    pkt = r.json()
    print(f"  POST packet -> answers={len(pkt['answers'])}  ledger.entry_count={pkt['ledger_proof']['entry_count']}  verified={pkt['ledger_proof']['verified']}  sig_alg={pkt['signature']['algorithm']}")
    assert r.status_code == 200 and pkt["ledger_proof"]["verified"]

    r = client.get(f"/insureds/{ins_a}/connectors", headers=as_(A1))
    print(f"  /insureds/<A1>/connectors -> {[c['connector_type'] for c in r.json()]}")

    print("\n=== as Carrier A admin ===")
    r = client.get("/insureds", headers=as_(CA))
    names = [i["name"] for i in r.json()]
    print(f"  /insureds -> {names}  (expect ['Insured A1'] -- their book only, NOT B1)")
    assert names == ["Insured A1"]

    r = client.get(f"/insureds/{ins_b}/posture", headers=as_(CA))
    print(f"  /insureds/<B1>/posture -> {r.status_code}  (still hidden)")
    assert r.status_code == 404

    print("\nOK: every endpoint returned; RLS enforced isolation across two callers.")


if __name__ == "__main__":
    main()
