"""Phase 0 exit criterion, end to end:

  a fake connector writes a signed, verifiable fact scoped to one insured.

Requires a Postgres reachable via DATABASE_URL with all migrations applied
(`make migrate`). Run with `make demo`.

Seeds Platform -> Carrier -> Insured, a user + membership, a noop connector, runs
it, then verifies the insured's evidence chain.
"""

from __future__ import annotations

from attestation.core.ledger import LocalEd25519Signer, verify_chain
from attestation.db import connect
from attestation.worker.run import run_connector


def main() -> None:
    signer = LocalEd25519Signer()
    conn = connect()
    conn.autocommit = False

    with conn.cursor() as cur:
        # --- seed a minimal org tree: Platform > Carrier > Insured ---
        cur.execute(
            "INSERT INTO orgs (type, name) VALUES ('PLATFORM', 'core-infosec') RETURNING id"
        )
        platform_id = cur.fetchone()[0]
        cur.execute(
            "INSERT INTO orgs (parent_id, type, name) VALUES (%s, 'CARRIER', 'Acme Cyber Insurance') RETURNING id",
            (platform_id,),
        )
        carrier_id = cur.fetchone()[0]
        cur.execute(
            "INSERT INTO orgs (parent_id, type, name) VALUES (%s, 'INSURED', 'Bob''s Auto Parts LLC') RETURNING id",
            (carrier_id,),
        )
        insured_id = cur.fetchone()[0]

        cur.execute(
            "INSERT INTO users (email, display_name) VALUES (%s, %s) RETURNING id",
            ("admin@bobsautoparts.example", "Bob"),
        )
        user_id = cur.fetchone()[0]
        cur.execute(
            "INSERT INTO memberships (user_id, org_id, role) VALUES (%s, %s, 'INSURED_ADMIN')",
            (user_id, insured_id),
        )

        cur.execute(
            """
            INSERT INTO connectors (insured_org_id, connector_type, display_name)
            VALUES (%s, 'noop', 'Reference connector') RETURNING id
            """,
            (insured_id,),
        )
        connector_id = cur.fetchone()[0]
    conn.commit()

    result = run_connector(conn, connector_id, signer)
    print(f"ingested {result['facts_ingested']} facts (run {result['run_id']})")

    ok = verify_chain(conn, str(insured_id), signer)
    print(f"evidence chain verified: {ok}")

    with conn.cursor() as cur:
        cur.execute(
            "SELECT seq, entry_type, entry_hash FROM evidence_ledger WHERE insured_org_id = %s ORDER BY seq",
            (insured_id,),
        )
        for seq, entry_type, entry_hash in cur.fetchall():
            print(f"  [{seq}] {entry_type:<8} {entry_hash[:23]}...")

    conn.close()
    assert ok, "ledger verification failed"


if __name__ == "__main__":
    main()
