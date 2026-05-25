"""Tamper-evident evidence ledger: per-insured hash chain + signatures.

The chain is pure and DB-agnostic so it can be unit-tested without Postgres
(see tests/test_ledger.py). ``append_entry`` / ``verify_chain`` wrap it with the
database. Swap ``LocalEd25519Signer`` for a KMS/HSM-backed ``Signer`` in prod;
the interface is identical.
"""

from __future__ import annotations

import abc
import base64
import hashlib
import hmac
import json
from typing import Any

GENESIS_HASH = "sha256:" + "0" * 64


class Signer(abc.ABC):
    key_id: str

    @abc.abstractmethod
    def sign(self, data: bytes) -> bytes: ...

    @abc.abstractmethod
    def verify(self, data: bytes, signature: bytes) -> bool: ...


class LocalEd25519Signer(Signer):
    """Dev/test signer. In production, back this with KMS so the private key
    never leaves the HSM; only ``sign``/``verify`` cross the boundary."""

    def __init__(self, private_key: Any = None, key_id: str = "local-dev") -> None:
        from cryptography.hazmat.primitives.asymmetric.ed25519 import (
            Ed25519PrivateKey,
        )

        self._sk = private_key or Ed25519PrivateKey.generate()
        self._pk = self._sk.public_key()
        self.key_id = key_id

    def sign(self, data: bytes) -> bytes:
        return self._sk.sign(data)

    def verify(self, data: bytes, signature: bytes) -> bool:
        from cryptography.exceptions import InvalidSignature

        try:
            self._pk.verify(signature, data)
            return True
        except InvalidSignature:
            return False


class HmacSigner(Signer):
    """Symmetric HMAC-SHA256 signer using only the stdlib. Useful where the
    asymmetric crypto backend is unavailable, or for a lightweight dev/CI mode.
    Note: HMAC is symmetric, so the verifier holds the same secret -- prefer the
    KMS/Ed25519 signer when non-repudiation matters."""

    def __init__(self, key: bytes = b"dev-secret", key_id: str = "hmac-dev") -> None:
        self._key = key
        self.key_id = key_id

    def sign(self, data: bytes) -> bytes:
        return hmac.new(self._key, data, hashlib.sha256).digest()

    def verify(self, data: bytes, signature: bytes) -> bool:
        return hmac.compare_digest(self.sign(data), signature)


def _canonical(payload: dict[str, Any]) -> bytes:
    """Deterministic JSON so the same logical payload always hashes the same."""
    return json.dumps(
        payload, sort_keys=True, separators=(",", ":"), default=str
    ).encode("utf-8")


def compute_entry_hash(prev_hash: str, entry_type: str, payload: dict[str, Any]) -> str:
    h = hashlib.sha256()
    h.update(prev_hash.encode("utf-8"))
    h.update(entry_type.encode("utf-8"))
    h.update(_canonical(payload))
    return "sha256:" + h.hexdigest()


# --- database-backed append / verify --------------------------------------
# psycopg connections are passed in; transactions are managed by the caller.


def append_entry(
    conn: Any,
    insured_org_id: str,
    entry_type: str,
    payload: dict[str, Any],
    signer: Signer,
) -> dict[str, Any]:
    """Append a signed entry to an insured's chain. Locks the insured's tail row
    so concurrent appends can't fork the chain."""
    with conn.cursor() as cur:
        cur.execute(
            """
            SELECT seq, entry_hash FROM evidence_ledger
            WHERE insured_org_id = %s
            ORDER BY seq DESC LIMIT 1
            FOR UPDATE
            """,
            (insured_org_id,),
        )
        row = cur.fetchone()
        if row is None:
            seq, prev_hash = 0, GENESIS_HASH
        else:
            seq, prev_hash = row[0] + 1, row[1]

        entry_hash = compute_entry_hash(prev_hash, entry_type, payload)
        signature = base64.b64encode(signer.sign(entry_hash.encode("utf-8"))).decode()

        cur.execute(
            """
            INSERT INTO evidence_ledger
                (insured_org_id, seq, prev_hash, entry_hash, entry_type,
                 payload, signature, signer_key_id)
            VALUES (%s, %s, %s, %s, %s, %s, %s, %s)
            RETURNING id
            """,
            (
                insured_org_id,
                seq,
                prev_hash,
                entry_hash,
                entry_type,
                json.dumps(payload, default=str),
                signature,
                signer.key_id,
            ),
        )
        entry_id = cur.fetchone()[0]

    return {"id": entry_id, "seq": seq, "entry_hash": entry_hash}


def verify_chain(conn: Any, insured_org_id: str, signer: Signer) -> bool:
    """Recompute the chain and check every signature. Returns False on any
    break -- this is what backs a claims-defense / continuity proof."""
    with conn.cursor() as cur:
        cur.execute(
            """
            SELECT seq, prev_hash, entry_hash, entry_type, payload, signature
            FROM evidence_ledger
            WHERE insured_org_id = %s
            ORDER BY seq ASC
            """,
            (insured_org_id,),
        )
        rows = cur.fetchall()

    expected_prev = GENESIS_HASH
    for seq, prev_hash, entry_hash, entry_type, payload, signature in rows:
        if prev_hash != expected_prev:
            return False
        payload_dict = payload if isinstance(payload, dict) else json.loads(payload)
        if compute_entry_hash(prev_hash, entry_type, payload_dict) != entry_hash:
            return False
        if signature is not None:
            sig = base64.b64decode(signature)
            if not signer.verify(entry_hash.encode("utf-8"), sig):
                return False
        expected_prev = entry_hash
    return True
