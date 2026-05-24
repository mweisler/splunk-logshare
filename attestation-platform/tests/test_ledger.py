"""Unit tests for the hash chain + signer. No database required -- exercises the
pure ledger primitives so the tamper-evidence guarantee is covered in CI."""

from __future__ import annotations

import base64

from attestation.core.ledger import (
    GENESIS_HASH,
    LocalEd25519Signer,
    compute_entry_hash,
)


def _build_chain(entries):
    """Build an in-memory signed chain, mirroring append_entry's hashing."""
    signer = LocalEd25519Signer()
    chain = []
    prev = GENESIS_HASH
    for i, (etype, payload) in enumerate(entries):
        entry_hash = compute_entry_hash(prev, etype, payload)
        sig = base64.b64encode(signer.sign(entry_hash.encode())).decode()
        chain.append(
            {"seq": i, "prev_hash": prev, "entry_hash": entry_hash,
             "entry_type": etype, "payload": payload, "signature": sig}
        )
        prev = entry_hash
    return signer, chain


def _verify(signer, chain):
    expected_prev = GENESIS_HASH
    for e in chain:
        if e["prev_hash"] != expected_prev:
            return False
        if compute_entry_hash(e["prev_hash"], e["entry_type"], e["payload"]) != e["entry_hash"]:
            return False
        if not signer.verify(e["entry_hash"].encode(), base64.b64decode(e["signature"])):
            return False
        expected_prev = e["entry_hash"]
    return True


def test_clean_chain_verifies():
    signer, chain = _build_chain(
        [("fact", {"a": 1}), ("fact", {"b": 2}), ("attestation", {"c": 3})]
    )
    assert _verify(signer, chain)


def test_tampered_payload_breaks_chain():
    signer, chain = _build_chain([("fact", {"a": 1}), ("fact", {"b": 2})])
    chain[0]["payload"] = {"a": 999}  # mutate after signing
    assert not _verify(signer, chain)


def test_deleted_entry_breaks_chain():
    signer, chain = _build_chain(
        [("fact", {"a": 1}), ("fact", {"b": 2}), ("fact", {"c": 3})]
    )
    del chain[1]  # drop the middle link
    assert not _verify(signer, chain)


def test_canonical_hash_is_key_order_independent():
    assert compute_entry_hash(GENESIS_HASH, "fact", {"a": 1, "b": 2}) == \
        compute_entry_hash(GENESIS_HASH, "fact", {"b": 2, "a": 1})


def test_foreign_signature_rejected():
    signer, chain = _build_chain([("fact", {"a": 1})])
    other = LocalEd25519Signer()
    assert not _verify(other, chain)  # signed by a different key
