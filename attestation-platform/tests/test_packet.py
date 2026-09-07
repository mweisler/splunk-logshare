"""Signature-verification tests for attestation packets. The DB-integrated
build/verify round-trip is exercised in the end-to-end demo; here we test the
tamper-detection contract directly against a hand-built packet."""

from __future__ import annotations

import base64
import copy

from attestation.core.ledger import HmacSigner, canonical_json
from attestation.packet.build import verify_packet


def _packet(signer):
    body = {
        "header": {
            "packet_version": "1",
            "issued_at": "2026-05-25T00:00:00+00:00",
            "insured": {"id": "ins-1", "name": "Bob Auto LLC", "type": "INSURED"},
            "questionnaire": {"id": "q1", "key": "baseline-v1", "name": "Baseline", "version": "1", "origin": "builtin"},
        },
        "answers": [
            {"item_key": "mfa.all_users", "answer": "yes", "state": "compliant", "coverage_pct": 1.0,
             "category": "Identity & Access", "prompt": "...", "required": True,
             "control_key": "identity.mfa_enforced"},
        ],
        "evidence": {
            "identity.mfa_enforced": {"state": "compliant", "coverage_pct": 1.0, "failing_subjects": [],
                                      "last_evaluated": "2026-05-25T00:00:00+00:00", "drift_since": None,
                                      "drift_history": {"total_events": 1, "open_events": 0}}
        },
        "ledger_proof": {"entry_count": 3, "first_hash": "sha256:aaa", "last_hash": "sha256:bbb",
                         "signer_key_id": signer.key_id, "verified": True},
    }
    sig = base64.b64encode(signer.sign(canonical_json(body))).decode("ascii")
    return {**body, "signature": {"algorithm": "HmacSigner", "key_id": signer.key_id, "value": sig}}


def test_verify_packet_accepts_untampered():
    signer = HmacSigner()
    assert verify_packet(_packet(signer), signer) is True


def test_verify_packet_rejects_flipped_answer():
    signer = HmacSigner()
    pkt = _packet(signer)
    tampered = copy.deepcopy(pkt)
    tampered["answers"][0]["answer"] = "no"
    assert verify_packet(tampered, signer) is False


def test_verify_packet_rejects_evidence_swap():
    signer = HmacSigner()
    pkt = _packet(signer)
    tampered = copy.deepcopy(pkt)
    tampered["evidence"]["identity.mfa_enforced"]["coverage_pct"] = 0.42
    assert verify_packet(tampered, signer) is False


def test_verify_packet_rejects_wrong_key():
    signer = HmacSigner(key=b"real")
    verifier = HmacSigner(key=b"impostor")
    assert verify_packet(_packet(signer), verifier) is False


def test_verify_packet_rejects_missing_signature():
    signer = HmacSigner()
    pkt = _packet(signer)
    del pkt["signature"]
    assert verify_packet(pkt, signer) is False
