"""Tests for the M365 Graph connector using an injected fake transport.
No network, no credentials -- exercises pagination, admin flag, MFA status
mapping, and the error paths."""

from __future__ import annotations

import pytest

from attestation.connectors.base import CollectionContext
from attestation.connectors.m365 import M365Connector
from attestation.core.models import FactStatus


class FakeTransport:
    def __init__(self, token_response=None, report_pages=None):
        self.token_response = token_response or {"access_token": "T", "token_type": "Bearer"}
        self._pages = list(report_pages or [])
        self.calls = []

    def post_form(self, url, data):
        self.calls.append(("POST", url, data))
        return self.token_response

    def get_json(self, url, token):
        self.calls.append(("GET", url, token))
        assert self._pages, f"no fake page queued for GET {url}"
        return self._pages.pop(0)


def _ctx():
    return CollectionContext(
        insured_org_id="ins-1", connector_id="conn-1", connector_type="m365", collector_run_id="run-1"
    )


PAGE_1 = {
    "value": [
        {"id": "u1", "userPrincipalName": "alice@t.com", "isMfaRegistered": True,  "isMfaCapable": True,  "isAdmin": False, "methodsRegistered": ["totp"]},
        {"id": "u2", "userPrincipalName": "bob@t.com",   "isMfaRegistered": False, "isMfaCapable": True,  "isAdmin": True,  "methodsRegistered": []},
    ],
    "@odata.nextLink": "https://graph.microsoft.com/v1.0/reports/authenticationMethods/userRegistrationDetails?$skiptoken=X",
}
PAGE_2 = {
    "value": [
        {"id": "u3", "userPrincipalName": "carol@t.com", "isMfaRegistered": True, "isMfaCapable": True, "isAdmin": True, "methodsRegistered": ["fido2"]},
    ],
}


def test_authenticate_hits_token_endpoint_with_client_credentials():
    fake = FakeTransport()
    c = M365Connector(transport=fake)
    session = c.authenticate({"tenant_id": "tid", "client_id": "cid"}, {"client_secret": "sec"})
    method, url, data = fake.calls[0]
    assert method == "POST" and "tid/oauth2/v2.0/token" in url
    assert data["grant_type"] == "client_credentials"
    assert data["client_id"] == "cid" and data["client_secret"] == "sec"
    assert session.token == "T"


def test_authenticate_rejects_missing_fields():
    c = M365Connector(transport=FakeTransport())
    with pytest.raises(ValueError, match="tenant_id"):
        c.authenticate({}, {"client_secret": "s"})
    with pytest.raises(ValueError, match="client_secret"):
        c.authenticate({"tenant_id": "t", "client_id": "c"}, {})


def test_authenticate_raises_when_token_endpoint_returns_no_token():
    fake = FakeTransport(token_response={"error": "invalid_client"})
    with pytest.raises(RuntimeError, match="access_token"):
        M365Connector(transport=fake).authenticate(
            {"tenant_id": "t", "client_id": "c"}, {"client_secret": "s"}
        )


def test_collect_emits_mfa_and_admin_facts_across_pages():
    fake = FakeTransport(report_pages=[PAGE_1, PAGE_2])
    c = M365Connector(transport=fake)
    session = c.authenticate({"tenant_id": "t", "client_id": "c"}, {"client_secret": "s"})
    facts = list(c.collect(session, c.checkpoint(), _ctx()))

    by_control: dict[str, list] = {}
    for f in facts:
        by_control.setdefault(f.control_key, []).append(f)

    # 3 users -> 3 mfa_enforced facts; 2 admins -> 2 mfa_admins facts
    assert len(by_control["identity.mfa_enforced"]) == 3
    assert len(by_control["identity.mfa_admins"]) == 2

    # u1 registered -> PASS ; u2 not registered -> FAIL (bob is an admin so also mfa_admins FAIL)
    by_upn = {f.subject.label: f for f in by_control["identity.mfa_enforced"]}
    assert by_upn["alice@t.com"].status == FactStatus.PASS
    assert by_upn["bob@t.com"].status == FactStatus.FAIL
    assert by_upn["carol@t.com"].status == FactStatus.PASS

    bob_admin = next(f for f in by_control["identity.mfa_admins"] if f.subject.label == "bob@t.com")
    assert bob_admin.status == FactStatus.FAIL
    assert bob_admin.observed_value["isAdmin"] is True

    # cursor advanced after a successful pass
    assert "last_run_at" in c.checkpoint().data

    # pagination followed nextLink
    get_urls = [u for m, u, _ in fake.calls if m == "GET"]
    assert len(get_urls) == 2
    assert "skiptoken" in get_urls[1]
