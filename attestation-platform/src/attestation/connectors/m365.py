"""Microsoft 365 (Graph) connector -- the first real integration.

Pulls the tenant's ``authenticationMethods/userRegistrationDetails`` report, which
already includes the ``isMfaRegistered`` and ``isAdmin`` flags per user, so a
single Graph call produces both ``identity.mfa_enforced`` and
``identity.mfa_admins`` facts. Uses OAuth 2.0 client credentials (app-only).

Required Graph application permissions (admin-consented in the customer tenant):
  - AuditLog.Read.All
  - UserAuthenticationMethod.Read.All

HTTP goes through an injectable ``GraphTransport`` so this connector is
unit-testable without any network. The default transport is stdlib
``urllib.request`` -- no third-party dependency is added.
"""

from __future__ import annotations

import datetime as dt
import json
import urllib.parse
import urllib.request
from collections.abc import Iterator
from typing import Any, Protocol

from ..core.models import ControlFact, Cursor, FactStatus, Pillar, Subject
from .base import CollectionContext, Connector, Session
from .registry import register


class GraphTransport(Protocol):
    def post_form(self, url: str, data: dict[str, str]) -> dict[str, Any]: ...
    def get_json(self, url: str, token: str) -> dict[str, Any]: ...


class _UrllibTransport:
    """Default transport: stdlib urllib. No dependencies added."""

    _TIMEOUT = 30

    def post_form(self, url: str, data: dict[str, str]) -> dict[str, Any]:
        body = urllib.parse.urlencode(data).encode("utf-8")
        req = urllib.request.Request(
            url,
            data=body,
            headers={
                "Content-Type": "application/x-www-form-urlencoded",
                "Accept": "application/json",
            },
            method="POST",
        )
        with urllib.request.urlopen(req, timeout=self._TIMEOUT) as resp:
            return json.loads(resp.read().decode("utf-8"))

    def get_json(self, url: str, token: str) -> dict[str, Any]:
        req = urllib.request.Request(
            url,
            headers={
                "Authorization": f"Bearer {token}",
                "Accept": "application/json",
            },
            method="GET",
        )
        with urllib.request.urlopen(req, timeout=self._TIMEOUT) as resp:
            return json.loads(resp.read().decode("utf-8"))


class _M365Session(Session):
    def __init__(self, tenant_id: str, token: str, transport: GraphTransport) -> None:
        self.tenant_id = tenant_id
        self.token = token
        self.transport = transport


@register
class M365Connector(Connector):
    connector_type = "m365"
    capabilities = frozenset({"identity.mfa_enforced", "identity.mfa_admins"})

    _TOKEN_URL_TMPL = "https://login.microsoftonline.com/{tenant}/oauth2/v2.0/token"
    _REPORT_URL = (
        "https://graph.microsoft.com/v1.0/reports/authenticationMethods/"
        "userRegistrationDetails"
    )
    _SCOPE = "https://graph.microsoft.com/.default"

    def __init__(self, transport: GraphTransport | None = None) -> None:
        self._transport: GraphTransport = transport or _UrllibTransport()
        self._cursor = Cursor()

    def authenticate(
        self, config: dict[str, Any], secret: dict[str, Any]
    ) -> Session:
        tenant_id = config.get("tenant_id")
        client_id = config.get("client_id")
        client_secret = secret.get("client_secret")
        missing = [k for k, v in (
            ("tenant_id (config)", tenant_id),
            ("client_id (config)", client_id),
            ("client_secret (secret)", client_secret),
        ) if not v]
        if missing:
            raise ValueError(f"m365 connector missing required fields: {', '.join(missing)}")

        resp = self._transport.post_form(
            self._TOKEN_URL_TMPL.format(tenant=urllib.parse.quote(tenant_id, safe="")),
            {
                "grant_type": "client_credentials",
                "client_id": client_id,
                "client_secret": client_secret,
                "scope": self._SCOPE,
            },
        )
        token = resp.get("access_token")
        if not token:
            raise RuntimeError("m365 token endpoint did not return an access_token")
        return _M365Session(tenant_id, token, self._transport)

    def discover(self, session: Session) -> list[Subject]:
        # Discover is currently informational; the coverage denominator comes
        # from the same report collect() reads, so we skip a redundant call.
        return []

    def collect(
        self, session: Session, cursor: Cursor, ctx: CollectionContext
    ) -> Iterator[ControlFact]:
        assert isinstance(session, _M365Session)
        url: str | None = self._REPORT_URL
        while url:
            page = session.transport.get_json(url, session.token)
            for entry in page.get("value", []):
                yield from self._facts_for(entry, ctx)
            url = page.get("@odata.nextLink")
        self._cursor = Cursor({"last_run_at": dt.datetime.now(dt.timezone.utc).isoformat()})

    def _facts_for(
        self, entry: dict[str, Any], ctx: CollectionContext
    ) -> Iterator[ControlFact]:
        user_id = entry.get("id") or entry.get("userPrincipalName") or "unknown"
        upn = entry.get("userPrincipalName") or user_id
        is_registered = bool(entry.get("isMfaRegistered"))
        is_admin = bool(entry.get("isAdmin"))
        subject = Subject("user", str(user_id), str(upn))
        status = FactStatus.PASS if is_registered else FactStatus.FAIL
        observed = {
            "isMfaRegistered": is_registered,
            "isMfaCapable": bool(entry.get("isMfaCapable")),
            "isAdmin": is_admin,
            "methodsRegistered": entry.get("methodsRegistered", []),
        }
        yield ctx.fact(
            pillar=Pillar.IDENTITY,
            control_key="identity.mfa_enforced",
            subject=subject,
            observed_value=observed,
            status=status,
        )
        if is_admin:
            yield ctx.fact(
                pillar=Pillar.IDENTITY,
                control_key="identity.mfa_admins",
                subject=subject,
                observed_value=observed,
                status=status,
            )

    def checkpoint(self) -> Cursor:
        return self._cursor
