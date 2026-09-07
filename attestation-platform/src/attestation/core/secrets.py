"""Secret resolution for connector credentials.

The connectors table stores a ``secret_ref`` -- a POINTER to the actual credential,
never the credential itself. This module turns that reference into a live secret
dict. Supported schemes:

  env:VAR_NAME     read a JSON blob from an environment variable (dev / CI)
  json:{...}       inline JSON (tests only)
  kms:<arn>        AWS KMS (TODO)
  vault:<path>     HashiCorp Vault (TODO)

Storing the reference rather than the material means rotating a client secret
requires no DB write, and the app process only holds the plaintext for the
duration of a run.
"""

from __future__ import annotations

import json
import os


class SecretResolutionError(RuntimeError):
    pass


def resolve_secret(secret_ref: str | None) -> dict[str, object]:
    if not secret_ref:
        return {}
    scheme, sep, rest = secret_ref.partition(":")
    if not sep:
        raise SecretResolutionError(f"secret_ref missing scheme: {secret_ref!r}")
    if scheme == "env":
        raw = os.environ.get(rest)
        if raw is None:
            raise SecretResolutionError(f"env var {rest} not set for secret_ref {secret_ref!r}")
        return _parse_json(raw, secret_ref)
    if scheme == "json":
        return _parse_json(rest, secret_ref)
    raise SecretResolutionError(f"unsupported secret_ref scheme: {scheme!r}")


def _parse_json(raw: str, secret_ref: str) -> dict[str, object]:
    try:
        data = json.loads(raw)
    except json.JSONDecodeError as e:
        raise SecretResolutionError(f"secret_ref {secret_ref!r} is not valid JSON: {e}") from None
    if not isinstance(data, dict):
        raise SecretResolutionError(f"secret_ref {secret_ref!r} must decode to an object")
    return data
