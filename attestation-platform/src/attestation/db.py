"""Thin psycopg helpers. The app should connect as the non-owner ``attest_app``
role and set the per-request user so RLS applies (see migrations/0005_rls.sql)."""

from __future__ import annotations

from contextlib import contextmanager
from typing import Any, Iterator

from .config import database_url


def connect() -> Any:
    import psycopg

    return psycopg.connect(database_url())


@contextmanager
def request_scope(conn: Any, user_id: str | None) -> Iterator[Any]:
    """Bind the current user for RLS for the duration of the block."""
    # Postgres SET can't be parameterized; set_config() is the parameterized form.
    with conn.cursor() as cur:
        cur.execute("SELECT set_config('app.current_user_id', %s, false)", (user_id or "",))
    try:
        yield conn
    finally:
        with conn.cursor() as cur:
            cur.execute("RESET app.current_user_id")
