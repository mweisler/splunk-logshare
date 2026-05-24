"""Minimal env-based config. Promote to pydantic-settings when the API lands."""

from __future__ import annotations

import os


def database_url() -> str:
    url = os.environ.get("DATABASE_URL")
    if not url:
        raise RuntimeError("DATABASE_URL is not set (see .env.example)")
    return url
