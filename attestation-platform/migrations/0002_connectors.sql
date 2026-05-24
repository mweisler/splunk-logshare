-- Phase 0: connector registry. A connector instance belongs to one INSURED org.
-- Secrets are never stored here -- only a pointer into the secret vault.

CREATE TYPE connector_status AS ENUM ('active', 'degraded', 'error', 'disabled');

CREATE TABLE connectors (
    id              uuid PRIMARY KEY DEFAULT gen_random_uuid(),
    insured_org_id  uuid NOT NULL REFERENCES orgs(id) ON DELETE CASCADE,
    connector_type  text NOT NULL,                 -- 'm365', 'sentinelone', 'noop', ...
    display_name    text NOT NULL,
    status          connector_status NOT NULL DEFAULT 'active',
    secret_ref      text,                          -- vault pointer, NOT the secret
    -- opaque resume token persisted between runs (the cloudflare.py checkpoint pattern)
    cursor          jsonb NOT NULL DEFAULT '{}'::jsonb,
    last_run_at     timestamptz,
    last_success_at timestamptz,
    created_at      timestamptz NOT NULL DEFAULT now()
);
CREATE INDEX idx_connectors_insured ON connectors(insured_org_id);
