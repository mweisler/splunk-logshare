-- Non-secret connector config lives on the row (tenant id, endpoint overrides,
-- feature toggles) alongside the vault pointer. Secrets stay out; this column
-- is safe to log and back up. jsonb so per-connector shapes can evolve without
-- schema churn.

ALTER TABLE connectors
    ADD COLUMN config jsonb NOT NULL DEFAULT '{}'::jsonb;
