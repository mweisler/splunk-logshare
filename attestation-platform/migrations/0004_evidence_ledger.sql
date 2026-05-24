-- Phase 0: tamper-evident evidence ledger.
-- One independent, per-insured hash chain. Each entry links to the previous via
-- prev_hash and is signed. This table doubles as the insured's "centralized
-- logging + retention" control evidence, so an SMB needs no separate SIEM.

CREATE TYPE ledger_entry_type AS ENUM (
    'fact', 'state_change', 'drift', 'attestation', 'connector_health'
);

CREATE TABLE evidence_ledger (
    id             uuid PRIMARY KEY DEFAULT gen_random_uuid(),
    insured_org_id uuid NOT NULL REFERENCES orgs(id) ON DELETE RESTRICT,
    seq            bigint NOT NULL,                 -- per-insured monotonic sequence
    prev_hash      text NOT NULL,                   -- previous entry_hash (genesis sentinel for seq 0)
    entry_hash     text NOT NULL,                   -- sha256(prev_hash + type + canonical(payload))
    entry_type     ledger_entry_type NOT NULL,
    payload        jsonb NOT NULL,
    signature      text,                            -- base64 signature over entry_hash
    signer_key_id  text,                            -- e.g. 'kms://.../v3' or 'local-dev'
    created_at     timestamptz NOT NULL DEFAULT now(),
    UNIQUE (insured_org_id, seq),
    UNIQUE (insured_org_id, entry_hash)
);
CREATE INDEX idx_ledger_insured_seq ON evidence_ledger(insured_org_id, seq);

-- Append-only: reject any UPDATE or DELETE at the database level.
CREATE OR REPLACE FUNCTION ledger_no_mutate() RETURNS trigger AS $$
BEGIN
    RAISE EXCEPTION 'evidence_ledger is append-only';
END;
$$ LANGUAGE plpgsql;

CREATE TRIGGER trg_ledger_no_mutate
    BEFORE UPDATE OR DELETE ON evidence_ledger
    FOR EACH ROW EXECUTE FUNCTION ledger_no_mutate();
