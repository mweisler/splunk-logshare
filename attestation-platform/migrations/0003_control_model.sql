-- Phase 0: the normalized control model.
--   control_definitions  -- the rules + the bridge to carrier questionnaires
--   control_facts        -- atomic normalized observations from connectors
--   control_states       -- rolled-up current posture per (insured, control)
--   drift_events         -- transitions that fire alerts / get recorded as evidence

CREATE TYPE pillar             AS ENUM ('edr', 'identity', 'email', 'logging', 'backup');
CREATE TYPE fact_status        AS ENUM ('pass', 'fail', 'degraded', 'unknown');
CREATE TYPE control_state_kind AS ENUM ('compliant', 'drifted', 'degraded', 'unknown', 'stale');

CREATE TABLE control_definitions (
    control_key          text PRIMARY KEY,            -- 'identity.mfa_enforced'
    title                text NOT NULL,
    pillar               pillar NOT NULL,
    -- maps this control to specific carrier questionnaire items, e.g.
    -- ["coalition.q.mfa_all", "atbay.q3"]
    questionnaire_refs   jsonb NOT NULL DEFAULT '[]'::jsonb,
    aggregation          text NOT NULL,               -- ratio|all|any|threshold|freshness
    expression           text NOT NULL,               -- human/DSL form of the pass condition
    grace_period_minutes int  NOT NULL DEFAULT 0,     -- debounce before declaring drift
    stale_after_minutes  int  NOT NULL DEFAULT 1440,  -- no fresh fact => state goes 'stale'
    severity             text NOT NULL DEFAULT 'medium'
);

CREATE TABLE control_facts (
    fact_id           uuid PRIMARY KEY DEFAULT gen_random_uuid(),
    insured_org_id    uuid NOT NULL REFERENCES orgs(id) ON DELETE CASCADE,
    connector_id      uuid NOT NULL REFERENCES connectors(id) ON DELETE CASCADE,
    connector_type    text NOT NULL,
    pillar            pillar NOT NULL,
    control_key       text NOT NULL REFERENCES control_definitions(control_key),
    subject           jsonb NOT NULL,                 -- {type,id,label}
    observed_value    jsonb NOT NULL,
    status            fact_status NOT NULL,
    source_event_time timestamptz,                    -- vendor's timestamp, if any
    collected_at      timestamptz NOT NULL DEFAULT now(),
    evidence_ref      text,                           -- sha256 pointer to raw payload
    collector_run_id  uuid NOT NULL
);
CREATE INDEX idx_facts_insured_control ON control_facts(insured_org_id, control_key, collected_at DESC);
CREATE INDEX idx_facts_run             ON control_facts(collector_run_id);

CREATE TABLE control_states (
    insured_org_id   uuid NOT NULL REFERENCES orgs(id) ON DELETE CASCADE,
    control_key      text NOT NULL REFERENCES control_definitions(control_key),
    state            control_state_kind NOT NULL DEFAULT 'unknown',
    coverage_pct     numeric(5,4),                    -- e.g. 0.9700
    failing_subjects jsonb NOT NULL DEFAULT '[]'::jsonb,
    last_evaluated   timestamptz,
    drift_since      timestamptz,
    PRIMARY KEY (insured_org_id, control_key)
);

CREATE TABLE drift_events (
    event_id         uuid PRIMARY KEY DEFAULT gen_random_uuid(),
    insured_org_id   uuid NOT NULL REFERENCES orgs(id) ON DELETE CASCADE,
    control_key      text NOT NULL REFERENCES control_definitions(control_key),
    from_state       control_state_kind NOT NULL,
    to_state         control_state_kind NOT NULL,
    severity         text NOT NULL,
    root_cause_facts jsonb NOT NULL DEFAULT '[]'::jsonb,
    detected_at      timestamptz NOT NULL DEFAULT now(),
    resolved_at      timestamptz
);
CREATE INDEX idx_drift_insured ON drift_events(insured_org_id, detected_at DESC);
