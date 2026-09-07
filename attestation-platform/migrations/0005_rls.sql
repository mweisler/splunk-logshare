-- Phase 0: row-level security. Tenant isolation is enforced in the database,
-- not just the app layer.
--
-- Deployment note: the application must connect as a NON-OWNER login role
-- (RLS does not apply to a table's owner unless FORCE is set). can_access_org()
-- is SECURITY DEFINER, so it can still read orgs/memberships/users to make the
-- decision. Create a dedicated app role and grant it DML:
--
--     CREATE ROLE attest_app LOGIN PASSWORD '...';
--     GRANT SELECT, INSERT, UPDATE, DELETE ON ALL TABLES IN SCHEMA public TO attest_app;
--     GRANT USAGE ON ALL SEQUENCES IN SCHEMA public TO attest_app;
--
-- Then per request:  SET app.current_user_id = '<user-uuid>';

ALTER TABLE connectors      ENABLE ROW LEVEL SECURITY;
ALTER TABLE control_facts   ENABLE ROW LEVEL SECURITY;
ALTER TABLE control_states  ENABLE ROW LEVEL SECURITY;
ALTER TABLE drift_events    ENABLE ROW LEVEL SECURITY;
ALTER TABLE evidence_ledger ENABLE ROW LEVEL SECURITY;

CREATE POLICY connectors_isolation ON connectors
    USING (can_access_org(insured_org_id))
    WITH CHECK (can_access_org(insured_org_id));

CREATE POLICY control_facts_isolation ON control_facts
    USING (can_access_org(insured_org_id))
    WITH CHECK (can_access_org(insured_org_id));

CREATE POLICY control_states_isolation ON control_states
    USING (can_access_org(insured_org_id))
    WITH CHECK (can_access_org(insured_org_id));

CREATE POLICY drift_events_isolation ON drift_events
    USING (can_access_org(insured_org_id))
    WITH CHECK (can_access_org(insured_org_id));

CREATE POLICY evidence_ledger_isolation ON evidence_ledger
    USING (can_access_org(insured_org_id))
    WITH CHECK (can_access_org(insured_org_id));

-- Carrier-safe projection: control posture WITHOUT raw subjects/PII.
-- The API serves this to CARRIER_ADMIN roles instead of control_states/facts.
-- (RLS on the underlying table still scopes rows to the carrier's book.)
CREATE VIEW carrier_control_states AS
SELECT insured_org_id,
       control_key,
       state,
       coverage_pct,
       last_evaluated,
       drift_since
FROM control_states;
