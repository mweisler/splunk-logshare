-- Item 2: the insurer-agnostic baseline questionnaire, plus the schema that
-- makes questionnaires first-class so we can ship pre-built carrier packs
-- (Cowbell, Coalition, ...) AND let partners/carriers author custom ones.
--
--   questionnaires       -- builtin (global) or custom (scoped to an org)
--   questionnaire_items  -- prompts, each optionally mapped to a control_key
--   questionnaire_answers(insured, key) -- derives answers from control_states

-- Patch/vulnerability management is its own area; extend the pillar enum.
-- (Runs as its own autocommitted statement, so later INSERTs can use the value.)
ALTER TYPE pillar ADD VALUE IF NOT EXISTS 'vuln';

-- --- controls referenced by the baseline that weren't seeded yet -----------
INSERT INTO control_definitions
    (control_key, title, pillar, aggregation, expression, grace_period_minutes, stale_after_minutes, severity)
VALUES
    ('identity.mfa_remote', 'MFA enforced for remote access', 'identity',
     'all', 'all remote access (VPN/RDP/webmail/SSO) requires MFA', 60, 1440, 'critical'),
    ('backup.tested', 'Backups encrypted, isolated, and restore-tested', 'backup',
     'all', 'last successful restore test within policy window', 1440, 10080, 'critical'),
    ('vuln.eol_software', 'No end-of-life software; patch SLA met', 'vuln',
     'threshold', 'eol_assets = 0 AND overdue_critical_patches = 0', 1440, 2880, 'high')
ON CONFLICT (control_key) DO NOTHING;

-- --- questionnaire schema --------------------------------------------------
CREATE TYPE questionnaire_origin AS ENUM ('builtin', 'custom');

CREATE TABLE questionnaires (
    id           uuid PRIMARY KEY DEFAULT gen_random_uuid(),
    key          text UNIQUE NOT NULL,              -- 'baseline-v1', 'coalition-2026', ...
    name         text NOT NULL,
    version      text NOT NULL DEFAULT '1',
    origin       questionnaire_origin NOT NULL DEFAULT 'builtin',
    -- NULL = global/builtin pack visible to everyone; otherwise the questionnaire
    -- is private to this org's subtree (a carrier's or MSP's custom questionnaire).
    owner_org_id uuid REFERENCES orgs(id) ON DELETE CASCADE,
    is_baseline  boolean NOT NULL DEFAULT false,
    created_at   timestamptz NOT NULL DEFAULT now()
);

CREATE TABLE questionnaire_items (
    id               uuid PRIMARY KEY DEFAULT gen_random_uuid(),
    questionnaire_id uuid NOT NULL REFERENCES questionnaires(id) ON DELETE CASCADE,
    item_key         text NOT NULL,
    category         text NOT NULL,
    prompt           text NOT NULL,
    -- NULL control_key => no automated signal yet; answered by manual attestation.
    control_key      text REFERENCES control_definitions(control_key),
    required         boolean NOT NULL DEFAULT true,
    weight           numeric(5,2) NOT NULL DEFAULT 1,
    sort_order       int NOT NULL DEFAULT 0,
    UNIQUE (questionnaire_id, item_key)
);
CREATE INDEX idx_qitems_questionnaire ON questionnaire_items(questionnaire_id);

-- Visibility for a custom questionnaire owned by org X: visible to users whose
-- membership lies on the SAME org branch as X, in either direction --
--   * ancestors of X (e.g. platform / a parent carrier) for oversight, and
--   * X and its subtree (the insureds the questionnaire is distributed to).
-- Builtin packs (owner_org_id IS NULL) are global. SECURITY DEFINER so the
-- check can read orgs/memberships regardless of RLS (avoids policy recursion).
CREATE OR REPLACE FUNCTION org_on_user_branch(owner uuid) RETURNS boolean AS $$
DECLARE
    uid   uuid := app_current_user_id();
    opath text;
BEGIN
    IF uid IS NULL THEN
        RETURN false;
    END IF;
    IF EXISTS (SELECT 1 FROM users WHERE id = uid AND is_platform_super) THEN
        RETURN true;
    END IF;
    SELECT path INTO opath FROM orgs WHERE id = owner;
    IF opath IS NULL THEN
        RETURN false;
    END IF;
    RETURN EXISTS (
        SELECT 1
        FROM memberships m
        JOIN orgs o ON o.id = m.org_id
        WHERE m.user_id = uid
          AND (opath LIKE o.path || '%'   -- user at/above owner
            OR o.path LIKE opath || '%')  -- user at/below owner
    );
END;
$$ LANGUAGE plpgsql STABLE SECURITY DEFINER;

CREATE OR REPLACE FUNCTION can_see_questionnaire(qid uuid) RETURNS boolean AS $$
    SELECT EXISTS (
        SELECT 1 FROM questionnaires q
        WHERE q.id = qid
          AND (q.owner_org_id IS NULL OR org_on_user_branch(q.owner_org_id))
    );
$$ LANGUAGE sql STABLE SECURITY DEFINER;

ALTER TABLE questionnaires      ENABLE ROW LEVEL SECURITY;
ALTER TABLE questionnaire_items ENABLE ROW LEVEL SECURITY;

CREATE POLICY questionnaires_visibility ON questionnaires
    USING (owner_org_id IS NULL OR org_on_user_branch(owner_org_id))
    WITH CHECK (owner_org_id IS NULL OR org_on_user_branch(owner_org_id));

CREATE POLICY qitems_visibility ON questionnaire_items
    USING (can_see_questionnaire(questionnaire_id))
    WITH CHECK (can_see_questionnaire(questionnaire_id));

-- --- seed the baseline pack ------------------------------------------------
INSERT INTO questionnaires (key, name, version, origin, is_baseline)
VALUES ('baseline-v1', 'Insurer-Agnostic Baseline', '1', 'builtin', true);

INSERT INTO questionnaire_items
    (questionnaire_id, item_key, category, prompt, control_key, required, sort_order)
SELECT q.id, v.item_key, v.category, v.prompt, v.control_key, v.required, v.sort_order
FROM questionnaires q,
(VALUES
    ('mfa.all_users',        'Identity & Access',   'Multi-factor authentication is enforced for all user accounts',                         'identity.mfa_enforced',         true,  1),
    ('mfa.privileged',       'Identity & Access',   'MFA is enforced for all administrative / privileged accounts',                          'identity.mfa_admins',           true,  2),
    ('mfa.remote',           'Identity & Access',   'MFA is enforced for all remote access (VPN, RDP, webmail, SSO)',                        'identity.mfa_remote',           true,  3),
    ('access.least_privilege','Identity & Access',  'Administrative accounts are inventoried and kept to a minimum',                         'identity.privileged_inventory', false, 4),
    ('edr.deployed',         'Endpoint',            'EDR / next-gen AV is deployed and healthy on all endpoints and servers',                'edr.coverage',                  true,  5),
    ('edr.tamper',           'Endpoint',            'EDR tamper protection is enabled on all agents',                                        'edr.tamper_protection',         false, 6),
    ('email.filtering',      'Email',               'Advanced email filtering / anti-phishing protection is enabled',                        'email.advanced_filtering',      true,  7),
    ('backup.tested',        'Resilience',          'Backups are encrypted, segregated/offline, and tested by periodic restore',             'backup.tested',                 true,  8),
    ('logging.centralized',  'Logging & Monitoring','Security logs are centrally collected and retained for at least 90 days',               'logging.centralized_retention', false, 9),
    ('vuln.patching',        'Vulnerability Mgmt',  'Critical patches applied within SLA; no end-of-life software in production',             'vuln.eol_software',             true,  10),
    ('training.awareness',   'Governance',          'Security awareness training including phishing simulations is conducted',               NULL,                            false, 11),
    ('ir.plan',              'Governance',          'A documented and tested incident response plan exists',                                 NULL,                            false, 12)
) AS v(item_key, category, prompt, control_key, required, sort_order)
WHERE q.key = 'baseline-v1';

-- --- derive questionnaire answers for an insured from current posture ------
-- Enumerates every item; left-joins the insured's control_states (RLS applies,
-- so the caller must be able to see the insured). Items with no control_key are
-- 'manual'; mapped controls with no facts yet are 'unknown'.
CREATE OR REPLACE FUNCTION questionnaire_answers(p_insured uuid, p_questionnaire text)
RETURNS TABLE (
    item_key     text,
    category     text,
    prompt       text,
    required     boolean,
    control_key  text,
    state        control_state_kind,
    coverage_pct numeric,
    answer       text
) AS $$
    SELECT qi.item_key, qi.category, qi.prompt, qi.required, qi.control_key,
           cs.state, cs.coverage_pct,
           CASE
               WHEN qi.control_key IS NULL          THEN 'manual'
               WHEN cs.state IS NULL                THEN 'unknown'
               WHEN cs.state = 'compliant'          THEN 'yes'
               WHEN cs.state IN ('drifted','degraded') THEN 'no'
               ELSE 'unknown'
           END AS answer
    FROM questionnaire_items qi
    JOIN questionnaires q ON q.id = qi.questionnaire_id AND q.key = p_questionnaire
    LEFT JOIN control_states cs
        ON cs.control_key = qi.control_key AND cs.insured_org_id = p_insured
    ORDER BY qi.sort_order;
$$ LANGUAGE sql STABLE;

-- Grant to the app role if it exists (created out-of-band per 0005_rls.sql).
DO $$ BEGIN
    IF EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'attest_app') THEN
        GRANT SELECT ON questionnaires, questionnaire_items TO attest_app;
        GRANT EXECUTE ON FUNCTION questionnaire_answers(uuid, text) TO attest_app;
        GRANT EXECUTE ON FUNCTION can_see_questionnaire(uuid) TO attest_app;
        GRANT EXECUTE ON FUNCTION org_on_user_branch(uuid) TO attest_app;
    END IF;
END $$;
