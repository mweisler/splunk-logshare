-- Phase 0: seed the MVP control taxonomy. questionnaire_refs are placeholders
-- until the first real carrier questionnaire is mapped (Phase 2).

INSERT INTO control_definitions
    (control_key, title, pillar, aggregation, expression, grace_period_minutes, stale_after_minutes, severity, questionnaire_refs)
VALUES
    ('identity.mfa_enforced', 'MFA enforced for all users', 'identity',
     'ratio', 'users_mfa_enforced / users_total >= 1.0', 60, 1440, 'critical',
     '["mfa.all_users"]'::jsonb),

    ('identity.mfa_admins', 'MFA enforced for all privileged accounts', 'identity',
     'all', 'every admin account has MFA enforced', 0, 1440, 'critical',
     '["mfa.admins"]'::jsonb),

    ('identity.privileged_inventory', 'Privileged account count within policy', 'identity',
     'threshold', 'admin_count <= max_admins', 1440, 2880, 'medium',
     '["access.least_privilege"]'::jsonb),

    ('edr.coverage', 'EDR healthy on all known endpoints', 'edr',
     'ratio', 'healthy_agents / known_assets >= 1.0', 360, 1440, 'critical',
     '["edr.deployed_all"]'::jsonb),

    ('edr.tamper_protection', 'EDR tamper protection enabled', 'edr',
     'all', 'every agent has tamper protection on', 360, 1440, 'high',
     '["edr.tamper"]'::jsonb),

    ('email.advanced_filtering', 'Advanced email filtering / anti-phishing on', 'email',
     'all', 'anti-phish, URL and attachment protection policies enabled', 60, 1440, 'high',
     '["email.filtering"]'::jsonb),

    ('logging.centralized_retention', 'Centralized logging retained >= 90 days', 'logging',
     'threshold', 'evidence_retention_days >= 90', 0, 2880, 'high',
     '["logging.retention"]'::jsonb),

    ('logging.feed_liveness', 'All connectors reporting within freshness window', 'logging',
     'freshness', 'every active connector reported within its stale window', 60, 720, 'medium',
     '["logging.monitoring"]'::jsonb);
