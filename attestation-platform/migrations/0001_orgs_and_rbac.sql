-- Phase 0: org tree + RBAC.
-- The org tree is typed and arbitrary-depth so a carrier-led book and an
-- MSP/broker-led book coexist. Connectors and all tenant data attach to an
-- INSURED node; every node above it is a roll-up view.

CREATE EXTENSION IF NOT EXISTS pgcrypto;   -- gen_random_uuid()
CREATE EXTENSION IF NOT EXISTS citext;      -- case-insensitive email

CREATE TYPE org_type AS ENUM ('PLATFORM', 'PARTNER', 'CARRIER', 'INSURED');

CREATE TABLE orgs (
    id         uuid PRIMARY KEY DEFAULT gen_random_uuid(),
    parent_id  uuid REFERENCES orgs(id) ON DELETE RESTRICT,
    type       org_type NOT NULL,
    name       text NOT NULL,
    -- materialized path of ids, '/<root>/<child>/...', maintained by trigger.
    -- Subtree queries become a cheap prefix match.
    path       text NOT NULL DEFAULT '',
    created_at timestamptz NOT NULL DEFAULT now()
);
CREATE INDEX idx_orgs_parent ON orgs(parent_id);
CREATE INDEX idx_orgs_path   ON orgs(path text_pattern_ops);

-- Column DEFAULTs are applied before BEFORE-INSERT triggers, so NEW.id exists.
-- NOTE: reparenting (UPDATE parent_id) must rebuild the subtree's paths; out of
-- scope for Phase 0 (orgs are not moved yet).
CREATE OR REPLACE FUNCTION orgs_set_path() RETURNS trigger AS $$
BEGIN
    IF NEW.parent_id IS NULL THEN
        NEW.path := '/' || NEW.id::text;
    ELSE
        SELECT path || '/' || NEW.id::text INTO NEW.path
        FROM orgs WHERE id = NEW.parent_id;
    END IF;
    RETURN NEW;
END;
$$ LANGUAGE plpgsql;

CREATE TRIGGER trg_orgs_path BEFORE INSERT ON orgs
    FOR EACH ROW EXECUTE FUNCTION orgs_set_path();

CREATE TABLE users (
    id                uuid PRIMARY KEY DEFAULT gen_random_uuid(),
    email             citext UNIQUE NOT NULL,
    display_name      text,
    -- platform super admin bypasses org scoping entirely (the master admin).
    is_platform_super boolean NOT NULL DEFAULT false,
    created_at        timestamptz NOT NULL DEFAULT now()
);

CREATE TYPE role_name AS ENUM (
    'PLATFORM_SUPER_ADMIN', 'PLATFORM_OPERATOR',
    'PARTNER_ADMIN', 'CARRIER_ADMIN', 'INSURED_ADMIN', 'INSURED_VIEWER'
);

-- A membership grants a role at an org node; it implicitly covers that node's
-- whole subtree (a PARTNER_ADMIN on an MSP org sees all insureds beneath it).
CREATE TABLE memberships (
    id         uuid PRIMARY KEY DEFAULT gen_random_uuid(),
    user_id    uuid NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    org_id     uuid NOT NULL REFERENCES orgs(id) ON DELETE CASCADE,
    role       role_name NOT NULL,
    created_at timestamptz NOT NULL DEFAULT now(),
    UNIQUE (user_id, org_id, role)
);
CREATE INDEX idx_memberships_user ON memberships(user_id);
CREATE INDEX idx_memberships_org  ON memberships(org_id);

-- ---------------------------------------------------------------------------
-- Access helpers used by row-level security (see 0005_rls.sql).
-- The current user id is set per request: SET app.current_user_id = '<uuid>'.
-- ---------------------------------------------------------------------------
CREATE OR REPLACE FUNCTION app_current_user_id() RETURNS uuid AS $$
    SELECT NULLIF(current_setting('app.current_user_id', true), '')::uuid;
$$ LANGUAGE sql STABLE;

-- True if the current user may see the given org (and thus its insured data).
-- SECURITY DEFINER so it can read users/memberships/orgs regardless of RLS.
CREATE OR REPLACE FUNCTION can_access_org(target uuid) RETURNS boolean AS $$
DECLARE
    uid   uuid := app_current_user_id();
    tpath text;
BEGIN
    IF uid IS NULL THEN
        RETURN false;
    END IF;
    IF EXISTS (SELECT 1 FROM users WHERE id = uid AND is_platform_super) THEN
        RETURN true;
    END IF;
    SELECT path INTO tpath FROM orgs WHERE id = target;
    IF tpath IS NULL THEN
        RETURN false;
    END IF;
    -- accessible if the user holds a membership at or above the target org
    RETURN EXISTS (
        SELECT 1
        FROM memberships m
        JOIN orgs o ON o.id = m.org_id
        WHERE m.user_id = uid
          AND tpath LIKE o.path || '%'
    );
END;
$$ LANGUAGE plpgsql STABLE SECURITY DEFINER;
