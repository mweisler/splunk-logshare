-- RLS was Phase-0-scoped to tenant DATA tables (facts, states, drift, ledger).
-- The org tree itself, memberships and users were left open -- which is fine for
-- background jobs running as owner, but the client-portal API connects as the
-- non-owner ``attest_app`` role and needs the tree scoped too. Otherwise a
-- signed-in insured admin can list every carrier's insureds.
--
-- Policies use the same ``can_access_org`` predicate the data tables use, so
-- the visibility model is consistent: you see an org iff you have membership
-- at some ancestor (or the org itself), or you are a platform super-admin.

ALTER TABLE orgs        ENABLE ROW LEVEL SECURITY;
ALTER TABLE memberships ENABLE ROW LEVEL SECURITY;
ALTER TABLE users       ENABLE ROW LEVEL SECURITY;

CREATE POLICY orgs_visibility ON orgs
    USING (can_access_org(id))
    WITH CHECK (can_access_org(id));

-- Each user sees their own memberships (needed by /me) and any membership on
-- orgs they can access (needed for admin views showing "who's on this org").
CREATE POLICY memberships_visibility ON memberships
    USING (user_id = app_current_user_id() OR can_access_org(org_id))
    WITH CHECK (user_id = app_current_user_id() OR can_access_org(org_id));

-- Users see themselves only. Widening this (peer visibility for admins) would
-- introduce a self-referential policy, so it needs a SECURITY DEFINER helper --
-- keep it simple for now: /me is a self-lookup and needs nothing more.
CREATE POLICY users_self_visibility ON users
    USING (id = app_current_user_id());
