-- Item 1: org-tree validation rules for the (confirmed) flexible typed tree.
-- Invariants:
--   * exactly one PLATFORM org, and it is the only root (parent_id IS NULL)
--   * INSURED is always a leaf -- nothing nests beneath it
--   * any non-root, non-PLATFORM node hangs under PLATFORM/PARTNER/CARRIER
-- This keeps the tree flexible (carrier-led and MSP-led books coexist) while
-- preventing nonsensical shapes.

CREATE OR REPLACE FUNCTION org_validate_hierarchy() RETURNS trigger AS $$
DECLARE
    parent_type org_type;
BEGIN
    -- single PLATFORM, and PLATFORM is always root
    IF NEW.type = 'PLATFORM' THEN
        IF NEW.parent_id IS NOT NULL THEN
            RAISE EXCEPTION 'PLATFORM org cannot have a parent';
        END IF;
        IF EXISTS (SELECT 1 FROM orgs WHERE type = 'PLATFORM' AND id <> NEW.id) THEN
            RAISE EXCEPTION 'only one PLATFORM org is allowed';
        END IF;
    ELSE
        IF NEW.parent_id IS NULL THEN
            RAISE EXCEPTION 'only a PLATFORM org may be a root; % needs a parent', NEW.type;
        END IF;
        SELECT type INTO parent_type FROM orgs WHERE id = NEW.parent_id;
        IF parent_type IS NULL THEN
            RAISE EXCEPTION 'parent org % does not exist', NEW.parent_id;
        END IF;
        IF parent_type = 'INSURED' THEN
            RAISE EXCEPTION 'INSURED is a leaf; cannot nest % beneath an INSURED', NEW.type;
        END IF;
    END IF;

    -- can't demote a node to INSURED while it still has children
    IF TG_OP = 'UPDATE' AND NEW.type = 'INSURED'
       AND EXISTS (SELECT 1 FROM orgs WHERE parent_id = NEW.id) THEN
        RAISE EXCEPTION 'cannot set org % to INSURED: it has child orgs', NEW.id;
    END IF;

    RETURN NEW;
END;
$$ LANGUAGE plpgsql;

-- Name sorts before trg_orgs_path so validation runs before path materialization.
CREATE TRIGGER trg_orgs_00_validate
    BEFORE INSERT OR UPDATE ON orgs
    FOR EACH ROW EXECUTE FUNCTION org_validate_hierarchy();
