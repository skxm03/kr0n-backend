-- Backfill default organization for any user without an existing membership.
DO $$
DECLARE
    u RECORD;
    org_id UUID;
    mem_id UUID;
    org_name TEXT;
    base_slug TEXT;
    final_slug TEXT;
    counter INT;
BEGIN
    FOR u IN 
        SELECT users.id, users.display_name, users.email
        FROM users
        LEFT JOIN organization_memberships ON organization_memberships.user_id = users.id
        WHERE organization_memberships.id IS NULL
    LOOP
        org_id := gen_random_uuid();
        mem_id := gen_random_uuid();
        
        IF u.display_name IS NOT NULL AND LENGTH(TRIM(u.display_name)) > 0 THEN
            org_name := TRIM(u.display_name) || '''s org';
            base_slug := LOWER(REGEXP_REPLACE(TRIM(u.display_name), '[^a-zA-Z0-9]+', '-', 'g'));
        ELSE
            org_name := SPLIT_PART(u.email, '@', 1) || '''s org';
            base_slug := LOWER(REGEXP_REPLACE(SPLIT_PART(u.email, '@', 1), '[^a-zA-Z0-9]+', '-', 'g'));
        END IF;
        
        base_slug := TRIM(BOTH '-' FROM base_slug);
        IF LENGTH(base_slug) = 0 THEN
            base_slug := 'default';
        END IF;
        base_slug := SUBSTRING(base_slug FROM 1 FOR 45) || '-org';
        
        final_slug := base_slug;
        counter := 1;
        WHILE EXISTS (SELECT 1 FROM organizations WHERE slug = final_slug) LOOP
            final_slug := base_slug || '-' || counter;
            counter := counter + 1;
        END LOOP;

        INSERT INTO organizations (id, name, slug, created_at, updated_at)
        VALUES (org_id, org_name, final_slug, now(), now());

        INSERT INTO organization_memberships (id, organization_id, user_id, role_id, created_at, updated_at)
        VALUES (mem_id, org_id, u.id, 'owner', now(), now());
    END LOOP;
END $$;
