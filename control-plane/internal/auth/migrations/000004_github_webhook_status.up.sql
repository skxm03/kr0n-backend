ALTER TABLE github_installations
    DROP CONSTRAINT IF EXISTS github_installations_status_check;

ALTER TABLE github_installations
    ADD CONSTRAINT github_installations_status_check
    CHECK (status IN ('active', 'suspended', 'uninstalled', 'deleted'));
