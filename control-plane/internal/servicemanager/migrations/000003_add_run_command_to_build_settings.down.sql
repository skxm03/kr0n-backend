ALTER TABLE project_build_settings
    DROP COLUMN IF EXISTS run_command,
    DROP COLUMN IF EXISTS run_command_override;
