CREATE TABLE project_build_settings (
    project_id UUID PRIMARY KEY REFERENCES projects(id) ON DELETE CASCADE,
    install_command TEXT NOT NULL DEFAULT '',
    install_command_override BOOLEAN NOT NULL DEFAULT FALSE,
    build_command TEXT NOT NULL DEFAULT '',
    build_command_override BOOLEAN NOT NULL DEFAULT FALSE,
    output_directory TEXT NOT NULL DEFAULT '',
    output_directory_override BOOLEAN NOT NULL DEFAULT FALSE,
    updated_at TIMESTAMPTZ NOT NULL DEFAULT now()
);
