package migrations

import "embed"

// FS embeds all SQL migration files for the GitHub microservice.
//
//go:embed *.sql
var FS embed.FS
