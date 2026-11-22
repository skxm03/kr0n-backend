package migrations

import "embed"

// FS embeds all SQL migration files for the Service Manager microservice.
//
//go:embed *.sql
var FS embed.FS
