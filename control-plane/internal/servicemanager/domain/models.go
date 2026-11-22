package domain

import (
	"errors"
	"path"
	"regexp"
	"strings"
	"time"

	"github.com/google/uuid"

	"github.com/skxm03/kr0n-backend/control-plane/pkg/authz"
)

var (
	ErrProjectNotFound       = errors.New("project not found")
	ErrProjectSlugConflict   = errors.New("project slug already exists in organization")
	ErrInvalidProject        = errors.New("invalid project configuration")
	ErrInvalidPreset         = errors.New("unsupported application preset")
	ErrInvalidRootDirectory  = errors.New("invalid root directory path")
	ErrInstallationNotLinked = errors.New("github installation is not linked or active for this organization")
	ErrRevisionConflict      = errors.New("project revision conflict: resource was modified by another request")
	ErrForbidden             = errors.New("insufficient permissions")
)

var (
	projectSlugRegex   = regexp.MustCompile(`^[a-z0-9]+(?:-[a-z0-9]+)*$`)
	nonSlugChars       = regexp.MustCompile(`[^a-z0-9]+`)
)

// Principal represents an authenticated caller forwarded by the API Gateway via CallerPrincipal.
type Principal = authz.Principal

// BuildSettings represents the 1:1 toggleable build settings row in `project_build_settings`.
// Each field has an explicit boolean override toggle so an empty string ("") with override=true
// is preserved as an intentional override rather than falling back to the preset default.
type BuildSettings struct {
	ProjectID               uuid.UUID
	InstallCommand          string
	InstallCommandOverride  bool
	BuildCommand            string
	BuildCommandOverride    bool
	OutputDirectory         string
	OutputDirectoryOverride bool
	UpdatedAt               time.Time
}

// Project represents an organization-scoped, repository-linked project in `projects`
// paired with its 1:1 `BuildSettings`.
type Project struct {
	ID                   uuid.UUID
	OrganizationID       uuid.UUID
	Name                 string
	Slug                 string
	Description          string
	GitHubInstallationID int64
	RepoID               *int64
	RepoOwner            string
	RepoName             string
	ProductionBranch     string
	RootDirectory        string
	ApplicationPreset    string
	Revision             int64
	CreatedByUserID      *uuid.UUID
	CreatedAt            time.Time
	UpdatedAt            time.Time
	BuildSettings        BuildSettings
}

// RepoFullName returns `<repo_owner>/<repo_name>`.
func (p Project) RepoFullName() string {
	return p.RepoOwner + "/" + p.RepoName
}

// ValidateProjectSlug checks that slug is 2..63 lowercase alphanumeric characters separated by single hyphens.
func ValidateProjectSlug(slug string) bool {
	return len(slug) >= 2 && len(slug) <= 63 && projectSlugRegex.MatchString(slug)
}

// DeriveProjectSlug generates a URL-safe slug from a project name or repository name.
func DeriveProjectSlug(name string) string {
	s := strings.ToLower(strings.TrimSpace(name))
	s = nonSlugChars.ReplaceAllString(s, "-")
	s = strings.Trim(s, "-")
	if len(s) > 63 {
		s = strings.Trim(s[:63], "-")
	}
	if len(s) == 1 {
		s = s + "-app"
	}
	return s
}

// NormalizeRootDirectory converts a user-supplied root directory into a canonical path
// starting with "/" (e.g. "" or "." -> "/", "apps/web/" -> "/apps/web") and rejects
// path traversal (".."), control characters, or backslashes.
func NormalizeRootDirectory(raw string) (string, error) {
	trimmed := strings.TrimSpace(raw)
	if trimmed == "" || trimmed == "." || trimmed == "/" || trimmed == "./" {
		return "/", nil
	}
	if strings.Contains(trimmed, "\\") || strings.ContainsAny(trimmed, "\x00\r\n") {
		return "", ErrInvalidRootDirectory
	}
	for _, seg := range strings.Split(trimmed, "/") {
		if seg == ".." {
			return "", ErrInvalidRootDirectory
		}
	}
	cleaned := path.Clean("/" + strings.TrimLeft(trimmed, "./"))
	if !strings.HasPrefix(cleaned, "/") || strings.Contains(cleaned, "..") {
		return "", ErrInvalidRootDirectory
	}
	return cleaned, nil
}
