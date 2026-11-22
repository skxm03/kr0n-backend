package domain

import (
	"errors"
	"time"

	"github.com/google/uuid"
)

var (
	// ErrInstallationNotFound is returned when an installation record does not exist.
	ErrInstallationNotFound = errors.New("github installation not found")
	// ErrInstallationAlreadyLinked indicates that the GitHub installation is already linked to another organization.
	ErrInstallationAlreadyLinked = errors.New("github installation is already linked to another organization")
	// ErrInvalidInstallation indicates invalid parameters for an installation.
	ErrInvalidInstallation = errors.New("invalid github installation")
)

// GitHubInstallation represents a connected GitHub App installation for an organization.
type GitHubInstallation struct {
	ID                  uuid.UUID
	OrganizationID      uuid.UUID
	InstallationID      int64
	AccountLogin        string
	AccountType         string
	RepositorySelection string
	Status              string
	CreatedByUserID     uuid.UUID
	CreatedAt           time.Time
	UpdatedAt           time.Time
}
