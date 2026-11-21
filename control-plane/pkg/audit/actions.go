package audit

import (
	"encoding/json"
	"fmt"
	"strings"
)

// Action identifies a canonical, audit-logged business operation.
type Action string

const (
	// Service Manager actions
	ActionProjectCreated              Action = "project.created"
	ActionProjectUpdated              Action = "project.updated"
	ActionProjectBuildSettingsUpdated Action = "project.build_settings_updated"
	ActionProjectDeleted              Action = "project.deleted"

	// Secrets & Vault actions
	ActionProjectEnvVarsUpserted      Action = "project.env_vars_upserted"
	ActionProjectEnvVarDeleted        Action = "project.env_var_deleted"

	// Auth & User Identity actions
	ActionUserRegistered              Action = "user.registered"
	ActionUserLogin                   Action = "user.login"
	ActionUserLoginFailed             Action = "user.login_failed"
	ActionUserLogout                  Action = "user.logout"
	ActionUserPasswordResetRequested  Action = "user.password_reset_requested"
	ActionUserPasswordReset           Action = "user.password_reset"
	ActionUserPasswordResetConfirmed  Action = "user.password_reset_confirmed"
	ActionUserPasswordChanged         Action = "user.password_changed"
	ActionUserEmailVerified           Action = "user.email_verified"
	ActionUserSessionRevoked          Action = "user.session_revoked"
	ActionUserOAuthLinked             Action = "user.oauth_linked"

	// Auth & Multi-tenant Organization actions
	ActionOrgCreated                  Action = "org.created"
	ActionOrgUpdated                  Action = "org.updated"
	ActionOrgDeleted                  Action = "org.deleted"
	ActionOrgMemberInvited            Action = "org.member.invited"
	ActionOrgMemberAdded              Action = "org.member.added"
	ActionOrgMemberRemoved            Action = "org.member.removed"
	ActionOrgMemberRoleUpdated        Action = "org.member.role_updated"
	ActionOrgInviteRevoked            Action = "org.invite.revoked"
	ActionOrgInviteAccepted           Action = "org.invite.accepted"

	// Auth & Automation API Tokens
	ActionAPITokenCreated             Action = "apitoken.created"
	ActionAPITokenRevoked             Action = "apitoken.revoked"

	// GitHub VCS integration actions
	ActionGitHubInstallationConnected    Action = "github.installation_connected"
	ActionGitHubInstallationDisconnected Action = "github.installation_disconnected"
	ActionGitHubInstallationRemoved      Action = "github.installation_removed"
	ActionGitHubInstallationSuspended    Action = "github.installation_suspended"
	ActionGitHubInstallationUnsuspended  Action = "github.installation_unsuspended"
	ActionGitHubWebhookReceived          Action = "github.webhook_received"

	// Perimeter Transport actions
	ActionHTTPRequest                 Action = "gateway.http.request"
	ActionHTTPGet                     Action = "gateway.http.get"
	ActionHTTPPost                    Action = "gateway.http.post"
	ActionHTTPPut                     Action = "gateway.http.put"
	ActionHTTPDelete                  Action = "gateway.http.delete"
	ActionHTTPPatch                   Action = "gateway.http.patch"
	ActionGRPCCall                    Action = "grpc.call"
)

// ActionHTTPMethod returns the canonical action for an HTTP method.
func ActionHTTPMethod(method string) Action {
	return Action("gateway.http." + strings.ToLower(method))
}

// String returns the string representation of an Action.
func (a Action) String() string {
	return string(a)
}

// Target resource type constants.
const (
	TargetTypeProject            = "project"
	TargetTypeOrg                = "organization"
	TargetTypeUser               = "user"
	TargetTypeAPIToken           = "api_token"
	TargetTypeOrgMember          = "org_member"
	TargetTypeOrgInvite          = "org_invite"
	TargetTypeGitHubInstallation = "github_installation"
	TargetTypeHTTPRoute          = "http_route"
	TargetTypeGRPCMethod         = "grpc_method"
)

// Service name constants.
const (
	ServiceAuth           = "auth"
	ServiceGateway        = "gateway"
	ServiceServiceManager = "servicemanager"
	ServiceSecrets        = "secrets"
	ServiceGitHub         = "github"
	ServiceMailer         = "mailer"
	ServiceAudit          = "audit"
)

// ProjectCreatedPayload captures typed metadata for project creation.
type ProjectCreatedPayload struct {
	Slug              string `json:"slug"`
	RepoFullName      string `json:"repo_full_name,omitempty"`
	ProductionBranch  string `json:"production_branch"`
	RootDirectory     string `json:"root_directory,omitempty"`
	ApplicationPreset string `json:"application_preset"`
	Revision          int64  `json:"revision"`
}

// ProjectUpdatedPayload captures typed metadata for project mutations.
type ProjectUpdatedPayload struct {
	Slug              string `json:"slug"`
	ProductionBranch  string `json:"production_branch,omitempty"`
	RootDirectory     string `json:"root_directory,omitempty"`
	ApplicationPreset string `json:"application_preset,omitempty"`
	Revision          int64  `json:"revision"`
}

// ProjectBuildSettingsUpdatedPayload captures typed metadata for build setting toggles.
type ProjectBuildSettingsUpdatedPayload struct {
	Slug                    string `json:"slug"`
	InstallCommandOverride  bool   `json:"install_command_override"`
	BuildCommandOverride    bool   `json:"build_command_override"`
	OutputDirectoryOverride bool   `json:"output_directory_override"`
	Revision                int64  `json:"revision"`
}

// ProjectDeletedPayload captures typed metadata for project deletion.
type ProjectDeletedPayload struct {
	ProjectID string `json:"project_id"`
	Slug      string `json:"slug,omitempty"`
}

// OrgMemberPayload captures typed metadata for organization membership operations.
type OrgMemberPayload struct {
	UserID string `json:"user_id,omitempty"`
	Email  string `json:"email,omitempty"`
	Role   string `json:"role"`
}

// APITokenPayload captures typed metadata for API token creation/revocation.
type APITokenPayload struct {
	TokenID     string   `json:"token_id,omitempty"`
	Name        string   `json:"name,omitempty"`
	TokenPrefix string   `json:"token_prefix,omitempty"`
	Scopes      []string `json:"scopes,omitempty"`
	Permissions []string `json:"permissions,omitempty"`
}

// UserAuthPayload captures typed metadata for user authentication and lifecycle events.
type UserAuthPayload struct {
	Email          string `json:"email,omitempty"`
	Provider       string `json:"provider,omitempty"`
	ProviderUserID string `json:"provider_user_id,omitempty"`
}

// OrgInvitePayload captures typed metadata for invitation lifecycle events.
type OrgInvitePayload struct {
	InviteID string `json:"invite_id,omitempty"`
	Email    string `json:"email,omitempty"`
	RoleID   string `json:"role_id,omitempty"`
}

// HTTPRequestPayload captures typed metadata for API Gateway HTTP audit logging.
type HTTPRequestPayload struct {
	Method        string `json:"method"`
	Path          string `json:"path"`
	RoutePattern  string `json:"route_pattern,omitempty"`
	Status        int    `json:"status"`
	DurationMs    int64  `json:"duration_ms"`
	TokenID       string `json:"token_id,omitempty"`
	SessionID     string `json:"session_id,omitempty"`
	PrincipalKind string `json:"principal_kind,omitempty"`
}

// ToMetadata converts any typed payload into a map[string]any suitable for Event.Metadata.
func ToMetadata(v any) (map[string]any, error) {
	if v == nil {
		return map[string]any{}, nil
	}
	if m, ok := v.(map[string]any); ok {
		return m, nil
	}
	data, err := json.Marshal(v)
	if err != nil {
		return nil, fmt.Errorf("marshal audit payload: %w", err)
	}
	var out map[string]any
	if err := json.Unmarshal(data, &out); err != nil {
		return nil, fmt.Errorf("unmarshal audit metadata map: %w", err)
	}
	return out, nil
}
