package gateway

// ErrorResponseDTO represents the standard gateway error response JSON schema.
type ErrorResponseDTO struct {
	Error     string `json:"error"`
	Code      string `json:"code,omitempty"`
	RequestID string `json:"request_id,omitempty"`
}

// UserDTO represents user profile information returned upon authentication.
type UserDTO struct {
	ID          string `json:"id"`
	Email       string `json:"email"`
	DisplayName string `json:"display_name"`
	Status      string `json:"status"`
}

// LoginResponseDTO represents the successful client login response JSON schema.
type LoginResponseDTO struct {
	AccessToken  string  `json:"access_token"`
	RefreshToken string  `json:"refresh_token"`
	TokenType    string  `json:"token_type"`
	ExpiresIn    int32   `json:"expires_in"`
	User         UserDTO `json:"user"`
}

// RegisterResponseDTO represents the successful client registration response JSON schema.
type RegisterResponseDTO struct {
	UserID      string `json:"user_id"`
	Email       string `json:"email"`
	DisplayName string `json:"display_name"`
	Status      string `json:"status"`
	CreatedAt   string `json:"created_at"`
}

// RefreshResponseDTO represents the successful client refresh response JSON schema.
type RefreshResponseDTO struct {
	AccessToken  string `json:"access_token"`
	RefreshToken string `json:"refresh_token"`
	TokenType    string `json:"token_type"`
	ExpiresIn    int32  `json:"expires_in"`
}

// LogoutResponseDTO represents the successful client logout response JSON schema.
type LogoutResponseDTO struct {
	Message string `json:"message"`
}

// VerifyEmailResponseDTO represents the successful client email verification response JSON schema.
type VerifyEmailResponseDTO struct {
	Message string `json:"message"`
}

// MeResponseDTO represents the authenticated user profile returned by GET /api/v1/me.
type MeResponseDTO struct {
	ID              string `json:"id,omitempty"`
	UserID          string `json:"user_id"`
	SessionID       string `json:"session_id,omitempty"`
	Kind            string `json:"kind"`
	Email           string `json:"email,omitempty"`
	DisplayName     string `json:"display_name,omitempty"`
	AvatarURL       string `json:"avatar_url,omitempty"`
	Status          string `json:"status,omitempty"`
	EmailVerified   bool   `json:"email_verified"`
	EmailVerifiedAt string `json:"email_verified_at,omitempty"`
	CreatedAt       string `json:"created_at,omitempty"`
}

// SessionInfoDTO represents an active session entry returned by GET /api/v1/auth/sessions.
type SessionInfoDTO struct {
	ID         string `json:"id"`
	UserAgent  string `json:"user_agent,omitempty"`
	IPAddress  string `json:"ip_address,omitempty"`
	CreatedAt  string `json:"created_at"`
	LastSeenAt string `json:"last_seen_at"`
	ExpiresAt  string `json:"expires_at"`
	Current    bool   `json:"current"`
}

// ListSessionsResponseDTO represents the response from GET /api/v1/auth/sessions.
type ListSessionsResponseDTO struct {
	Sessions []SessionInfoDTO `json:"sessions"`
}

// OrganizationDTO represents an organization returned by the gateway.
type OrganizationDTO struct {
	ID        string `json:"id"`
	Name      string `json:"name"`
	Slug      string `json:"slug"`
	RoleID    string `json:"role_id,omitempty"`
	CreatedAt string `json:"created_at,omitempty"`
	UpdatedAt string `json:"updated_at,omitempty"`
}

// APITokenDTO represents an API token returned by the gateway.
type APITokenDTO struct {
	ID              string   `json:"id"`
	OrgID           string   `json:"org_id"`
	CreatedByUserID string   `json:"created_by_user_id,omitempty"`
	Name            string   `json:"name"`
	TokenPrefix     string   `json:"token_prefix"`
	Permissions     []string `json:"permissions"`
	ExpiresAt       string   `json:"expires_at,omitempty"`
	LastUsedAt      string   `json:"last_used_at,omitempty"`
	CreatedAt       string   `json:"created_at,omitempty"`
}

// CreateAPITokenResponseDTO represents the response from POST /api/v1/orgs/{id}/tokens.
type CreateAPITokenResponseDTO struct {
	Token  APITokenDTO `json:"token"`
	Secret string      `json:"secret"`
}

// AuditEventDTO represents an audit event item returned by GET /api/v1/orgs/{id}/audit.
type AuditEventDTO struct {
	ID           string         `json:"id"`
	OrgID        string         `json:"org_id"`
	ActorUserID  string         `json:"actor_user_id,omitempty"`
	ActorType    string         `json:"actor_type"`
	Action       string         `json:"action"`
	ResourceType string         `json:"resource_type"`
	ResourceID   string         `json:"resource_id"`
	Metadata     map[string]any `json:"metadata,omitempty"`
	CreatedAt    string         `json:"created_at,omitempty"`
}

// ListAuditEventsResponseDTO represents the response from GET /api/v1/orgs/{id}/audit.
type ListAuditEventsResponseDTO struct {
	Events []AuditEventDTO `json:"events"`
}
