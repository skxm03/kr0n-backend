package gateway

import (
	"encoding/json"
	"net/http"
	"strconv"
	"strings"
	"time"

	authv1 "github.com/skxm03/kr0n-backend/control-plane/gen/auth/v1"
	"github.com/skxm03/kr0n-backend/control-plane/internal/config"
	"github.com/skxm03/kr0n-backend/control-plane/internal/gateway/middleware"
)

// RoleDTO represents a role and its permissions.
type RoleDTO struct {
	ID          string   `json:"id"`
	Name        string   `json:"name"`
	Description string   `json:"description,omitempty"`
	Permissions []string `json:"permissions"`
}

// ListRolesResponseDTO represents the response from GET /api/v1/roles.
type ListRolesResponseDTO struct {
	Roles []RoleDTO `json:"roles"`
}

// CreateOrgRequestDTO represents the request body for POST /api/v1/orgs.
type CreateOrgRequestDTO struct {
	Name string `json:"name"`
	Slug string `json:"slug"`
}

// UpdateOrgRequestDTO represents the request body for PATCH /api/v1/orgs/{id}.
type UpdateOrgRequestDTO struct {
	Name string `json:"name"`
}

// OrganizationDTO represents an organization returned by the gateway.
type OrganizationDTO struct {
	ID        string `json:"id"`
	Name      string `json:"name"`
	Slug      string `json:"slug"`
	RoleID    string `json:"role_id,omitempty"`
	CreatedAt string `json:"created_at"`
	UpdatedAt string `json:"updated_at"`
}

// ListOrgsResponseDTO represents the response from GET /api/v1/orgs.
type ListOrgsResponseDTO struct {
	Organizations []OrganizationDTO `json:"organizations"`
}

// MemberDTO represents an organization member.
type MemberDTO struct {
	UserID      string `json:"user_id"`
	Email       string `json:"email"`
	DisplayName string `json:"display_name"`
	RoleID      string `json:"role_id"`
	CreatedAt   string `json:"created_at"`
}

// ListMembersResponseDTO represents the response from GET /api/v1/orgs/{id}/members.
type ListMembersResponseDTO struct {
	Members []MemberDTO `json:"members"`
}

// AddMemberRequestDTO represents the request body for POST /api/v1/orgs/{id}/members.
type AddMemberRequestDTO struct {
	Email  string `json:"email"`
	RoleID string `json:"role_id"`
}

// UpdateMemberRoleRequestDTO represents the request body for PATCH /api/v1/orgs/{id}/members/{user_id}.
type UpdateMemberRoleRequestDTO struct {
	RoleID string `json:"role_id"`
}

// CreateInviteRequestDTO represents the request body for POST /api/v1/orgs/{id}/invites.
type CreateInviteRequestDTO struct {
	Email  string `json:"email"`
	RoleID string `json:"role_id"`
}

// InviteResponseDTO represents the response from POST /api/v1/orgs/{id}/invites.
// Token is only populated when KR0N_ENV is development/test; in staging/production the raw token
// is delivered out-of-band via email and omitted from the API response.
type InviteResponseDTO struct {
	ID        string `json:"id"`
	OrgID     string `json:"org_id"`
	Email     string `json:"email"`
	RoleID    string `json:"role_id"`
	Token     string `json:"token,omitempty"`
	ExpiresAt string `json:"expires_at"`
	CreatedAt string `json:"created_at"`
}

// AcceptInviteRequestDTO represents the request body for POST /api/v1/orgs/invites/accept.
type AcceptInviteRequestDTO struct {
	Token string `json:"token"`
}

// CreateAPITokenRequestDTO represents the request body for POST /api/v1/orgs/{id}/tokens.
type CreateAPITokenRequestDTO struct {
	Name             string   `json:"name"`
	Permissions      []string `json:"permissions"`
	ExpiresInSeconds int64    `json:"expires_in_seconds,omitempty"`
}

// APITokenDTO represents API token metadata (never includes the secret after creation).
type APITokenDTO struct {
	ID              string   `json:"id"`
	OrgID           string   `json:"org_id"`
	CreatedByUserID string   `json:"created_by_user_id"`
	Name            string   `json:"name"`
	TokenPrefix     string   `json:"token_prefix"`
	Permissions     []string `json:"permissions"`
	ExpiresAt       string   `json:"expires_at,omitempty"`
	LastUsedAt      string   `json:"last_used_at,omitempty"`
	CreatedAt       string   `json:"created_at"`
}

// CreateAPITokenResponseDTO represents the response from POST /api/v1/orgs/{id}/tokens.
type CreateAPITokenResponseDTO struct {
	Token  APITokenDTO `json:"token"`
	Secret string      `json:"secret"`
}

// ListAPITokensResponseDTO represents the response from GET /api/v1/orgs/{id}/tokens.
type ListAPITokensResponseDTO struct {
	Tokens []APITokenDTO `json:"tokens"`
}

// AuditEventDTO represents an append-only audit event entry returned by GET /api/v1/orgs/{id}/audit.
type AuditEventDTO struct {
	ID           string         `json:"id"`
	OrgID        string         `json:"org_id"`
	ActorUserID  string         `json:"actor_user_id,omitempty"`
	ActorType    string         `json:"actor_type"`
	Action       string         `json:"action"`
	ResourceType string         `json:"resource_type"`
	ResourceID   string         `json:"resource_id,omitempty"`
	IPAddress    string         `json:"ip_address,omitempty"`
	UserAgent    string         `json:"user_agent,omitempty"`
	Metadata     map[string]any `json:"metadata"`
	CreatedAt    string         `json:"created_at"`
}

// ListAuditEventsResponseDTO represents the response from GET /api/v1/orgs/{id}/audit.
type ListAuditEventsResponseDTO struct {
	Events []AuditEventDTO `json:"events"`
}

func callerFromPrincipal(p *middleware.Principal) *authv1.CallerPrincipal {
	return &authv1.CallerPrincipal{
		UserId:           p.UserID,
		Kind:             p.Kind,
		TokenOrgId:       p.OrgID,
		TokenPermissions: p.Permissions,
	}
}

func toOrgDTO(o *authv1.OrganizationResponse) OrganizationDTO {
	dto := OrganizationDTO{
		ID:     o.GetId(),
		Name:   o.GetName(),
		Slug:   o.GetSlug(),
		RoleID: o.GetRoleId(),
	}
	if o.GetCreatedAt() != nil {
		dto.CreatedAt = o.GetCreatedAt().AsTime().Format(time.RFC3339)
	}
	if o.GetUpdatedAt() != nil {
		dto.UpdatedAt = o.GetUpdatedAt().AsTime().Format(time.RFC3339)
	}
	return dto
}

func toAPITokenDTO(t *authv1.APITokenInfo) APITokenDTO {
	perms := t.GetPermissions()
	if perms == nil {
		perms = []string{}
	}
	dto := APITokenDTO{
		ID:              t.GetId(),
		OrgID:           t.GetOrgId(),
		CreatedByUserID: t.GetCreatedByUserId(),
		Name:            t.GetName(),
		TokenPrefix:     t.GetTokenPrefix(),
		Permissions:     perms,
	}
	if t.GetExpiresAt() != nil {
		dto.ExpiresAt = t.GetExpiresAt().AsTime().Format(time.RFC3339)
	}
	if t.GetLastUsedAt() != nil {
		dto.LastUsedAt = t.GetLastUsedAt().AsTime().Format(time.RFC3339)
	}
	if t.GetCreatedAt() != nil {
		dto.CreatedAt = t.GetCreatedAt().AsTime().Format(time.RFC3339)
	}
	return dto
}

// ListRoles handles GET /api/v1/roles.
func (h *Handler) ListRoles(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		h.writeError(w, http.StatusMethodNotAllowed, "method not allowed", "METHOD_NOT_ALLOWED")
		return
	}
	if _, ok := middleware.PrincipalFromContext(r.Context()); !ok {
		h.writeError(w, http.StatusUnauthorized, "authentication required", "UNAUTHORIZED")
		return
	}

	ctx, cancel := h.grpcContext(r, 5*time.Second)
	defer cancel()

	grpcResp, err := h.authClient.ListRoles(ctx, &authv1.ListRolesRequest{})
	if err != nil {
		h.writeGRPCError(w, err)
		return
	}

	roles := make([]RoleDTO, 0, len(grpcResp.GetRoles()))
	for _, rl := range grpcResp.GetRoles() {
		perms := rl.GetPermissions()
		if perms == nil {
			perms = []string{}
		}
		roles = append(roles, RoleDTO{
			ID:          rl.GetId(),
			Name:        rl.GetName(),
			Description: rl.GetDescription(),
			Permissions: perms,
		})
	}
	writeJSON(w, http.StatusOK, ListRolesResponseDTO{Roles: roles})
}

// CreateOrg handles POST /api/v1/orgs.
func (h *Handler) CreateOrg(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		h.writeError(w, http.StatusMethodNotAllowed, "method not allowed", "METHOD_NOT_ALLOWED")
		return
	}
	p, ok := middleware.PrincipalFromContext(r.Context())
	if !ok || p.UserID == "" {
		h.writeError(w, http.StatusUnauthorized, "authentication required", "UNAUTHORIZED")
		return
	}
	if p.Kind == middleware.PrincipalKindAPIToken {
		h.writeError(w, http.StatusForbidden, "api tokens cannot create organizations", "FORBIDDEN")
		return
	}
	var req CreateOrgRequestDTO
	if !h.decodeJSON(w, r, &req) {
		return
	}
	if strings.TrimSpace(req.Name) == "" || strings.TrimSpace(req.Slug) == "" {
		h.writeError(w, http.StatusBadRequest, "name and slug are required", "INVALID_ARGUMENT")
		return
	}

	ctx, cancel := h.grpcContext(r, 5*time.Second)
	defer cancel()

	grpcResp, err := h.authClient.CreateOrganization(ctx, &authv1.CreateOrganizationRequest{
		UserId: p.UserID,
		Name:   req.Name,
		Slug:   req.Slug,
	})
	if err != nil {
		h.writeGRPCError(w, err)
		return
	}

	writeJSON(w, http.StatusCreated, toOrgDTO(grpcResp))
}

// ListOrgs handles GET /api/v1/orgs.
func (h *Handler) ListOrgs(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		h.writeError(w, http.StatusMethodNotAllowed, "method not allowed", "METHOD_NOT_ALLOWED")
		return
	}
	p, ok := middleware.PrincipalFromContext(r.Context())
	if !ok || p.UserID == "" {
		h.writeError(w, http.StatusUnauthorized, "authentication required", "UNAUTHORIZED")
		return
	}

	ctx, cancel := h.grpcContext(r, 5*time.Second)
	defer cancel()

	grpcResp, err := h.authClient.ListOrganizations(ctx, &authv1.ListOrganizationsRequest{
		UserId: p.UserID,
	})
	if err != nil {
		h.writeGRPCError(w, err)
		return
	}

	orgs := make([]OrganizationDTO, 0, len(grpcResp.GetOrganizations()))
	for _, o := range grpcResp.GetOrganizations() {
		if p.Kind == middleware.PrincipalKindAPIToken && p.OrgID != "" && o.GetId() != p.OrgID {
			continue
		}
		orgs = append(orgs, toOrgDTO(o))
	}

	writeJSON(w, http.StatusOK, ListOrgsResponseDTO{Organizations: orgs})
}

// GetOrg handles GET /api/v1/orgs/{id}.
func (h *Handler) GetOrg(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		h.writeError(w, http.StatusMethodNotAllowed, "method not allowed", "METHOD_NOT_ALLOWED")
		return
	}
	p, ok := middleware.PrincipalFromContext(r.Context())
	if !ok || p.UserID == "" {
		h.writeError(w, http.StatusUnauthorized, "authentication required", "UNAUTHORIZED")
		return
	}
	orgID := strings.TrimSpace(r.PathValue("id"))
	if orgID == "" {
		h.writeError(w, http.StatusBadRequest, "organization id is required", "INVALID_ARGUMENT")
		return
	}

	ctx, cancel := h.grpcContext(r, 5*time.Second)
	defer cancel()

	grpcResp, err := h.authClient.GetOrganization(ctx, &authv1.GetOrganizationRequest{
		Caller: callerFromPrincipal(p),
		OrgId:  orgID,
	})
	if err != nil {
		h.writeGRPCError(w, err)
		return
	}

	writeJSON(w, http.StatusOK, toOrgDTO(grpcResp))
}

// UpdateOrg handles PATCH /api/v1/orgs/{id}.
func (h *Handler) UpdateOrg(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPatch {
		h.writeError(w, http.StatusMethodNotAllowed, "method not allowed", "METHOD_NOT_ALLOWED")
		return
	}
	p, ok := middleware.PrincipalFromContext(r.Context())
	if !ok || p.UserID == "" {
		h.writeError(w, http.StatusUnauthorized, "authentication required", "UNAUTHORIZED")
		return
	}
	orgID := strings.TrimSpace(r.PathValue("id"))
	if orgID == "" {
		h.writeError(w, http.StatusBadRequest, "organization id is required", "INVALID_ARGUMENT")
		return
	}
	var req UpdateOrgRequestDTO
	if !h.decodeJSON(w, r, &req) {
		return
	}
	if strings.TrimSpace(req.Name) == "" {
		h.writeError(w, http.StatusBadRequest, "name is required", "INVALID_ARGUMENT")
		return
	}

	ctx, cancel := h.grpcContext(r, 5*time.Second)
	defer cancel()

	grpcResp, err := h.authClient.UpdateOrganization(ctx, &authv1.UpdateOrganizationRequest{
		Caller: callerFromPrincipal(p),
		OrgId:  orgID,
		Name:   req.Name,
	})
	if err != nil {
		h.writeGRPCError(w, err)
		return
	}

	writeJSON(w, http.StatusOK, toOrgDTO(grpcResp))
}

// DeleteOrg handles DELETE /api/v1/orgs/{id}.
func (h *Handler) DeleteOrg(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodDelete {
		h.writeError(w, http.StatusMethodNotAllowed, "method not allowed", "METHOD_NOT_ALLOWED")
		return
	}
	p, ok := middleware.PrincipalFromContext(r.Context())
	if !ok || p.UserID == "" {
		h.writeError(w, http.StatusUnauthorized, "authentication required", "UNAUTHORIZED")
		return
	}
	orgID := strings.TrimSpace(r.PathValue("id"))
	if orgID == "" {
		h.writeError(w, http.StatusBadRequest, "organization id is required", "INVALID_ARGUMENT")
		return
	}

	ctx, cancel := h.grpcContext(r, 5*time.Second)
	defer cancel()

	if _, err := h.authClient.DeleteOrganization(ctx, &authv1.DeleteOrganizationRequest{
		Caller: callerFromPrincipal(p),
		OrgId:  orgID,
	}); err != nil {
		h.writeGRPCError(w, err)
		return
	}

	writeJSON(w, http.StatusOK, MessageResponseDTO{Message: "organization deleted successfully"})
}

// ListMembers handles GET /api/v1/orgs/{id}/members.
func (h *Handler) ListMembers(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		h.writeError(w, http.StatusMethodNotAllowed, "method not allowed", "METHOD_NOT_ALLOWED")
		return
	}
	p, ok := middleware.PrincipalFromContext(r.Context())
	if !ok || p.UserID == "" {
		h.writeError(w, http.StatusUnauthorized, "authentication required", "UNAUTHORIZED")
		return
	}
	orgID := strings.TrimSpace(r.PathValue("id"))
	if orgID == "" {
		h.writeError(w, http.StatusBadRequest, "organization id is required", "INVALID_ARGUMENT")
		return
	}

	ctx, cancel := h.grpcContext(r, 5*time.Second)
	defer cancel()

	grpcResp, err := h.authClient.ListMembers(ctx, &authv1.ListMembersRequest{
		Caller: callerFromPrincipal(p),
		OrgId:  orgID,
	})
	if err != nil {
		h.writeGRPCError(w, err)
		return
	}

	members := make([]MemberDTO, 0, len(grpcResp.GetMembers()))
	for _, m := range grpcResp.GetMembers() {
		dto := MemberDTO{
			UserID:      m.GetUserId(),
			Email:       m.GetEmail(),
			DisplayName: m.GetDisplayName(),
			RoleID:      m.GetRoleId(),
		}
		if m.GetCreatedAt() != nil {
			dto.CreatedAt = m.GetCreatedAt().AsTime().Format(time.RFC3339)
		}
		members = append(members, dto)
	}

	writeJSON(w, http.StatusOK, ListMembersResponseDTO{Members: members})
}

// AddMember handles POST /api/v1/orgs/{id}/members.
func (h *Handler) AddMember(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		h.writeError(w, http.StatusMethodNotAllowed, "method not allowed", "METHOD_NOT_ALLOWED")
		return
	}
	p, ok := middleware.PrincipalFromContext(r.Context())
	if !ok || p.UserID == "" {
		h.writeError(w, http.StatusUnauthorized, "authentication required", "UNAUTHORIZED")
		return
	}
	orgID := strings.TrimSpace(r.PathValue("id"))
	if orgID == "" {
		h.writeError(w, http.StatusBadRequest, "organization id is required", "INVALID_ARGUMENT")
		return
	}
	var req AddMemberRequestDTO
	if !h.decodeJSON(w, r, &req) {
		return
	}
	if strings.TrimSpace(req.Email) == "" || strings.TrimSpace(req.RoleID) == "" {
		h.writeError(w, http.StatusBadRequest, "email and role_id are required", "INVALID_ARGUMENT")
		return
	}

	ctx, cancel := h.grpcContext(r, 5*time.Second)
	defer cancel()

	m, err := h.authClient.AddMember(ctx, &authv1.AddMemberRequest{
		Caller: callerFromPrincipal(p),
		OrgId:  orgID,
		Email:  req.Email,
		RoleId: req.RoleID,
	})
	if err != nil {
		h.writeGRPCError(w, err)
		return
	}

	dto := MemberDTO{
		UserID:      m.GetUserId(),
		Email:       m.GetEmail(),
		DisplayName: m.GetDisplayName(),
		RoleID:      m.GetRoleId(),
	}
	if m.GetCreatedAt() != nil {
		dto.CreatedAt = m.GetCreatedAt().AsTime().Format(time.RFC3339)
	}

	writeJSON(w, http.StatusCreated, dto)
}

// UpdateMemberRole handles PATCH /api/v1/orgs/{id}/members/{user_id}.
func (h *Handler) UpdateMemberRole(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPatch {
		h.writeError(w, http.StatusMethodNotAllowed, "method not allowed", "METHOD_NOT_ALLOWED")
		return
	}
	p, ok := middleware.PrincipalFromContext(r.Context())
	if !ok || p.UserID == "" {
		h.writeError(w, http.StatusUnauthorized, "authentication required", "UNAUTHORIZED")
		return
	}
	orgID := strings.TrimSpace(r.PathValue("id"))
	targetUserID := strings.TrimSpace(r.PathValue("user_id"))
	if orgID == "" || targetUserID == "" {
		h.writeError(w, http.StatusBadRequest, "organization id and user_id are required", "INVALID_ARGUMENT")
		return
	}
	var req UpdateMemberRoleRequestDTO
	if !h.decodeJSON(w, r, &req) {
		return
	}
	if strings.TrimSpace(req.RoleID) == "" {
		h.writeError(w, http.StatusBadRequest, "role_id is required", "INVALID_ARGUMENT")
		return
	}

	ctx, cancel := h.grpcContext(r, 5*time.Second)
	defer cancel()

	if _, err := h.authClient.UpdateMemberRole(ctx, &authv1.UpdateMemberRoleRequest{
		Caller:       callerFromPrincipal(p),
		OrgId:        orgID,
		TargetUserId: targetUserID,
		RoleId:       req.RoleID,
	}); err != nil {
		h.writeGRPCError(w, err)
		return
	}

	writeJSON(w, http.StatusOK, MessageResponseDTO{Message: "member role updated successfully"})
}

// RemoveMember handles DELETE /api/v1/orgs/{id}/members/{user_id}.
func (h *Handler) RemoveMember(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodDelete {
		h.writeError(w, http.StatusMethodNotAllowed, "method not allowed", "METHOD_NOT_ALLOWED")
		return
	}
	p, ok := middleware.PrincipalFromContext(r.Context())
	if !ok || p.UserID == "" {
		h.writeError(w, http.StatusUnauthorized, "authentication required", "UNAUTHORIZED")
		return
	}
	orgID := strings.TrimSpace(r.PathValue("id"))
	targetUserID := strings.TrimSpace(r.PathValue("user_id"))
	if orgID == "" || targetUserID == "" {
		h.writeError(w, http.StatusBadRequest, "organization id and user_id are required", "INVALID_ARGUMENT")
		return
	}

	ctx, cancel := h.grpcContext(r, 5*time.Second)
	defer cancel()

	if _, err := h.authClient.RemoveMember(ctx, &authv1.RemoveMemberRequest{
		Caller:       callerFromPrincipal(p),
		OrgId:        orgID,
		TargetUserId: targetUserID,
	}); err != nil {
		h.writeGRPCError(w, err)
		return
	}

	writeJSON(w, http.StatusOK, MessageResponseDTO{Message: "member removed successfully"})
}

// CreateInvite handles POST /api/v1/orgs/{id}/invites.
func (h *Handler) CreateInvite(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		h.writeError(w, http.StatusMethodNotAllowed, "method not allowed", "METHOD_NOT_ALLOWED")
		return
	}
	p, ok := middleware.PrincipalFromContext(r.Context())
	if !ok || p.UserID == "" {
		h.writeError(w, http.StatusUnauthorized, "authentication required", "UNAUTHORIZED")
		return
	}
	orgID := strings.TrimSpace(r.PathValue("id"))
	if orgID == "" {
		h.writeError(w, http.StatusBadRequest, "organization id is required", "INVALID_ARGUMENT")
		return
	}
	var req CreateInviteRequestDTO
	if !h.decodeJSON(w, r, &req) {
		return
	}
	if strings.TrimSpace(req.Email) == "" || strings.TrimSpace(req.RoleID) == "" {
		h.writeError(w, http.StatusBadRequest, "email and role_id are required", "INVALID_ARGUMENT")
		return
	}

	ctx, cancel := h.grpcContext(r, 5*time.Second)
	defer cancel()

	grpcResp, err := h.authClient.CreateInvite(ctx, &authv1.CreateInviteRequest{
		Caller: callerFromPrincipal(p),
		OrgId:  orgID,
		Email:  req.Email,
		RoleId: req.RoleID,
	})
	if err != nil {
		h.writeGRPCError(w, err)
		return
	}

	resp := InviteResponseDTO{
		ID:     grpcResp.GetId(),
		OrgID:  grpcResp.GetOrgId(),
		Email:  grpcResp.GetEmail(),
		RoleID: grpcResp.GetRoleId(),
	}
	if config.IsDevEnv(h.env) {
		resp.Token = grpcResp.GetToken()
	}
	if grpcResp.GetExpiresAt() != nil {
		resp.ExpiresAt = grpcResp.GetExpiresAt().AsTime().Format(time.RFC3339)
	}
	if grpcResp.GetCreatedAt() != nil {
		resp.CreatedAt = grpcResp.GetCreatedAt().AsTime().Format(time.RFC3339)
	}

	writeJSON(w, http.StatusCreated, resp)
}

// AcceptInvite handles POST /api/v1/orgs/invites/accept.
func (h *Handler) AcceptInvite(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		h.writeError(w, http.StatusMethodNotAllowed, "method not allowed", "METHOD_NOT_ALLOWED")
		return
	}
	p, ok := middleware.PrincipalFromContext(r.Context())
	if !ok || p.UserID == "" {
		h.writeError(w, http.StatusUnauthorized, "authentication required", "UNAUTHORIZED")
		return
	}
	if p.Kind == middleware.PrincipalKindAPIToken {
		h.writeError(w, http.StatusForbidden, "api tokens cannot accept invitations", "FORBIDDEN")
		return
	}
	var req AcceptInviteRequestDTO
	if !h.decodeJSON(w, r, &req) {
		return
	}
	if strings.TrimSpace(req.Token) == "" {
		h.writeError(w, http.StatusBadRequest, "token is required", "INVALID_ARGUMENT")
		return
	}

	ctx, cancel := h.grpcContext(r, 5*time.Second)
	defer cancel()

	grpcResp, err := h.authClient.AcceptInvite(ctx, &authv1.AcceptInviteRequest{
		UserId: p.UserID,
		Token:  req.Token,
	})
	if err != nil {
		h.writeGRPCError(w, err)
		return
	}

	writeJSON(w, http.StatusOK, toOrgDTO(grpcResp))
}

// RevokeInvite handles DELETE /api/v1/orgs/{id}/invites/{invite_id}.
func (h *Handler) RevokeInvite(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodDelete {
		h.writeError(w, http.StatusMethodNotAllowed, "method not allowed", "METHOD_NOT_ALLOWED")
		return
	}
	p, ok := middleware.PrincipalFromContext(r.Context())
	if !ok || p.UserID == "" {
		h.writeError(w, http.StatusUnauthorized, "authentication required", "UNAUTHORIZED")
		return
	}
	orgID := strings.TrimSpace(r.PathValue("id"))
	inviteID := strings.TrimSpace(r.PathValue("invite_id"))
	if orgID == "" || inviteID == "" {
		h.writeError(w, http.StatusBadRequest, "organization id and invite_id are required", "INVALID_ARGUMENT")
		return
	}

	ctx, cancel := h.grpcContext(r, 5*time.Second)
	defer cancel()

	if _, err := h.authClient.RevokeInvite(ctx, &authv1.RevokeInviteRequest{
		Caller:   callerFromPrincipal(p),
		OrgId:    orgID,
		InviteId: inviteID,
	}); err != nil {
		h.writeGRPCError(w, err)
		return
	}

	writeJSON(w, http.StatusOK, MessageResponseDTO{Message: "invite revoked successfully"})
}

// CreateAPIToken handles POST /api/v1/orgs/{id}/tokens.
func (h *Handler) CreateAPIToken(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		h.writeError(w, http.StatusMethodNotAllowed, "method not allowed", "METHOD_NOT_ALLOWED")
		return
	}
	p, ok := middleware.PrincipalFromContext(r.Context())
	if !ok || p.UserID == "" {
		h.writeError(w, http.StatusUnauthorized, "authentication required", "UNAUTHORIZED")
		return
	}
	orgID := strings.TrimSpace(r.PathValue("id"))
	if orgID == "" {
		h.writeError(w, http.StatusBadRequest, "organization id is required", "INVALID_ARGUMENT")
		return
	}
	var req CreateAPITokenRequestDTO
	if !h.decodeJSON(w, r, &req) {
		return
	}
	if strings.TrimSpace(req.Name) == "" || len(req.Permissions) == 0 {
		h.writeError(w, http.StatusBadRequest, "name and permissions are required", "INVALID_ARGUMENT")
		return
	}

	ctx, cancel := h.grpcContext(r, 5*time.Second)
	defer cancel()

	grpcResp, err := h.authClient.CreateAPIToken(ctx, &authv1.CreateAPITokenRequest{
		Caller:           callerFromPrincipal(p),
		OrgId:            orgID,
		Name:             req.Name,
		Permissions:      req.Permissions,
		ExpiresInSeconds: req.ExpiresInSeconds,
	})
	if err != nil {
		h.writeGRPCError(w, err)
		return
	}

	writeJSON(w, http.StatusCreated, CreateAPITokenResponseDTO{
		Token:  toAPITokenDTO(grpcResp.GetToken()),
		Secret: grpcResp.GetSecret(),
	})
}

// ListAPITokens handles GET /api/v1/orgs/{id}/tokens.
func (h *Handler) ListAPITokens(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		h.writeError(w, http.StatusMethodNotAllowed, "method not allowed", "METHOD_NOT_ALLOWED")
		return
	}
	p, ok := middleware.PrincipalFromContext(r.Context())
	if !ok || p.UserID == "" {
		h.writeError(w, http.StatusUnauthorized, "authentication required", "UNAUTHORIZED")
		return
	}
	orgID := strings.TrimSpace(r.PathValue("id"))
	if orgID == "" {
		h.writeError(w, http.StatusBadRequest, "organization id is required", "INVALID_ARGUMENT")
		return
	}

	ctx, cancel := h.grpcContext(r, 5*time.Second)
	defer cancel()

	grpcResp, err := h.authClient.ListAPITokens(ctx, &authv1.ListAPITokensRequest{
		Caller: callerFromPrincipal(p),
		OrgId:  orgID,
	})
	if err != nil {
		h.writeGRPCError(w, err)
		return
	}

	tokens := make([]APITokenDTO, 0, len(grpcResp.GetTokens()))
	for _, t := range grpcResp.GetTokens() {
		tokens = append(tokens, toAPITokenDTO(t))
	}

	writeJSON(w, http.StatusOK, ListAPITokensResponseDTO{Tokens: tokens})
}

// RevokeAPIToken handles DELETE /api/v1/orgs/{id}/tokens/{token_id}.
func (h *Handler) RevokeAPIToken(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodDelete {
		h.writeError(w, http.StatusMethodNotAllowed, "method not allowed", "METHOD_NOT_ALLOWED")
		return
	}
	p, ok := middleware.PrincipalFromContext(r.Context())
	if !ok || p.UserID == "" {
		h.writeError(w, http.StatusUnauthorized, "authentication required", "UNAUTHORIZED")
		return
	}
	orgID := strings.TrimSpace(r.PathValue("id"))
	tokenID := strings.TrimSpace(r.PathValue("token_id"))
	if orgID == "" || tokenID == "" {
		h.writeError(w, http.StatusBadRequest, "organization id and token_id are required", "INVALID_ARGUMENT")
		return
	}

	ctx, cancel := h.grpcContext(r, 5*time.Second)
	defer cancel()

	if _, err := h.authClient.RevokeAPIToken(ctx, &authv1.RevokeAPITokenRequest{
		Caller:  callerFromPrincipal(p),
		OrgId:   orgID,
		TokenId: tokenID,
	}); err != nil {
		h.writeGRPCError(w, err)
		return
	}

	writeJSON(w, http.StatusOK, MessageResponseDTO{Message: "api token revoked successfully"})
}

// ListAuditEvents handles GET /api/v1/orgs/{id}/audit (gated by `audit:read`).
func (h *Handler) ListAuditEvents(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		h.writeError(w, http.StatusMethodNotAllowed, "method not allowed", "METHOD_NOT_ALLOWED")
		return
	}
	p, ok := middleware.PrincipalFromContext(r.Context())
	if !ok || p.UserID == "" {
		h.writeError(w, http.StatusUnauthorized, "authentication required", "UNAUTHORIZED")
		return
	}
	orgID := strings.TrimSpace(r.PathValue("id"))
	if orgID == "" {
		h.writeError(w, http.StatusBadRequest, "organization id is required", "INVALID_ARGUMENT")
		return
	}

	limit := 50
	if rawLimit := strings.TrimSpace(r.URL.Query().Get("limit")); rawLimit != "" {
		if parsed, err := strconv.Atoi(rawLimit); err == nil && parsed > 0 {
			limit = parsed
		}
	}
	offset := 0
	if rawOffset := strings.TrimSpace(r.URL.Query().Get("offset")); rawOffset != "" {
		if parsed, err := strconv.Atoi(rawOffset); err == nil && parsed >= 0 {
			offset = parsed
		}
	}

	ctx, cancel := h.grpcContext(r, 5*time.Second)
	defer cancel()

	grpcResp, err := h.authClient.ListAuditEvents(ctx, &authv1.ListAuditEventsRequest{
		Caller: callerFromPrincipal(p),
		OrgId:  orgID,
		Limit:  int32(limit),
		Offset: int32(offset),
	})
	if err != nil {
		h.writeGRPCError(w, err)
		return
	}

	events := make([]AuditEventDTO, 0, len(grpcResp.GetEvents()))
	for _, ev := range grpcResp.GetEvents() {
		meta := map[string]any{}
		if raw := ev.GetMetadataJson(); raw != "" {
			_ = json.Unmarshal([]byte(raw), &meta)
		}
		dto := AuditEventDTO{
			ID:           ev.GetId(),
			OrgID:        ev.GetOrgId(),
			ActorUserID:  ev.GetActorUserId(),
			ActorType:    ev.GetActorType(),
			Action:       ev.GetAction(),
			ResourceType: ev.GetResourceType(),
			ResourceID:   ev.GetResourceId(),
			IPAddress:    ev.GetIpAddress(),
			UserAgent:    ev.GetUserAgent(),
			Metadata:     meta,
		}
		if ev.GetCreatedAt() != nil {
			dto.CreatedAt = ev.GetCreatedAt().AsTime().Format(time.RFC3339)
		}
		events = append(events, dto)
	}

	writeJSON(w, http.StatusOK, ListAuditEventsResponseDTO{Events: events})
}
