package tests

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/google/uuid"
	"github.com/grpc-ecosystem/grpc-gateway/v2/runtime"
	"google.golang.org/protobuf/encoding/protojson"

	authv1 "github.com/skxm03/kr0n-backend/control-plane/gen/auth/v1"
	"github.com/skxm03/kr0n-backend/control-plane/internal/auth/handlers"
	"github.com/skxm03/kr0n-backend/control-plane/internal/auth/repository"
	"github.com/skxm03/kr0n-backend/control-plane/internal/auth/service"
	"github.com/skxm03/kr0n-backend/control-plane/internal/gateway"
	"github.com/skxm03/kr0n-backend/control-plane/internal/gateway/middleware"
)

type countingAuditRepo struct {
	memAuditRepo
	listCalls int
}

func (r *countingAuditRepo) ListByOrg(ctx context.Context, orgID uuid.UUID, action string, limit, offset int) ([]repository.AuditEvent, error) {
	r.listCalls++
	return r.memAuditRepo.ListByOrg(ctx, orgID, action, limit, offset)
}

func TestHandlers_ListAuditEventsHTTP(t *testing.T) {
	ctx := context.Background()
	orgRepo := newMemOrgRepo()
	// Mirror the audit permission granted to admins by the existing migration.
	orgRepo.rolePerms["admin"] = append(orgRepo.rolePerms["admin"], "audit:read")
	orgID, otherOrgID := uuid.New(), uuid.New()
	adminID, memberID, outsiderID := uuid.New(), uuid.New(), uuid.New()
	orgRepo.members[orgID] = map[uuid.UUID]string{adminID: "admin", memberID: "member"}
	auditRepo := &countingAuditRepo{}
	auditSvc := service.NewAuditService(auditRepo)
	events := []repository.AuditEvent{
		{OrganizationID: &orgID, Action: "invite.revoked"},
		{OrganizationID: &orgID, Action: "invite.revoked"},
		{OrganizationID: &orgID, Action: "invite.created"},
		{OrganizationID: &otherOrgID, Action: "invite.revoked"},
	}
	for i := range events {
		events[i].ID = uuid.New()
		if err := auditSvc.Record(ctx, events[i]); err != nil {
			t.Fatal(err)
		}
	}
	srv := handlers.NewServer(nil, nil,
		handlers.WithOrgService(service.NewOrgService(orgRepo)),
		handlers.WithAuditService(auditSvc))
	mux := runtime.NewServeMux(runtime.WithMetadata(gateway.GatewayMetadataAnnotator(nil)))
	if err := authv1.RegisterAuthServiceHandlerServer(ctx, mux, srv); err != nil {
		t.Fatal(err)
	}
	admin := &middleware.Principal{UserID: adminID.String(), Kind: middleware.PrincipalKindSession}
	for _, tc := range []struct {
		name      string
		query     string
		principal *middleware.Principal
		status    int
		want      []uuid.UUID
	}{
		{name: "first filtered page", query: "?action=invite.revoked&limit=1", principal: admin, status: http.StatusOK, want: []uuid.UUID{events[1].ID}},
		{name: "second filtered page", query: "?action=invite.revoked&limit=1&offset=1", principal: admin, status: http.StatusOK, want: []uuid.UUID{events[0].ID}},
		{name: "omitted action", query: "?limit=20", principal: admin, status: http.StatusOK, want: []uuid.UUID{events[2].ID, events[1].ID, events[0].ID}},
		{name: "empty action", query: "?action=&limit=20", principal: admin, status: http.StatusOK, want: []uuid.UUID{events[2].ID, events[1].ID, events[0].ID}},
		{name: "unknown action", query: "?action=unknown.action&limit=20", principal: admin, status: http.StatusOK},
		{name: "exact action", query: "?action=invite&limit=20", principal: admin, status: http.StatusOK},
		{name: "member lacks audit permission", query: "?action=invite.revoked&limit=20", principal: &middleware.Principal{UserID: memberID.String(), Kind: middleware.PrincipalKindSession}, status: http.StatusForbidden},
		{name: "outsider denied", query: "?action=invite.revoked&limit=20", principal: &middleware.Principal{UserID: outsiderID.String(), Kind: middleware.PrincipalKindSession}, status: http.StatusForbidden},
		{name: "unknown action still requires permission", query: "?action=unknown.action", principal: &middleware.Principal{UserID: memberID.String(), Kind: middleware.PrincipalKindSession}, status: http.StatusForbidden},
		{name: "token lacks audit permission", query: "?action=invite.revoked", principal: &middleware.Principal{UserID: adminID.String(), Kind: middleware.PrincipalKindAPIToken, OrgID: orgID.String(), Permissions: []string{"org:read"}}, status: http.StatusForbidden},
		{name: "token scoped to another org", query: "?action=invite.revoked", principal: &middleware.Principal{UserID: adminID.String(), Kind: middleware.PrincipalKindAPIToken, OrgID: otherOrgID.String(), Permissions: []string{"audit:read"}}, status: http.StatusForbidden},
		{name: "authentication required", query: "?action=invite.revoked", status: http.StatusUnauthorized},
	} {
		t.Run(tc.name, func(t *testing.T) {
			req := httptest.NewRequest(http.MethodGet, "/api/v1/orgs/"+orgID.String()+"/audit"+tc.query, nil)
			if tc.principal != nil {
				req = req.WithContext(middleware.WithPrincipal(req.Context(), tc.principal))
			}
			callsBefore := auditRepo.listCalls
			rec := httptest.NewRecorder()
			mux.ServeHTTP(rec, req)
			if rec.Code != tc.status {
				t.Fatalf("status %d, want %d: %s", rec.Code, tc.status, rec.Body.String())
			}
			if tc.status != http.StatusOK {
				if auditRepo.listCalls != callsBefore {
					t.Fatal("unauthorized request reached audit repository")
				}
				return
			}
			var resp authv1.ListAuditEventsResponse
			if err := protojson.Unmarshal(rec.Body.Bytes(), &resp); err != nil {
				t.Fatal(err)
			}
			if len(resp.Events) != len(tc.want) {
				t.Fatalf("got %d events, want %d: %s", len(resp.Events), len(tc.want), rec.Body.String())
			}
			for i, id := range tc.want {
				if resp.Events[i].Id != id.String() || resp.Events[i].OrgId != orgID.String() {
					t.Errorf("event %d: got %v, want %s in org %s", i, resp.Events[i], id, orgID)
				}
			}
		})
	}
}
