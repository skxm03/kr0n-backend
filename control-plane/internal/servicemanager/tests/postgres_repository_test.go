package tests

import (
	"context"
	"testing"
	"time"

	"github.com/google/uuid"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	authv1 "github.com/skxm03/kr0n-backend/control-plane/gen/auth/v1"
	servicemanagerv1 "github.com/skxm03/kr0n-backend/control-plane/gen/servicemanager/v1"
	"github.com/skxm03/kr0n-backend/control-plane/internal/servicemanager/handlers"
	"github.com/skxm03/kr0n-backend/control-plane/internal/servicemanager/repository"
	"github.com/skxm03/kr0n-backend/control-plane/internal/servicemanager/service"
	"github.com/skxm03/kr0n-backend/control-plane/internal/testdb"
	pkgAudit "github.com/skxm03/kr0n-backend/control-plane/pkg/audit"
)

func TestServiceManager_EndToEndWithPostgresAndAudit(t *testing.T) {
	pool := testdb.Pool(t)
	ctx := context.Background()

	ownerID := uuid.New()
	memberID := uuid.New()
	outsiderID := uuid.New()

	for _, u := range []struct {
		id    uuid.UUID
		email string
	}{
		{ownerID, "sm_owner_" + ownerID.String() + "@kr0n.dev"},
		{memberID, "sm_member_" + memberID.String() + "@kr0n.dev"},
		{outsiderID, "sm_outsider_" + outsiderID.String() + "@kr0n.dev"},
	} {
		if _, err := pool.Exec(ctx, `
			INSERT INTO users (id, email, email_verified_at, display_name, status)
			VALUES ($1, $2, now(), 'SM Test', 'active')
		`, u.id, u.email); err != nil {
			t.Fatalf("insert user: %v", err)
		}
	}

	orgID := uuid.New()
	otherOrgID := uuid.New()
	for _, o := range []struct {
		id    uuid.UUID
		slug  string
		owner uuid.UUID
	}{
		{orgID, "sm-org-" + uuid.NewString()[:8], ownerID},
		{otherOrgID, "sm-other-" + uuid.NewString()[:8], outsiderID},
	} {
		if _, err := pool.Exec(ctx, `
			INSERT INTO organizations (id, name, slug) VALUES ($1, 'SM Org', $2)
		`, o.id, o.slug); err != nil {
			t.Fatalf("insert org: %v", err)
		}
		if _, err := pool.Exec(ctx, `
			INSERT INTO organization_memberships (id, organization_id, user_id, role_id)
			VALUES ($1, $2, $3, 'owner')
		`, uuid.New(), o.id, o.owner); err != nil {
			t.Fatalf("insert owner membership: %v", err)
		}
	}

	if _, err := pool.Exec(ctx, `
		INSERT INTO organization_memberships (id, organization_id, user_id, role_id)
		VALUES ($1, $2, $3, 'member')
	`, uuid.New(), orgID, memberID); err != nil {
		t.Fatalf("insert member membership: %v", err)
	}

	// Seed an active installation (91001) and a suspended installation (91002) on orgID, plus 91003 on otherOrgID
	for _, inst := range []struct {
		id     int64
		org    uuid.UUID
		status string
	}{
		{91001, orgID, "active"},
		{91002, orgID, "suspended"},
		{91003, otherOrgID, "active"},
	} {
		if _, err := pool.Exec(ctx, `
			INSERT INTO github_installations (
				id, organization_id, installation_id, account_login, account_type, repository_selection, status, created_by_user_id
			) VALUES ($1, $2, $3, 'acme-gh', 'Organization', 'all', $4, $5)
		`, uuid.New(), inst.org, inst.id, inst.status, ownerID); err != nil {
			t.Fatalf("insert installation %d: %v", inst.id, err)
		}
	}

	repo := repository.NewPostgresProjectRepository(pool)
	authorizer := service.NewLocalDBAuthorizer(pool)
	instVerifier := service.NewLocalDBInstallationVerifier(pool)
	svc := service.NewProjectService(
		repo,
		service.WithAuthorizer(authorizer),
		service.WithInstallationVerifier(instVerifier),
	)
	auditEmitter := pkgAudit.NewMemoryEmitter("servicemanager")
	srv := handlers.NewServer(svc, handlers.WithAuditEmitter(auditEmitter))

	ownerCaller := &authv1.CallerPrincipal{UserId: ownerID.String(), Kind: "session"}
	memberCaller := &authv1.CallerPrincipal{UserId: memberID.String(), Kind: "session"}
	outsiderCaller := &authv1.CallerPrincipal{UserId: outsiderID.String(), Kind: "session"}

	// 1. ListApplicationPresets returns Railpack catalog
	presetsResp, err := srv.ListApplicationPresets(ctx, &servicemanagerv1.ListApplicationPresetsRequest{})
	if err != nil || len(presetsResp.GetPresets()) < 15 {
		t.Fatalf("ListApplicationPresets: err=%v count=%d", err, len(presetsResp.GetPresets()))
	}

	// 2. Member without project:create is denied CreateProject
	if _, err := srv.CreateProject(ctx, &servicemanagerv1.CreateProjectRequest{
		Caller:               memberCaller,
		OrgId:                orgID.String(),
		Name:                 "Web Dashboard",
		GithubInstallationId: 91001,
		RepoOwner:            "acme-gh",
		RepoName:             "monorepo",
	}); status.Code(err) != codes.PermissionDenied {
		t.Fatalf("expected PermissionDenied for member CreateProject, got %v", err)
	}

	// 3. Cannot create project with suspended installation (91002) or another org's installation (91003)
	for _, badInst := range []int64{91002, 91003} {
		if _, err := srv.CreateProject(ctx, &servicemanagerv1.CreateProjectRequest{
			Caller:               ownerCaller,
			OrgId:                orgID.String(),
			Name:                 "Web Dashboard",
			GithubInstallationId: badInst,
			RepoOwner:            "acme-gh",
			RepoName:             "monorepo",
		}); status.Code(err) != codes.InvalidArgument {
			t.Fatalf("expected InvalidArgument for installation %d, got %v", badInst, err)
		}
	}

	// 4. CreateProject succeeds at revision 1 with toggleable build settings (install override ON with empty "", build override OFF using preset default)
	createResp, err := srv.CreateProject(ctx, &servicemanagerv1.CreateProjectRequest{
		Caller:               ownerCaller,
		OrgId:                orgID.String(),
		Name:                 "Web Dashboard",
		Description:          "Primary customer dashboard",
		GithubInstallationId: 91001,
		RepoId:               55001,
		RepoOwner:            "acme-gh",
		RepoName:             "monorepo",
		ProductionBranch:     "main",
		RootDirectory:        "apps/web/",
		ApplicationPreset:    "nextjs",
		BuildSettings: &servicemanagerv1.BuildSettingsInput{
			InstallCommand:          "",
			InstallCommandOverride:  true, // Intentionally empty install command!
			BuildCommand:            "ignored",
			BuildCommandOverride:    false, // Toggle OFF -> uses nextjs default "npm run build"
			RunCommand:              "node server.js",
			RunCommandOverride:      true,
			OutputDirectory:         ".next-custom",
			OutputDirectoryOverride: true,
		},
	})
	if err != nil {
		t.Fatalf("CreateProject: %v", err)
	}

	created := createResp.GetProject()
	if created.GetSlug() != "web-dashboard" ||
		created.GetRootDirectory() != "/apps/web" ||
		created.GetRevision() != 1 ||
		created.GetRepoFullName() != "acme-gh/monorepo" {
		t.Fatalf("unexpected created project: %+v", created)
	}
	bs := created.GetBuildSettings()
	if !bs.GetInstallCommandOverride() || bs.GetInstallCommand() != "" || bs.GetEffectiveInstallCommand() != "" {
		t.Fatalf("expected empty install command override to be preserved as empty, got %+v", bs)
	}
	if bs.GetBuildCommandOverride() || bs.GetBuildCommand() != "" || bs.GetEffectiveBuildCommand() != "npm run build" {
		t.Fatalf("expected build command with toggle OFF to resolve to nextjs default 'npm run build', got %+v", bs)
	}
	if !bs.GetOutputDirectoryOverride() || bs.GetEffectiveOutputDirectory() != ".next-custom" {
		t.Fatalf("expected custom output directory '.next-custom', got %+v", bs)
	}
	if !bs.GetRunCommandOverride() || bs.GetEffectiveRunCommand() != "node server.js" {
		t.Fatalf("expected custom run command 'node server.js', got %+v", bs)
	}

	// Duplicate slug in same org returns AlreadyExists
	if _, err := srv.CreateProject(ctx, &servicemanagerv1.CreateProjectRequest{
		Caller:               ownerCaller,
		OrgId:                orgID.String(),
		Name:                 "Web Dashboard",
		GithubInstallationId: 91001,
		RepoOwner:            "acme-gh",
		RepoName:             "monorepo",
	}); status.Code(err) != codes.AlreadyExists {
		t.Fatalf("expected AlreadyExists on duplicate project slug, got %v", err)
	}

	// 5. Member with project:read can GetProject and ListProjects; outsider is denied
	if _, err := srv.GetProject(ctx, &servicemanagerv1.GetProjectRequest{
		Caller:    outsiderCaller,
		OrgId:     orgID.String(),
		ProjectId: created.GetId(),
	}); status.Code(err) != codes.PermissionDenied {
		t.Fatalf("expected PermissionDenied for outsider GetProject, got %v", err)
	}
	listResp, err := srv.ListProjects(ctx, &servicemanagerv1.ListProjectsRequest{
		Caller: memberCaller,
		OrgId:  orgID.String(),
	})
	if err != nil || len(listResp.GetProjects()) != 1 {
		t.Fatalf("ListProjects for member: err=%v count=%d", err, len(listResp.GetProjects()))
	}

	// 6. UpdateProject increments revision to 2 and enforces expected_revision optimistic locking
	updateResp, err := srv.UpdateProject(ctx, &servicemanagerv1.UpdateProjectRequest{
		Caller:            ownerCaller,
		OrgId:             orgID.String(),
		ProjectId:         created.GetId(),
		Name:              "Web Dashboard v2",
		RootDirectory:     "apps/dashboard",
		ApplicationPreset: "vite",
		ExpectedRevision:  1,
	})
	if err != nil {
		t.Fatalf("UpdateProject: %v", err)
	}
	if updateResp.GetProject().GetRevision() != 2 ||
		updateResp.GetProject().GetRootDirectory() != "/apps/dashboard" ||
		updateResp.GetProject().GetApplicationPreset() != "vite" {
		t.Fatalf("unexpected updated project: %+v", updateResp.GetProject())
	}

	// Stale expected_revision = 1 must now fail with codes.Aborted (409 Conflict)
	if _, err := srv.UpdateProject(ctx, &servicemanagerv1.UpdateProjectRequest{
		Caller:           ownerCaller,
		OrgId:            orgID.String(),
		ProjectId:        created.GetId(),
		Name:             "Stale Update",
		ExpectedRevision: 1,
	}); status.Code(err) != codes.Aborted {
		t.Fatalf("expected Aborted (revision conflict) for stale expected_revision=1, got %v", err)
	}

	// 7. UpdateProjectBuildSettings increments revision to 3
	bsResp, err := srv.UpdateProjectBuildSettings(ctx, &servicemanagerv1.UpdateProjectBuildSettingsRequest{
		Caller:           ownerCaller,
		OrgId:            orgID.String(),
		ProjectId:        created.GetId(),
		ExpectedRevision: 2,
		BuildSettings: &servicemanagerv1.BuildSettingsInput{
			InstallCommand:          "bun install",
			InstallCommandOverride:  true,
			BuildCommand:            "bun run build",
			BuildCommandOverride:    true,
			RunCommand:              "",
			RunCommandOverride:      false, // Toggle OFF -> uses vite default "npm run preview"
			OutputDirectory:         "",
			OutputDirectoryOverride: false, // Toggle OFF -> uses vite default "dist"
		},
	})
	if err != nil {
		t.Fatalf("UpdateProjectBuildSettings: %v", err)
	}
	if bsResp.GetProject().GetRevision() != 3 ||
		bsResp.GetProject().GetBuildSettings().GetEffectiveInstallCommand() != "bun install" ||
		bsResp.GetProject().GetBuildSettings().GetEffectiveOutputDirectory() != "dist" ||
		bsResp.GetProject().GetBuildSettings().GetEffectiveRunCommand() != "npm run preview" {
		t.Fatalf("unexpected build settings update response: %+v", bsResp.GetProject())
	}

	// 8. DeleteProject removes project and cascades to project_build_settings
	if _, err := srv.DeleteProject(ctx, &servicemanagerv1.DeleteProjectRequest{
		Caller:    ownerCaller,
		OrgId:     orgID.String(),
		ProjectId: created.GetId(),
	}); err != nil {
		t.Fatalf("DeleteProject: %v", err)
	}

	var count int
	if err := pool.QueryRow(ctx, `SELECT COUNT(*) FROM project_build_settings WHERE project_id = $1`, uuid.MustParse(created.GetId())).Scan(&count); err != nil || count != 0 {
		t.Fatalf("expected cascade delete of project_build_settings, count=%d err=%v", count, err)
	}

	// 9. Verify all 4 audit events were emitted via pkg/audit
	emitted := auditEmitter.Events()
	if len(emitted) != 4 {
		t.Fatalf("expected 4 audit events, got %d: %+v", len(emitted), emitted)
	}
	wantActions := []string{
		"project.created",
		"project.updated",
		"project.build_settings_updated",
		"project.deleted",
	}
	for i, want := range wantActions {
		if emitted[i].Action != want || emitted[i].Service != "servicemanager" {
			t.Fatalf("audit event[%d]: got (%s, %s), want (servicemanager, %s)", i, emitted[i].Service, emitted[i].Action, want)
		}
	}
	_ = time.Now()
}
