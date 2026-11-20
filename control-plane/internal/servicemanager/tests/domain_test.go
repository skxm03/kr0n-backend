package tests

import (
	"testing"

	"github.com/skxm03/kr0n-backend/control-plane/internal/servicemanager/domain"
)

func TestNormalizeRootDirectory(t *testing.T) {
	cases := []struct {
		raw     string
		want    string
		wantErr bool
	}{
		{raw: "", want: "/"},
		{raw: ".", want: "/"},
		{raw: "/", want: "/"},
		{raw: "./", want: "/"},
		{raw: "apps/web", want: "/apps/web"},
		{raw: "/apps/web/", want: "/apps/web"},
		{raw: "./packages/api/cmd", want: "/packages/api/cmd"},
		{raw: "../secret", wantErr: true},
		{raw: "/apps/../../etc/passwd", wantErr: true},
		{raw: `apps\web`, wantErr: true},
	}

	for _, tc := range cases {
		got, err := domain.NormalizeRootDirectory(tc.raw)
		if tc.wantErr {
			if err == nil {
				t.Fatalf("NormalizeRootDirectory(%q): expected error, got %q", tc.raw, got)
			}
			continue
		}
		if err != nil || got != tc.want {
			t.Fatalf("NormalizeRootDirectory(%q): got (%q, %v), want (%q, nil)", tc.raw, got, err, tc.want)
		}
	}
}

func TestResolveEffectiveBuildSettings_ToggleSemantics(t *testing.T) {
	// 1. Toggle OFF (false): uses preset defaults (e.g. nextjs -> npm install, npm run build, .next)
	effDefault := domain.ResolveEffectiveBuildSettings("nextjs", domain.BuildSettings{
		InstallCommand:          "ignored-when-toggle-off",
		InstallCommandOverride:  false,
		BuildCommand:            "ignored-when-toggle-off",
		BuildCommandOverride:    false,
		OutputDirectory:         "ignored-when-toggle-off",
		OutputDirectoryOverride: false,
	})
	if effDefault.InstallCommand != "npm install" ||
		effDefault.BuildCommand != "npm run build" ||
		effDefault.OutputDirectory != ".next" {
		t.Fatalf("expected nextjs preset defaults when override toggles are OFF, got %+v", effDefault)
	}

	// 2. Toggle ON (true) with custom non-empty values: uses custom values
	effCustom := domain.ResolveEffectiveBuildSettings("nextjs", domain.BuildSettings{
		InstallCommand:          "pnpm install --frozen-lockfile",
		InstallCommandOverride:  true,
		BuildCommand:            "pnpm turbo run build",
		BuildCommandOverride:    true,
		OutputDirectory:         "dist",
		OutputDirectoryOverride: true,
	})
	if effCustom.InstallCommand != "pnpm install --frozen-lockfile" ||
		effCustom.BuildCommand != "pnpm turbo run build" ||
		effCustom.OutputDirectory != "dist" {
		t.Fatalf("expected custom overrides when toggles are ON, got %+v", effCustom)
	}

	// 3. Toggle ON (true) with empty string "": preserves empty string "" (intentionally empty / skip step)
	effEmptyOverride := domain.ResolveEffectiveBuildSettings("nextjs", domain.BuildSettings{
		InstallCommand:          "",
		InstallCommandOverride:  true,
		BuildCommand:            "",
		BuildCommandOverride:    true,
		OutputDirectory:         "",
		OutputDirectoryOverride: true,
	})
	if effEmptyOverride.InstallCommand != "" ||
		effEmptyOverride.BuildCommand != "" ||
		effEmptyOverride.OutputDirectory != "" {
		t.Fatalf("expected empty strings when override toggles are ON with empty value, got %+v", effEmptyOverride)
	}
}
