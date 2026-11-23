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
	effDefault := domain.ResolveEffectiveBuildSettings("nextjs", domain.BuildSettings{
		InstallCommand:          "ignored-when-toggle-off",
		InstallCommandOverride:  false,
		BuildCommand:            "ignored-when-toggle-off",
		BuildCommandOverride:    false,
		RunCommand:              "ignored-when-toggle-off",
		RunCommandOverride:      false,
		OutputDirectory:         "ignored-when-toggle-off",
		OutputDirectoryOverride: false,
	})
	if effDefault.InstallCommand != "npm install" ||
		effDefault.BuildCommand != "npm run build" ||
		effDefault.RunCommand != "npm start" ||
		effDefault.OutputDirectory != ".next" {
		t.Fatalf("expected nextjs preset defaults when override toggles are OFF, got %+v", effDefault)
	}

	effCustom := domain.ResolveEffectiveBuildSettings("nextjs", domain.BuildSettings{
		InstallCommand:          "pnpm install --frozen-lockfile",
		InstallCommandOverride:  true,
		BuildCommand:            "pnpm turbo run build",
		BuildCommandOverride:    true,
		RunCommand:              "pnpm start",
		RunCommandOverride:      true,
		OutputDirectory:         "dist",
		OutputDirectoryOverride: true,
	})
	if effCustom.InstallCommand != "pnpm install --frozen-lockfile" ||
		effCustom.BuildCommand != "pnpm turbo run build" ||
		effCustom.RunCommand != "pnpm start" ||
		effCustom.OutputDirectory != "dist" {
		t.Fatalf("expected custom overrides when toggles are ON, got %+v", effCustom)
	}

	effEmptyOverride := domain.ResolveEffectiveBuildSettings("nextjs", domain.BuildSettings{
		InstallCommand:          "",
		InstallCommandOverride:  true,
		BuildCommand:            "",
		BuildCommandOverride:    true,
		RunCommand:              "",
		RunCommandOverride:      true,
		OutputDirectory:         "",
		OutputDirectoryOverride: true,
	})
	if effEmptyOverride.InstallCommand != "" ||
		effEmptyOverride.BuildCommand != "" ||
		effEmptyOverride.RunCommand != "" ||
		effEmptyOverride.OutputDirectory != "" {
		t.Fatalf("expected empty strings when override toggles are ON with empty value, got %+v", effEmptyOverride)
	}
}

func TestPresets_Catalog(t *testing.T) {
	presets := domain.ListPresets()
	if len(presets) != 4 {
		t.Fatalf("expected exactly 4 presets, got %d", len(presets))
	}

	expectedIDs := map[string]bool{
		"nextjs": true,
		"vite":   true,
		"golang": true,
		"other":  true,
	}
	for _, p := range presets {
		if !expectedIDs[p.ID] {
			t.Errorf("unexpected preset in catalog: %s", p.ID)
		}
	}

	// Test aliases
	goSpec, ok := domain.LookupPreset("go")
	if !ok || goSpec.ID != "golang" {
		t.Fatalf("expected 'go' to lookup 'golang' preset, got (%+v, %v)", goSpec, ok)
	}
	autoSpec, ok := domain.LookupPreset("auto")
	if !ok || autoSpec.ID != "other" {
		t.Fatalf("expected 'auto' to lookup 'other' preset, got (%+v, %v)", autoSpec, ok)
	}
}
