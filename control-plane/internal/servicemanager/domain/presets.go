package domain

import "strings"

// PresetCategory classifies application presets by workload archetype.
type PresetCategory string

const (
	PresetCategoryAuto      PresetCategory = "auto"
	PresetCategoryFrontend  PresetCategory = "frontend"
	PresetCategoryFullstack PresetCategory = "fullstack"
	PresetCategoryBackend   PresetCategory = "backend"
	PresetCategoryContainer PresetCategory = "container"
	PresetCategoryStatic    PresetCategory = "static"
)

// PresetSpec defines a Railpack-aligned application preset and its suggested default build settings.
// When a project's build setting override toggle is OFF (false), Railpack auto-detection / preset defaults apply.
// When an override toggle is ON (true), the user's explicit value (including empty string "") overrides the step.
type PresetSpec struct {
	ID                     string
	DisplayName            string
	RailpackProvider       string
	Category               PresetCategory
	DefaultInstallCommand  string
	DefaultBuildCommand    string
	DefaultRunCommand      string
	DefaultOutputDirectory string
}

var presetCatalog = []PresetSpec{
	{
		ID:                     "nextjs",
		DisplayName:            "Next.js",
		RailpackProvider:       "node",
		Category:               PresetCategoryFullstack,
		DefaultInstallCommand:  "npm install",
		DefaultBuildCommand:    "npm run build",
		DefaultRunCommand:      "npm start",
		DefaultOutputDirectory: ".next",
	},
	{
		ID:                     "vite",
		DisplayName:            "Vite",
		RailpackProvider:       "node",
		Category:               PresetCategoryFrontend,
		DefaultInstallCommand:  "npm install",
		DefaultBuildCommand:    "npm run build",
		DefaultRunCommand:      "npm run preview",
		DefaultOutputDirectory: "dist",
	},
	{
		ID:                     "golang",
		DisplayName:            "Go",
		RailpackProvider:       "golang",
		Category:               PresetCategoryBackend,
		DefaultInstallCommand:  "go mod download",
		DefaultBuildCommand:    "go build -o out/app ./...",
		DefaultRunCommand:      "./out/app",
		DefaultOutputDirectory: "out",
	},
	{
		ID:                     "other",
		DisplayName:            "Other",
		RailpackProvider:       "custom",
		Category:               PresetCategoryAuto,
		DefaultInstallCommand:  "",
		DefaultBuildCommand:    "",
		DefaultRunCommand:      "",
		DefaultOutputDirectory: "",
	},
}

var presetIndex = func() map[string]PresetSpec {
	m := make(map[string]PresetSpec, len(presetCatalog))
	for _, p := range presetCatalog {
		m[p.ID] = p
	}
	// Aliases for compatibility
	if golangSpec, ok := m["golang"]; ok {
		m["go"] = golangSpec
	}
	if otherSpec, ok := m["other"]; ok {
		m["auto"] = otherSpec
		m["custom"] = otherSpec
	}
	return m
}()

// ListPresets returns a copy of the supported application preset catalog.
func ListPresets() []PresetSpec {
	out := make([]PresetSpec, len(presetCatalog))
	copy(out, presetCatalog)
	return out
}

// LookupPreset returns the PresetSpec for id (case-insensitive, supporting aliases).
func LookupPreset(id string) (PresetSpec, bool) {
	normalized := strings.ToLower(strings.TrimSpace(id))
	p, ok := presetIndex[normalized]
	return p, ok
}

// EffectiveBuildSettings represents the resolved build commands and output directory
// after applying the on/off override toggles over the preset defaults.
type EffectiveBuildSettings struct {
	InstallCommand  string
	BuildCommand    string
	RunCommand      string
	OutputDirectory string
}

// ResolveEffectiveBuildSettings computes the effective install command, build command,
// run command, and output directory for a project.
//   - If an override toggle is TRUE: the user's exact stored string is returned (even if "" to skip the step).
//   - If an override toggle is FALSE: the preset's default string is returned.
func ResolveEffectiveBuildSettings(presetID string, bs BuildSettings) EffectiveBuildSettings {
	spec, _ := LookupPreset(presetID)

	eff := EffectiveBuildSettings{
		InstallCommand:  spec.DefaultInstallCommand,
		BuildCommand:    spec.DefaultBuildCommand,
		RunCommand:      spec.DefaultRunCommand,
		OutputDirectory: spec.DefaultOutputDirectory,
	}
	if bs.InstallCommandOverride {
		eff.InstallCommand = bs.InstallCommand
	}
	if bs.BuildCommandOverride {
		eff.BuildCommand = bs.BuildCommand
	}
	if bs.RunCommandOverride {
		eff.RunCommand = bs.RunCommand
	}
	if bs.OutputDirectoryOverride {
		eff.OutputDirectory = bs.OutputDirectory
	}
	return eff
}
