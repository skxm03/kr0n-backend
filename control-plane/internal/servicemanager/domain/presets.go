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
	DefaultOutputDirectory string
}

var presetCatalog = []PresetSpec{
	{
		ID:                     "auto",
		DisplayName:            "Auto-Detect (Railpack)",
		RailpackProvider:       "auto",
		Category:               PresetCategoryAuto,
		DefaultInstallCommand:  "",
		DefaultBuildCommand:    "",
		DefaultOutputDirectory: "",
	},
	{
		ID:                     "nextjs",
		DisplayName:            "Next.js",
		RailpackProvider:       "node",
		Category:               PresetCategoryFullstack,
		DefaultInstallCommand:  "npm install",
		DefaultBuildCommand:    "npm run build",
		DefaultOutputDirectory: ".next",
	},
	{
		ID:                     "vite",
		DisplayName:            "Vite",
		RailpackProvider:       "node",
		Category:               PresetCategoryFrontend,
		DefaultInstallCommand:  "npm install",
		DefaultBuildCommand:    "npm run build",
		DefaultOutputDirectory: "dist",
	},
	{
		ID:                     "react",
		DisplayName:            "React (CRA / SPA)",
		RailpackProvider:       "node",
		Category:               PresetCategoryFrontend,
		DefaultInstallCommand:  "npm install",
		DefaultBuildCommand:    "npm run build",
		DefaultOutputDirectory: "build",
	},
	{
		ID:                     "vue",
		DisplayName:            "Vue.js",
		RailpackProvider:       "node",
		Category:               PresetCategoryFrontend,
		DefaultInstallCommand:  "npm install",
		DefaultBuildCommand:    "npm run build",
		DefaultOutputDirectory: "dist",
	},
	{
		ID:                     "nuxt",
		DisplayName:            "Nuxt",
		RailpackProvider:       "node",
		Category:               PresetCategoryFullstack,
		DefaultInstallCommand:  "npm install",
		DefaultBuildCommand:    "npm run build",
		DefaultOutputDirectory: ".output",
	},
	{
		ID:                     "sveltekit",
		DisplayName:            "SvelteKit",
		RailpackProvider:       "node",
		Category:               PresetCategoryFullstack,
		DefaultInstallCommand:  "npm install",
		DefaultBuildCommand:    "npm run build",
		DefaultOutputDirectory: "build",
	},
	{
		ID:                     "astro",
		DisplayName:            "Astro",
		RailpackProvider:       "node",
		Category:               PresetCategoryFullstack,
		DefaultInstallCommand:  "npm install",
		DefaultBuildCommand:    "npm run build",
		DefaultOutputDirectory: "dist",
	},
	{
		ID:                     "remix",
		DisplayName:            "Remix / React Router",
		RailpackProvider:       "node",
		Category:               PresetCategoryFullstack,
		DefaultInstallCommand:  "npm install",
		DefaultBuildCommand:    "npm run build",
		DefaultOutputDirectory: "build",
	},
	{
		ID:                     "nodejs",
		DisplayName:            "Node.js",
		RailpackProvider:       "node",
		Category:               PresetCategoryBackend,
		DefaultInstallCommand:  "npm install",
		DefaultBuildCommand:    "npm run build --if-present",
		DefaultOutputDirectory: "",
	},
	{
		ID:                     "bun",
		DisplayName:            "Bun",
		RailpackProvider:       "node",
		Category:               PresetCategoryBackend,
		DefaultInstallCommand:  "bun install",
		DefaultBuildCommand:    "bun run build",
		DefaultOutputDirectory: "dist",
	},
	{
		ID:                     "deno",
		DisplayName:            "Deno",
		RailpackProvider:       "deno",
		Category:               PresetCategoryBackend,
		DefaultInstallCommand:  "deno cache main.ts",
		DefaultBuildCommand:    "",
		DefaultOutputDirectory: "",
	},
	{
		ID:                     "go",
		DisplayName:            "Go",
		RailpackProvider:       "golang",
		Category:               PresetCategoryBackend,
		DefaultInstallCommand:  "go mod download",
		DefaultBuildCommand:    "go build -o out/app ./...",
		DefaultOutputDirectory: "out",
	},
	{
		ID:                     "python",
		DisplayName:            "Python",
		RailpackProvider:       "python",
		Category:               PresetCategoryBackend,
		DefaultInstallCommand:  "pip install -r requirements.txt",
		DefaultBuildCommand:    "",
		DefaultOutputDirectory: "",
	},
	{
		ID:                     "rust",
		DisplayName:            "Rust",
		RailpackProvider:       "rust",
		Category:               PresetCategoryBackend,
		DefaultInstallCommand:  "cargo fetch",
		DefaultBuildCommand:    "cargo build --release",
		DefaultOutputDirectory: "target/release",
	},
	{
		ID:                     "ruby",
		DisplayName:            "Ruby",
		RailpackProvider:       "ruby",
		Category:               PresetCategoryBackend,
		DefaultInstallCommand:  "bundle install",
		DefaultBuildCommand:    "",
		DefaultOutputDirectory: "",
	},
	{
		ID:                     "php",
		DisplayName:            "PHP",
		RailpackProvider:       "php",
		Category:               PresetCategoryBackend,
		DefaultInstallCommand:  "composer install --no-dev --optimize-autoloader",
		DefaultBuildCommand:    "",
		DefaultOutputDirectory: "public",
	},
	{
		ID:                     "java",
		DisplayName:            "Java",
		RailpackProvider:       "java",
		Category:               PresetCategoryBackend,
		DefaultInstallCommand:  "",
		DefaultBuildCommand:    "./mvnw clean package -DskipTests",
		DefaultOutputDirectory: "target",
	},
	{
		ID:                     "dotnet",
		DisplayName:            ".NET",
		RailpackProvider:       "dotnet",
		Category:               PresetCategoryBackend,
		DefaultInstallCommand:  "dotnet restore",
		DefaultBuildCommand:    "dotnet publish -c Release -o out",
		DefaultOutputDirectory: "out",
	},
	{
		ID:                     "gleam",
		DisplayName:            "Gleam",
		RailpackProvider:       "gleam",
		Category:               PresetCategoryBackend,
		DefaultInstallCommand:  "gleam deps download",
		DefaultBuildCommand:    "gleam export erlang-shipment",
		DefaultOutputDirectory: "build/erlang-shipment",
	},
	{
		ID:                     "dockerfile",
		DisplayName:            "Dockerfile",
		RailpackProvider:       "dockerfile",
		Category:               PresetCategoryContainer,
		DefaultInstallCommand:  "",
		DefaultBuildCommand:    "",
		DefaultOutputDirectory: "",
	},
	{
		ID:                     "static",
		DisplayName:            "Static Site",
		RailpackProvider:       "staticfile",
		Category:               PresetCategoryStatic,
		DefaultInstallCommand:  "",
		DefaultBuildCommand:    "",
		DefaultOutputDirectory: ".",
	},
	{
		ID:                     "custom",
		DisplayName:            "Custom (Railpack)",
		RailpackProvider:       "custom",
		Category:               PresetCategoryAuto,
		DefaultInstallCommand:  "",
		DefaultBuildCommand:    "",
		DefaultOutputDirectory: "",
	},
}

var presetIndex = func() map[string]PresetSpec {
	m := make(map[string]PresetSpec, len(presetCatalog))
	for _, p := range presetCatalog {
		m[p.ID] = p
	}
	return m
}()

// ListPresets returns a copy of the supported Railpack application preset catalog.
func ListPresets() []PresetSpec {
	out := make([]PresetSpec, len(presetCatalog))
	copy(out, presetCatalog)
	return out
}

// LookupPreset returns the PresetSpec for id (case-insensitive).
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
	OutputDirectory string
}

// ResolveEffectiveBuildSettings computes the effective install command, build command,
// and output directory for a project.
//   - If an override toggle is TRUE: the user's exact stored string is returned (even if "" to skip the step).
//   - If an override toggle is FALSE: the preset's default string is returned.
func ResolveEffectiveBuildSettings(presetID string, bs BuildSettings) EffectiveBuildSettings {
	spec, _ := LookupPreset(presetID)

	eff := EffectiveBuildSettings{
		InstallCommand:  spec.DefaultInstallCommand,
		BuildCommand:    spec.DefaultBuildCommand,
		OutputDirectory: spec.DefaultOutputDirectory,
	}
	if bs.InstallCommandOverride {
		eff.InstallCommand = bs.InstallCommand
	}
	if bs.BuildCommandOverride {
		eff.BuildCommand = bs.BuildCommand
	}
	if bs.OutputDirectoryOverride {
		eff.OutputDirectory = bs.OutputDirectory
	}
	return eff
}
