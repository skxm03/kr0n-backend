package config

import (
	"fmt"
	"os"
	"strings"
	"time"
)

var validHTTPMethods = map[string]bool{
	"GET":     true,
	"POST":    true,
	"PUT":     true,
	"DELETE":  true,
	"PATCH":   true,
	"HEAD":    true,
	"OPTIONS": true,
}

var validMatchTypes = map[string]bool{
	"exact":    true,
	"prefix":   true,
	"template": true,
}

// ServiceCatalog defines an interface for querying registered services and their routes.
type ServiceCatalog interface {
	HasService(name string) bool
	GetServiceEndpoints(name string) ([]RouteDescriptor, bool)
}

// RouteDescriptor represents an HTTP method and path for a registered endpoint.
type RouteDescriptor struct {
	Method string
	Path   string
}

// Validate checks the consistency and validity of the GatewayConfig against basic schema rules.
func Validate(cfg *GatewayConfig) error {
	return ValidateWithCatalog(cfg, nil)
}

// ValidateWithCatalog checks the consistency and validity of the GatewayConfig,
// verifying route collisions, group match alignment, and catalog registration when a catalog is provided.
func ValidateWithCatalog(cfg *GatewayConfig, catalog ServiceCatalog) error {
	if cfg == nil {
		return fmt.Errorf("configuration cannot be nil")
	}

	// Validate Server Config
	if cfg.Gateway.ReadTimeout < 0 {
		return fmt.Errorf("gateway.read_timeout cannot be negative")
	}
	if cfg.Gateway.WriteTimeout < 0 {
		return fmt.Errorf("gateway.write_timeout cannot be negative")
	}
	if cfg.Gateway.IdleTimeout < 0 {
		return fmt.Errorf("gateway.idle_timeout cannot be negative")
	}
	if cfg.Gateway.MaxBodyBytes < 0 {
		return fmt.Errorf("gateway.max_body_bytes cannot be negative")
	}

	for idx, redir := range cfg.Gateway.Redirects {
		if strings.TrimSpace(redir.Path) == "" {
			return fmt.Errorf("gateway.redirects[%d].path cannot be empty", idx)
		}
		if !strings.HasPrefix(redir.Path, "/") {
			return fmt.Errorf("gateway.redirects[%d].path must start with '/'", idx)
		}
		if strings.TrimSpace(redir.Target) == "" {
			return fmt.Errorf("gateway.redirects[%d].target cannot be empty", idx)
		}
	}

	// Validate profiles map
	profiles := make(map[string]bool)
	for profileName, items := range cfg.MiddlewareProfiles {
		name := strings.TrimSpace(profileName)
		if name == "" {
			return fmt.Errorf("middleware profile name cannot be empty")
		}
		profiles[name] = true
		for idx, item := range items {
			if strings.TrimSpace(item.Name) == "" {
				return fmt.Errorf("profile %q item[%d] has empty middleware name", name, idx)
			}
		}
	}

	// Track seen routes across all services to prevent collision: "METHOD:PATH" -> serviceName
	seenRoutes := make(map[string]string)

	for svcName, svc := range cfg.Services {
		svcName = strings.TrimSpace(svcName)
		if svcName == "" {
			return fmt.Errorf("service name cannot be empty")
		}

		if strings.TrimSpace(svc.Address) == "" {
			envKey := serviceEnvPrefix(svcName) + "_GRPC_ADDR"
			return fmt.Errorf("service %q is defined in YAML but has no address in YAML or .env (%s)", svcName, envKey)
		}

		if !svc.IsEnabled() {
			continue
		}

		if catalog != nil && !catalog.HasService(svcName) {
			return fmt.Errorf("service %q is enabled in configuration but not registered in service catalog", svcName)
		}

		if svc.Timeout < 0 {
			return fmt.Errorf("service %q timeout cannot be negative", svcName)
		}

		if svc.DefaultProfile != "" && !profiles[svc.DefaultProfile] {
			return fmt.Errorf("service %q default_profile references unknown profile %q", svcName, svc.DefaultProfile)
		}

		// Determine active routes for collision and group alignment checks
		type activeRoute struct {
			method string
			path   string
		}
		var activeRoutes []activeRoute

		if len(svc.Endpoints) > 0 {
			// Validate explicit endpoints
			for idx, ep := range svc.Endpoints {
				method := strings.ToUpper(strings.TrimSpace(ep.Method))
				if !validHTTPMethods[method] {
					return fmt.Errorf("service %q endpoint[%d] has invalid HTTP method %q", svcName, idx, ep.Method)
				}
				path := strings.TrimSpace(ep.Path)
				if path == "" || !strings.HasPrefix(path, "/") {
					return fmt.Errorf("service %q endpoint[%d] path must start with '/': %q", svcName, idx, ep.Path)
				}
				if ep.Timeout < 0 {
					return fmt.Errorf("service %q endpoint[%d] (%s %s) timeout cannot be negative", svcName, idx, method, path)
				}
				for _, prof := range ep.Use {
					if !profiles[prof] {
						return fmt.Errorf("service %q endpoint (%s %s) references unknown profile %q", svcName, method, path, prof)
					}
				}
				activeRoutes = append(activeRoutes, activeRoute{method: method, path: path})
			}

			// If catalog has registered endpoints for this service, verify explicit endpoints are valid
			if catalog != nil {
				if catalogEps, ok := catalog.GetServiceEndpoints(svcName); ok && len(catalogEps) > 0 {
					catalogSet := make(map[string]bool)
					for _, cep := range catalogEps {
						catalogSet[cep.Method+":"+cep.Path] = true
					}
					for _, ar := range activeRoutes {
						if !catalogSet[ar.method+":"+ar.path] {
							return fmt.Errorf("service %q declares endpoint %s %s which is not defined in service catalog/proto", svcName, ar.method, ar.path)
						}
					}
				}
			}
		} else if svc.IsAutoMount() && catalog != nil {
			// Auto-mount endpoints from catalog
			if catalogEps, ok := catalog.GetServiceEndpoints(svcName); ok {
				for _, cep := range catalogEps {
					m := strings.ToUpper(strings.TrimSpace(cep.Method))
					p := strings.TrimSpace(cep.Path)
					if m != "" && p != "" {
						activeRoutes = append(activeRoutes, activeRoute{method: m, path: p})
					}
				}
			}
		}

		// Check for route collisions across services
		for _, ar := range activeRoutes {
			routeKey := ar.method + ":" + ar.path
			if existingSvc, exists := seenRoutes[routeKey]; exists {
				return fmt.Errorf("duplicate route registration for %s %s (claimed by %q and %q)", ar.method, ar.path, existingSvc, svcName)
			}
			seenRoutes[routeKey] = svcName
		}

		// Validate group rules
		for grpName, grp := range svc.Groups {
			grpName = strings.TrimSpace(grpName)
			if grpName == "" {
				return fmt.Errorf("service %q group name cannot be empty", svcName)
			}
			for _, prof := range grp.Use {
				if !profiles[prof] {
					return fmt.Errorf("service %q group %q references unknown profile %q", svcName, grpName, prof)
				}
			}
			for idx, rule := range grp.Match {
				matchType := strings.ToLower(strings.TrimSpace(rule.Type))
				if matchType != "" && !validMatchTypes[matchType] {
					return fmt.Errorf("service %q group %q match[%d] has invalid type %q (must be exact, prefix, or template)", svcName, grpName, idx, rule.Type)
				}
				path := strings.TrimSpace(rule.Path)
				if path == "" || !strings.HasPrefix(path, "/") {
					return fmt.Errorf("service %q group %q match[%d] path must start with '/': %q", svcName, grpName, idx, rule.Path)
				}
				for _, m := range rule.Methods {
					mUpper := strings.ToUpper(strings.TrimSpace(m))
					if !validHTTPMethods[mUpper] {
						return fmt.Errorf("service %q group %q match[%d] has invalid method %q", svcName, grpName, idx, m)
					}
				}

				// Type Safety Alignment: Exact match rules must correspond to a mounted/registered endpoint
				if catalog != nil && len(activeRoutes) > 0 && matchType == "exact" {
					matched := false
					for _, ar := range activeRoutes {
						if ar.path == path {
							if len(rule.Methods) == 0 {
								matched = true
								break
							}
							for _, rm := range rule.Methods {
								if strings.ToUpper(strings.TrimSpace(rm)) == ar.method {
									matched = true
									break
								}
							}
						}
						if matched {
							break
						}
					}
					if !matched {
						return fmt.Errorf("service %q group %q exact match rule %q does not match any registered endpoint for this service", svcName, grpName, path)
					}
				}
			}
		}
	}

	return nil
}

// ApplyDefaults fills in default values for unset fields in GatewayConfig.
func ApplyDefaults(cfg *GatewayConfig) {
	if cfg.Gateway.HTTPAddr == "" {
		cfg.Gateway.HTTPAddr = ":8080"
	}
	if cfg.Gateway.ReadTimeout == 0 {
		cfg.Gateway.ReadTimeout = 15 * time.Second
	}
	if cfg.Gateway.WriteTimeout == 0 {
		cfg.Gateway.WriteTimeout = 30 * time.Second
	}
	if cfg.Gateway.IdleTimeout == 0 {
		cfg.Gateway.IdleTimeout = 60 * time.Second
	}
	if cfg.Gateway.MaxBodyBytes == 0 {
		cfg.Gateway.MaxBodyBytes = 4 * 1024 * 1024 // 4 MB default
	}

	for k, svc := range cfg.Services {
		if strings.TrimSpace(svc.Address) == "" {
			svc.Address = lookupServiceEnvAddress(k)
		}
		if svc.Timeout == 0 {
			svc.Timeout = 10 * time.Second
		}
		for i := range svc.Endpoints {
			svc.Endpoints[i].Method = strings.ToUpper(strings.TrimSpace(svc.Endpoints[i].Method))
			svc.Endpoints[i].Path = strings.TrimSpace(svc.Endpoints[i].Path)
		}
		for gName, grp := range svc.Groups {
			for idx := range grp.Match {
				if grp.Match[idx].Type == "" {
					grp.Match[idx].Type = "exact"
				} else {
					grp.Match[idx].Type = strings.ToLower(strings.TrimSpace(grp.Match[idx].Type))
				}
				for mIdx := range grp.Match[idx].Methods {
					grp.Match[idx].Methods[mIdx] = strings.ToUpper(strings.TrimSpace(grp.Match[idx].Methods[mIdx]))
				}
			}
			svc.Groups[gName] = grp
		}
		cfg.Services[k] = svc
	}
}

func serviceEnvPrefix(svcName string) string {
	return strings.ToUpper(strings.NewReplacer("-", "_", ".", "_").Replace(strings.TrimSpace(svcName)))
}

func lookupServiceEnvAddress(svcName string) string {
	prefix := serviceEnvPrefix(svcName)
	if prefix == "" {
		return ""
	}
	for _, suffix := range []string{"_GRPC_ADDR", "_ADDR", "_URL"} {
		if val := strings.TrimSpace(os.Getenv(prefix + suffix)); val != "" {
			return val
		}
	}
	return ""
}
