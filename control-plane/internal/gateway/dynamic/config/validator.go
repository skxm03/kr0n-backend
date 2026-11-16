package config

import (
	"fmt"
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

// Validate checks the consistency and validity of the GatewayConfig.
func Validate(cfg *GatewayConfig) error {
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

	// Track seen routes across all services to prevent collision: "METHOD:PATH"
	seenRoutes := make(map[string]string)

	for svcName, svc := range cfg.Services {
		svcName = strings.TrimSpace(svcName)
		if svcName == "" {
			return fmt.Errorf("service name cannot be empty")
		}

		if !svc.IsEnabled() {
			continue
		}

		if strings.TrimSpace(svc.Address) == "" {
			return fmt.Errorf("service %q has empty address", svcName)
		}

		if svc.Timeout < 0 {
			return fmt.Errorf("service %q timeout cannot be negative", svcName)
		}

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

			routeKey := method + ":" + path
			if existingSvc, exists := seenRoutes[routeKey]; exists {
				return fmt.Errorf("duplicate route registration for %s %s (claimed by %q and %q)", method, path, existingSvc, svcName)
			}
			seenRoutes[routeKey] = svcName
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
		if svc.Timeout == 0 {
			svc.Timeout = 10 * time.Second
		}
		for i := range svc.Endpoints {
			svc.Endpoints[i].Method = strings.ToUpper(strings.TrimSpace(svc.Endpoints[i].Method))
			svc.Endpoints[i].Path = strings.TrimSpace(svc.Endpoints[i].Path)
		}
		cfg.Services[k] = svc
	}
}
