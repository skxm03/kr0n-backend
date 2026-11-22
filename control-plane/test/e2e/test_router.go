package e2e

import (
	"context"
	"net/http"

	"github.com/grpc-ecosystem/grpc-gateway/v2/runtime"
	"google.golang.org/grpc"

	"github.com/skxm03/kr0n-backend/control-plane/internal/gateway"
	dynamicconfig "github.com/skxm03/kr0n-backend/control-plane/internal/gateway/dynamic/config"
	dynamicregistry "github.com/skxm03/kr0n-backend/control-plane/internal/gateway/dynamic/registry"
	dynamicrouter "github.com/skxm03/kr0n-backend/control-plane/internal/gateway/dynamic/router"
	"github.com/skxm03/kr0n-backend/control-plane/internal/gateway/middleware"
	"github.com/skxm03/kr0n-backend/control-plane/internal/gateway/middleware/builtins"
)

// newE2ETestRouter creates an HTTP handler for E2E tests powered by the dynamic gateway router.
func newE2ETestRouter(authConn *grpc.ClientConn, optDeps ...builtins.SharedDeps) (http.Handler, error) {
	reg := dynamicregistry.DefaultRegistry()
	mwReg := middleware.NewRegistry()
	var deps builtins.SharedDeps
	if len(optDeps) > 0 {
		deps = optDeps[0]
	}
	_ = builtins.RegisterDefaults(mwReg, deps)

	dynManager := dynamicrouter.NewManager(dynamicrouter.ManagerOptions{
		Registry:           reg,
		MiddlewareRegistry: mwReg,
		Dialer: func(svc dynamicconfig.ServiceConfig) (*grpc.ClientConn, error) {
			return authConn, nil
		},
		MuxFactory: func() *runtime.ServeMux {
			return gateway.NewGatewayServeMux(nil)
		},
	})
	cfg := &dynamicconfig.GatewayConfig{
		MiddlewareProfiles: map[string][]middleware.MiddlewareItem{
			"authenticated_api": {
				{Name: "authentication", Config: map[string]any{"allow_api_tokens": true}},
			},
			"public_api": {},
		},
		Services: map[string]dynamicconfig.ServiceConfig{
			"auth": {
				Address:        "e2e-auth",
				DefaultProfile: "authenticated_api",
				Groups: map[string]dynamicconfig.GroupConfig{
					"public": {
						Match: []dynamicconfig.MatchRule{
							{Path: "/api/v1/auth/*", Type: "prefix"},
						},
						Use: []string{"public_api"},
					},
				},
			},
		},
	}
	dynamicconfig.ApplyDefaults(cfg)
	if err := dynManager.Initialize(context.Background(), cfg); err != nil {
		return nil, err
	}
	return dynManager, nil
}
