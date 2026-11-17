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
)

// newE2ETestRouter creates an HTTP handler for E2E tests powered by the dynamic gateway router.
func newE2ETestRouter(authConn *grpc.ClientConn) (http.Handler, error) {
	reg := dynamicregistry.DefaultRegistry()
	dynManager := dynamicrouter.NewManager(dynamicrouter.ManagerOptions{
		Registry: reg,
		Dialer: func(svc dynamicconfig.ServiceConfig) (*grpc.ClientConn, error) {
			return authConn, nil
		},
		MuxFactory: func() *runtime.ServeMux {
			return gateway.NewGatewayServeMux(nil)
		},
	})
	cfg := &dynamicconfig.GatewayConfig{
		Services: map[string]dynamicconfig.ServiceConfig{
			"auth": {
				Address: "e2e-auth",
			},
		},
	}
	dynamicconfig.ApplyDefaults(cfg)
	if err := dynManager.Initialize(context.Background(), cfg); err != nil {
		return nil, err
	}
	return dynManager, nil
}
