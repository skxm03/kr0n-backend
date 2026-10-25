package gateway

import (
	"context"

	"google.golang.org/grpc"
	"google.golang.org/grpc/metadata"
)

// ServiceTokenClientInterceptor appends serviceToken to outgoing gRPC metadata on every request.
func ServiceTokenClientInterceptor(serviceToken string) grpc.UnaryClientInterceptor {
	return func(ctx context.Context, method string, req, reply any, cc *grpc.ClientConn, invoker grpc.UnaryInvoker, opts ...grpc.CallOption) error {
		if serviceToken != "" {
			ctx = metadata.AppendToOutgoingContext(ctx, "x-service-token", serviceToken)
		}
		return invoker(ctx, method, req, reply, cc, opts...)
	}
}

