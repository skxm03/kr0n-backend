package gateway

import (
	"github.com/skxm03/kr0n-backend/control-plane/internal/gateway/middleware"
)

// PassportUnaryClientInterceptor propagates the authenticated caller principal from the HTTP
// request context into the outgoing protobuf request's `caller` field.
// Untrusted caller inputs from external HTTP JSON bodies are strictly sanitized or cleared.
var PassportUnaryClientInterceptor = middleware.PassportUnaryClientInterceptor

// IncomingHeaderMatcher blocks external HTTP clients from spoofing internal identity headers.
var IncomingHeaderMatcher = middleware.IncomingHeaderMatcher

// InjectPassport populates or clears the `caller` field on a protobuf message based on principal.
var InjectPassport = middleware.InjectPassport
