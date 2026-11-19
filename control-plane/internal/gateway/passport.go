package gateway

import (
	"context"

	"google.golang.org/grpc"
	"google.golang.org/protobuf/proto"
	"google.golang.org/protobuf/reflect/protoreflect"

	"github.com/skxm03/kr0n-backend/control-plane/internal/gateway/middleware"
)

// PassportUnaryClientInterceptor propagates the authenticated caller principal from the HTTP
// request context into the outgoing protobuf request's `caller` field.
// Untrusted caller inputs from external HTTP JSON bodies are strictly sanitized or cleared.
func PassportUnaryClientInterceptor() grpc.UnaryClientInterceptor {
	return func(ctx context.Context, method string, req, reply any, cc *grpc.ClientConn, invoker grpc.UnaryInvoker, opts ...grpc.CallOption) error {
		if msg, ok := req.(proto.Message); ok {
			p, _ := middleware.PrincipalFromContext(ctx)
			InjectPassport(msg, p)
		}
		return invoker(ctx, method, req, reply, cc, opts...)
	}
}

// InjectPassport populates or clears the `caller` field on a protobuf message based on principal.
func InjectPassport(msg proto.Message, p *middleware.Principal) {
	if msg == nil {
		return
	}
	m := msg.ProtoReflect()
	callerField := m.Descriptor().Fields().ByName("caller")
	if callerField == nil || callerField.Kind() != protoreflect.MessageKind {
		return
	}

	if p == nil {
		if m.Has(callerField) {
			m.Clear(callerField)
		}
		return
	}

	callerMsg := m.Mutable(callerField).Message()
	setStr := func(fieldName, val string) {
		fd := callerMsg.Descriptor().Fields().ByName(protoreflect.Name(fieldName))
		if fd != nil {
			callerMsg.Set(fd, protoreflect.ValueOfString(val))
		}
	}

	setStr("user_id", p.UserID)
	setStr("kind", p.Kind)
	setStr("token_org_id", p.OrgID)
	setStr("session_id", p.SessionID)

	permsField := callerMsg.Descriptor().Fields().ByName("token_permissions")
	if permsField != nil && permsField.IsList() {
		callerMsg.Clear(permsField)
		if len(p.Permissions) > 0 {
			list := callerMsg.Mutable(permsField).List()
			for _, perm := range p.Permissions {
				list.Append(protoreflect.ValueOfString(perm))
			}
		}
	}
}
