package middleware

import (
	"context"
	"strings"

	"github.com/grpc-ecosystem/grpc-gateway/v2/runtime"
	"google.golang.org/grpc"
	"google.golang.org/grpc/metadata"
	"google.golang.org/protobuf/proto"
	"google.golang.org/protobuf/reflect/protoreflect"
)

// IncomingHeaderMatcher blocks external HTTP clients from spoofing internal identity headers
// (such as "X-Passport-*", "Grpc-Metadata-X-Passport-*"), while allowing standard grpc-gateway headers.
func IncomingHeaderMatcher(header string) (string, bool) {
	k, ok := runtime.DefaultHeaderMatcher(header)
	if !ok {
		return "", false
	}
	if strings.HasPrefix(strings.ToLower(k), "x-passport-") {
		return "", false
	}
	return k, true
}

// PassportUnaryClientInterceptor propagates the authenticated caller principal from the HTTP
// request context into the outgoing protobuf request's `caller` field and outbound gRPC metadata.
// Untrusted caller inputs from external HTTP JSON bodies are strictly sanitized or cleared.
func PassportUnaryClientInterceptor() grpc.UnaryClientInterceptor {
	return func(ctx context.Context, method string, req, reply any, cc *grpc.ClientConn, invoker grpc.UnaryInvoker, opts ...grpc.CallOption) error {
		p, _ := PrincipalFromContext(ctx)
		if msg, ok := req.(proto.Message); ok {
			InjectPassport(msg, p)
		}
		if p != nil {
			pairs := []string{
				"x-passport-user-id", p.UserID,
				"x-passport-kind", p.Kind,
			}
			if p.OrgID != "" {
				pairs = append(pairs, "x-passport-org-id", p.OrgID)
			}
			if p.SessionID != "" {
				pairs = append(pairs, "x-passport-session-id", p.SessionID)
			}
			if len(p.Permissions) > 0 {
				roles := strings.Join(p.Permissions, ",")
				pairs = append(pairs, "x-passport-roles", roles, "x-passport-permissions", roles)
			}
			ctx = metadata.AppendToOutgoingContext(ctx, pairs...)
		}
		return invoker(ctx, method, req, reply, cc, opts...)
	}
}

// InjectPassport populates or clears the `caller` field on a protobuf message based on principal.
func InjectPassport(msg proto.Message, p *Principal) {
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
