package audit

import (
	"context"
	"net"
	"strings"
	"time"

	"github.com/google/uuid"
	"google.golang.org/grpc/metadata"
)

// ExtractPassport extracts identity passport claims injected by API Gateway into incoming gRPC metadata.
func ExtractPassport(ctx context.Context) (userID *uuid.UUID, orgID *uuid.UUID, actorType string, roles []string) {
	md, ok := metadata.FromIncomingContext(ctx)
	if !ok {
		return nil, nil, ActorTypeUser, nil
	}

	if rawUser := firstMD(md, "x-passport-user-id"); rawUser != "" {
		if uid, err := uuid.Parse(rawUser); err == nil {
			userID = &uid
		}
	}

	if rawOrg := firstMD(md, "x-passport-org-id"); rawOrg != "" {
		if oid, err := uuid.Parse(rawOrg); err == nil {
			orgID = &oid
		}
	}

	if kind := firstMD(md, "x-passport-kind"); kind != "" {
		actorType = kind
	} else if userID != nil {
		actorType = ActorTypeUser
	} else {
		actorType = ActorTypeSystem
	}

	if rawRoles := firstMD(md, "x-passport-roles"); rawRoles != "" {
		for _, r := range strings.Split(rawRoles, ",") {
			trimmed := strings.TrimSpace(r)
			if trimmed != "" {
				roles = append(roles, trimmed)
			}
		}
	}

	return userID, orgID, actorType, roles
}

// ExtractClientContext extracts network, user-agent, and trace IDs from incoming gRPC metadata.
func ExtractClientContext(ctx context.Context) ClientContext {
	var cc ClientContext
	md, ok := metadata.FromIncomingContext(ctx)
	if !ok {
		return cc
	}

	if rawIP := firstMD(md, "x-client-ip"); rawIP != "" {
		if parsed := net.ParseIP(rawIP); parsed != nil {
			cc.IPAddress = &parsed
		}
	}

	if ua := firstMD(md, "x-user-agent"); ua != "" {
		cc.UserAgent = &ua
	}

	cc.RequestID = firstMD(md, "x-request-id")
	cc.TraceID = firstMD(md, "x-trace-id")
	return cc
}

// NewEventFromContext constructs a validated, normalized canonical Event using incoming gRPC metadata
// for actor identity and client network context.
func NewEventFromContext(
	ctx context.Context,
	service string,
	action Action,
	target Target,
	payload any,
) (Event, error) {
	userID, orgID, actorType, _ := ExtractPassport(ctx)
	clientCtx := ExtractClientContext(ctx)

	meta, err := ToMetadata(payload)
	if err != nil {
		return Event{}, err
	}

	ev := Event{
		Service:        service,
		Action:         action.String(),
		Status:         StatusSuccess,
		OrganizationID: orgID,
		Actor: Actor{
			UserID: userID,
			Type:   actorType,
		},
		Target:        target,
		ClientContext: clientCtx,
		Metadata:      meta,
		Timestamp:     time.Now().UTC(),
	}

	ev.Normalize(service)
	if err := ev.Validate(); err != nil {
		return Event{}, err
	}

	return ev, nil
}
