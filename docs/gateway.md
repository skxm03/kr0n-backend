# Gateway Developer Guide & Service Registration Manual

> **Audience:** Developers and AI agents building and registering upstream gRPC services behind the kr0n API Gateway.

---

## 1. Overview & Architectural Role

The API Gateway (`cmd/gateway`) acts as a **stateless, dynamic reverse proxy** (translating external HTTP/JSON REST requests into internal gRPC calls) based on [`grpc-gateway/v2`](https://github.com/grpc-ecosystem/grpc-gateway).

### What the Gateway Handles:
1. **Edge Authentication & Authorization:**
   - Caches Ed25519 public keys from Auth service via JWKS (`GetJWKS`) and validates access tokens locally without a database round-trip per request.
   - Validates opaque API tokens (`kr0n_pat_...`) against the Auth service.
2. **Metadata Propagation:**
   - Extracts caller identity and context, then attaches it to outgoing gRPC metadata headers (`x-caller-user-id`, `x-caller-token-org-id`, `x-caller-token-permissions`, `x-client-ip`, `x-request-id`, etc.).
   - **Downstream services DO NOT verify JWTs or tokens themselves.** They simply read incoming gRPC metadata.
3. **Dynamic 4-Tier Middleware Hierarchy:**
   - Evaluates middleware configured in `gateway.yaml`: Global $\rightarrow$ Service $\rightarrow$ Group $\rightarrow$ Endpoint.
4. **Dynamic Response & Error Mapping:**
   - Automatically maps standard gRPC status codes to REST HTTP status codes (400, 401, 403, 404, 409, 503, 504).
   - Preserves upstream error messages (`st.Message()`) without hardcoded string scraping.
   - Dynamically supports custom error reasons via gRPC `errdetails.ErrorInfo`.
   - Supports custom HTTP status codes (e.g. 201, 202, 204) via gRPC response headers or proto conventions.
5. **Zero-Downtime Hot Reloads:**
   - Watches `gateway.yaml` via filesystem events and swaps routing snapshots atomically.

---

## 2. Step-by-Step: Registering a New Service

When you create a new backend microservice (e.g., `mailer`, `projects`, `runner`, `billing`), follow these 3 steps to expose it through the gateway:

### Step 1: Annotate Your Protobuf Service with HTTP Rules
In your `.proto` file (e.g., `control-plane/internal/proto/<service>/v1/<service>.proto`), import `google/api/annotations.proto` and specify the HTTP path/method for each RPC:

```protobuf
syntax = "proto3";

package mailer.v1;

import "google/api/annotations.proto";

service MailerService {
  rpc SendEmail(SendEmailRequest) returns (SendEmailResponse) {
    option (google.api.http) = {
      post: "/api/v1/emails"
      body: "*"
    };
  }

  rpc GetEmailStatus(GetEmailStatusRequest) returns (GetEmailStatusResponse) {
    option (google.api.http) = {
      get: "/api/v1/emails/{email_id}"
    };
  }
}
```

Compile protobufs (generates `*.pb.go` and `*.pb.gw.go` using `protoc-gen-grpc-gateway`).

---

### Step 2: Register Service in the Gateway Registry
Open [`control-plane/internal/gateway/dynamic/registry/registry.go`](file:///Users/nimitsharma/Desktop/mycode/kr0n-backend/control-plane/internal/gateway/dynamic/registry/registry.go) and register your new service in `DefaultRegistry()`:

```go
func DefaultRegistry() *Registry {
    reg := NewRegistry()

    // 1. Existing Auth Service
    _ = reg.RegisterService("auth", ServiceRegistration{
        Registrar: func(ctx context.Context, mux *runtime.ServeMux, conn *grpc.ClientConn) error {
            return authv1.RegisterAuthServiceHandlerClient(ctx, mux, authv1.NewAuthServiceClient(conn))
        },
        Endpoints: DefaultAuthEndpoints,
    })

    // 2. Add your new service here:
    _ = reg.RegisterService("mailer", ServiceRegistration{
        Registrar: func(ctx context.Context, mux *runtime.ServeMux, conn *grpc.ClientConn) error {
            return mailerv1.RegisterMailerServiceHandlerClient(ctx, mux, mailerv1.NewMailerServiceClient(conn))
        },
        Endpoints: []EndpointDescriptor{
            {Method: "POST", Path: "/api/v1/emails"},
            {Method: "GET", Path: "/api/v1/emails/{email_id}"},
        },
    })

    return reg
}
```

> **Why declare `Endpoints`?**
> The `Endpoints` slice allows the gateway's `auto_mount: true` engine to discover all endpoints and attach the service's default or group middleware profile (rate limits, authentication, CORS) to each route in Chi.

---

### Step 3: Declare the Service in `gateway.yaml`
Open [`control-plane/gateway.yaml`](file:///Users/nimitsharma/Desktop/mycode/kr0n-backend/control-plane/gateway.yaml) and add the upstream configuration under `services:`:

```yaml
services:
  # ... existing auth service ...

  mailer:
    address: "${MAILER_GRPC_ADDR:-localhost:50052}"
    enabled: true
    timeout: 10s
    default_profile: authenticated_api

    # Optional: mTLS configuration
    tls:
      ca_file: "${MAILER_GRPC_TLS_CA_FILE:-}"
      cert_file: "${GATEWAY_GRPC_TLS_CERT_FILE:-}"
      key_file: "${GATEWAY_GRPC_TLS_KEY_FILE:-}"
      server_name: "${MAILER_GRPC_SERVER_NAME:-mailer.internal}"

    # Optional: Inter-service authentication token
    service_token: "${MAILER_SERVICE_TOKEN:-}"

    # Optional: URL Groups to apply custom profiles
    groups:
      public_webhooks:
        match:
          - path: "/api/v1/emails/webhooks/*"
            type: prefix
            methods: [POST]
        use:
          - public_api
```

---

## 3. How Downstream Services Consume Caller Identity

Upstream microservices **do not** need to parse JWTs, check Bearer headers, or verify passwords. The gateway injects the verified caller identity into standard gRPC metadata headers on every call:

### Metadata Headers Available to Upstream Services:
| Metadata Header | Description | Example |
| :--- | :--- | :--- |
| `x-caller-user-id` | UUID of the authenticated user | `018f3a5e-6c8a-7292-9111-bf74c2d67d71` |
| `x-caller-kind` | Authentication type: `session` (JWT) or `api_token` (PAT) | `session` |
| `x-caller-token-org-id` | Organization ID (if caller authenticated via org API token) | `018f3a5e-6c8a-7292-9111-bf74c2d67d72` |
| `x-caller-token-permissions`| Comma-separated list of granted permissions | `org:read,members:write` |
| `x-caller-session-id` | Session UUID (for session JWTs) | `018f3a5e-6c8a-7292-9111-bf74c2d67d73` |
| `x-client-ip` | Validated real client IP address (trusted-proxy aware) | `203.0.113.195` |
| `x-request-id` | Unique UUID for distributed request tracing | `c3a1b02d-34e8-466f-98f5-f2d4e68e4c71` |
| `x-user-agent` | Caller's user agent | `Mozilla/5.0 ...` |

### Consuming Context in Go (Example in Upstream Service):
```go
import "google.golang.org/grpc/metadata"

func (s *MailerServer) SendEmail(ctx context.Context, req *mailerv1.SendEmailRequest) (*mailerv1.SendEmailResponse, error) {
    md, ok := metadata.FromIncomingContext(ctx)
    if !ok {
        return nil, status.Error(codes.Unauthenticated, "missing request metadata")
    }

    callerUserID := ""
    if vals := md.Get("x-caller-user-id"); len(vals) > 0 {
        callerUserID = vals[0]
    }

    clientIP := ""
    if vals := md.Get("x-client-ip"); len(vals) > 0 {
        clientIP = vals[0]
    }

    // Process request with callerUserID ...
}
```

---

## 4. Controlling HTTP Status Codes & Custom Error Codes

### A. HTTP 201 Created (Automatic Convention)
Any protobuf response message whose name starts with `Create...` or `Add...` (or `RegisterResponse`) automatically returns **HTTP 201 Created**.
* `CreateProjectResponse` $\rightarrow$ `201 Created`
* `CreateInviteResponse` $\rightarrow$ `201 Created`
* `AddMemberResponse` $\rightarrow$ `201 Created`

### B. Custom HTTP Status Code (Upstream Header)
If an RPC should return another HTTP status code (e.g. `202 Accepted` for an async job, or `204 No Content`), the upstream gRPC handler can set `x-http-code` or `x-http-status` in response headers:

```go
import "google.golang.org/grpc"
import "google.golang.org/grpc/metadata"

func (s *JobServer) SubmitBatch(ctx context.Context, req *JobRequest) (*JobResponse, error) {
    // Tell the gateway to return HTTP 202 Accepted
    _ = grpc.SetHeader(ctx, metadata.Pairs("x-http-code", "202"))
    return &JobResponse{JobId: "job-123"}, nil
}
```

### C. Returning Domain-Specific Error Codes
The gateway preserves your exact gRPC error message:
```go
return nil, status.Error(codes.NotFound, "project not found")
```
Returns:
```json
{
  "error": "project not found",
  "code": "NOT_FOUND",
  "request_id": "req-123"
}
```

To return a **custom machine-readable error code** (e.g. `INSUFFICIENT_CREDITS`), attach an `errdetails.ErrorInfo`:
```go
import (
    "google.golang.org/genproto/googleapis/rpc/errdetails"
    "google.golang.org/grpc/codes"
    "google.golang.org/grpc/status"
)

func (s *BillingServer) Charge(ctx context.Context, req *ChargeRequest) (*ChargeResponse, error) {
    st := status.New(codes.FailedPrecondition, "account has insufficient credits")
    stWithDetails, _ := st.WithDetails(&errdetails.ErrorInfo{
        Reason: "INSUFFICIENT_CREDITS",
    })
    return nil, stWithDetails.Err()
}
```
The gateway automatically extracts `Reason` and emits:
```json
{
  "error": "account has insufficient credits",
  "code": "INSUFFICIENT_CREDITS",
  "request_id": "req-123"
}
```

---

## 5. Middleware Profiles Reference

Defined in `gateway.yaml`:

| Profile Name | Builtin Middleware Included | Use Case |
| :--- | :--- | :--- |
| `public_api` | `cors`, `request_validation`, `rate_limit (100 req/m)` | Public unauthenticated routes (e.g. `/api/v1/auth/login`, health checks, public webhooks) |
| `authenticated_api` | `cors`, `authentication (JWT/PAT)`, `rate_limit (300 req/m)` | Standard authenticated API endpoints |
| `sensitive_api` | `cors`, `authentication (JWT/PAT)`, `audit_log`, `rate_limit (50 req/m)` | High-privilege mutations (org creation, PAT creation, password changes, deletions) |

### Builtin Middleware Available:
* `request_id`: Attaches UUID to context and sets `X-Request-ID`.
* `recovery`: Catches panics and returns structured 500 JSON.
* `access_log`: Structured JSON access logging with latency measurement.
* `cors`: Configurable CORS headers (`allowed_origins`, `allowed_methods`, `allowed_headers`, `max_age`).
* `authentication`: Enforces valid Bearer JWT or PAT (`allow_api_tokens`, `require_permissions`).
* `rate_limit`: Atomic Redis leaky-bucket limiter with fallback to memory bucket (`requests`, `window`, `key: ip|user|token`).
* `audit_log`: Logs security audit events with caller user ID, org ID, client IP.
* `request_validation`: Enforces `application/json` Content-Type and `max_body_bytes`.
* `timeout`: Request deadline timeout wrapper.
