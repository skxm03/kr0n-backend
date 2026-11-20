# kr0n Control Plane — API Gateway & Auth Service

## Architecture
- **API Gateway (`cmd/gateway`)**: HTTP reverse proxy (`:8080`) routing dynamically to upstream gRPC microservices via `gateway.yaml` and grpc-gateway. Handles JWT verification (cached Ed25519 JWKS), API token validation, 4-tier middleware pipeline, and typed protobuf passport propagation (`CallerPrincipal`).
- **Auth Service (`cmd/auth`)**: gRPC server (`:50051`) backed by PostgreSQL. Handles registration, login throttling & temporary lockout, refresh-token rotation with reuse detection, email verification, password reset/change, GitHub OAuth 2.0 + PKCE, organizations, RBAC (`Can(principal, orgID, permission)`), API tokens, and append-only `audit_events`.
- **Rate Limiter (`internal/ratelimit`)**: Atomic Redis Lua leaky-bucket meter. Fails open on general routes and fails closed (`503`) on credential endpoints if Redis is unreachable.

## Running Locally

### Recommended: Root Makefile & Air Live Reload
From the repository root, run:
```bash
make dev
```
This automatically boots PostgreSQL on port 5433, Redis on 6379, RabbitMQ on 5672, Mailpit on 1025/8025, applies schema migrations, and launches all microservices with Air live reloading.

See the root [README.md](../README.md) for full developer documentation, architecture overview, and command references.

### Production & Full-Stack Containerized Compose
To run all microservices fully containerized in Docker:
```bash
make docker-build
make docker-up
```

## Security & Service Boundary

### Internal gRPC Service Authentication & mTLS
The API Gateway and Auth Service communicate over internal gRPC (`:50051`). In production (`KR0N_ENV != dev`):
- **Mandatory Mutual TLS (mTLS)**: Enforced via `AUTH_GRPC_CLIENT_CA_FILE` (`tls.RequireAndVerifyClientCert`), validating client certificates against trusted internal CA pools. Startup fails closed if the CA file is missing, empty, or unparseable.
- **Client Identity Verification**: The Auth service verifies the client's Subject CommonName / DNS SAN against configured trusted callers (`AUTH_GRPC_ALLOWED_CLIENTS`, e.g. `kr0n-gateway`, `kr0n-github`). A certificate chaining to the CA is rejected if its identity is not on the allowlist.
- **Zero-Trust Certificate-Based Security**: All internal communication relies exclusively on mTLS client identity; legacy shared service tokens have been completely removed.
- **Hostname & Server-Name Verification**: The Gateway validates the Auth server certificate SAN against `AUTH_GRPC_SERVER_NAME` (or the dial target host). In non-dev environments, dialing an IP address without an explicit `AUTH_GRPC_SERVER_NAME` fails closed at startup.
- **Principal Spoofing Prevention**: The Auth gRPC service strictly rejects calls carrying `CallerPrincipal` or user credentials unless they originate from an authenticated, trusted internal service. Unauthenticated callers attempting to invoke protected RPCs receive `codes.Unauthenticated`.
- Plaintext gRPC and unauthenticated dev bypass are strictly prohibited unless `KR0N_ENV=dev`.

### Stateless JWT Revocation Window
- **Access Tokens**: Short-lived (default 15 minutes), signed by the Auth Service (Ed25519) and verified locally statelessly by the API Gateway using cached JWKS (`GetJWKS`).
- **Revocation Window**: Because access tokens are stateless, revocation events (logout, password change, session revocation) take effect immediately on session and refresh token usage, while existing short-lived access tokens expire naturally within their 15-minute validity window.
- **API Tokens**: Opaque `kr0n_pat_<random>` tokens are hashed (SHA-256) and verified on-demand via the Auth Service `ValidateAPIToken` RPC, reflecting privilege changes and revocation in real time.

### Database Schema, Token Lifecycle & UUID Strategy
- **PostgreSQL migrations**: The schema is defined in [`internal/auth/migrations/`](internal/auth/migrations/).
- **UUID Ordering**:
  - `uuid.NewV7()` (time-ordered sequential UUIDs) is used for high-write tables (`audit_events`, `users`, `sessions`) to ensure B-Tree index page locality and high write throughput.
  - `uuid.New()` (cryptographically secure random UUID v4) is used for non-clustered resources (`organizations`, `api_tokens`, `organization_invites`).
- **Token Lifecycle & Sanitization**:
  - Single-use invite and password reset tokens are stored exclusively as SHA-256 hashes (`token_hash`).
  - Organization invite creation responses omit raw bearer tokens unless explicitly running in `KR0N_ENV=dev`. In non-dev environments, invite tokens are dispatched directly to invitees via SMTP email with a 3-second timeout.
  - Foreign key indexes are established on `refresh_token_history(user_id)`, `api_tokens(created_by_user_id)`, and `organization_invites(invited_by_user_id)`.
  - The append-only `audit_events` log captures user IP address, User-Agent, and Request ID across all security-sensitive actions.

## Testing
```sh
go build ./... && go vet ./... && go test -race ./...
```
*(Integration and E2E tests automatically provision ephemeral `postgres:18-alpine` and `redis:7-alpine` containers via [Testcontainers for Go](https://golang.testcontainers.org/) when Docker is running, and never touch `DATABASE_URL`. Set `KR0N_REQUIRE_DB_TESTS=1` in CI to fail instead of skip if the Docker daemon is unreachable.)*


