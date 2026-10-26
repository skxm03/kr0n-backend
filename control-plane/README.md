# kr0n Control Plane — API Gateway & Auth Service

## Architecture
- **API Gateway (`cmd/gateway`)**: HTTP server (`:8080`) with middleware chain (`RequestID` → `WithClientIP` → `Recover` → `AccessLog` → `SecureHeaders` → `MaxBody` → `RateLimit` → `Authenticate` / `RequirePermission` → handler). Verifies Ed25519 JWTs locally using cached public keys fetched from Auth gRPC `GetJWKS`, and resolves opaque `kr0n_pat_<random>` API tokens via `ValidateAPIToken`.
- **Auth Service (`cmd/auth`)**: gRPC server (`:50051`) backed by PostgreSQL. Handles registration, login throttling & temporary lockout, refresh-token rotation with reuse detection, email verification, password reset/change, GitHub OAuth 2.0 + PKCE, organizations, RBAC (`Can(principal, orgID, permission)`), API tokens, and append-only `audit_events`.
- **Rate Limiter (`internal/ratelimit`)**: Atomic Redis Lua leaky-bucket meter. Fails open on general routes and fails closed (`503`) on credential endpoints if Redis is unreachable.

## Running Locally

1. **Start infrastructure (PostgreSQL 18, Redis 7, Mailpit)**:
   ```sh
   docker compose -f ../infrastructure/docker/compose.yaml up -d
   ```

2. **Copy `.env.example` and run database migrations**:
   ```sh
   cp .env.example .env
   set -a && source .env && set +a
   go run ./cmd/migrate
   ```

3. **Start the Auth gRPC service and API Gateway**:
   ```sh
   go run ./cmd/auth
   # in another terminal:
   go run ./cmd/gateway
   ```
   Mailpit UI is available at `http://localhost:8025`.

## Security & Service Boundary

### Internal gRPC Service Authentication & mTLS
The API Gateway and Auth Service communicate over internal gRPC (`:50051`). In production (`KR0N_ENV != dev`):
- **Mandatory Mutual TLS (mTLS)**: Enforced via `AUTH_GRPC_CLIENT_CA_FILE` (`tls.RequireAndVerifyClientCert`), validating client certificates against trusted internal CA pools. Startup fails closed if the CA file is missing, empty, or unparseable.
- **Client Identity Verification**: The Auth service verifies the client's Subject CommonName / DNS SAN against configured trusted callers (`AUTH_GRPC_ALLOWED_CLIENTS`, e.g. `kr0n-gateway`). A certificate chaining to the CA is rejected if its identity is not on the allowlist.
- **No Token-Only Bypass**: A shared service token cannot authenticate a caller whose client certificate is missing or untrusted. Token-only authentication is restricted strictly to local dev environments.
- **Dual-Mode Defense-in-Depth**: When `AUTH_SERVICE_TOKEN` is configured in production, both valid mTLS credentials and the service token must succeed (`AND` conjunction, never `OR`).
- **Hostname & Server-Name Verification**: The Gateway validates the Auth server certificate SAN against `AUTH_GRPC_SERVER_NAME` (or the dial target host). In non-dev environments, dialing an IP address without an explicit `AUTH_GRPC_SERVER_NAME` fails closed at startup.
- **Principal Spoofing Prevention**: The Auth gRPC service strictly rejects calls carrying `CallerPrincipal` or user credentials unless they originate from an authenticated, trusted internal service. Unauthenticated callers attempting to invoke protected RPCs receive `codes.Unauthenticated`.
- Plaintext gRPC and unauthenticated dev bypass are strictly prohibited unless `KR0N_ENV=dev`.

### Stateless JWT Revocation Window
- **Access Tokens**: Short-lived (default 15 minutes), signed by the Auth Service (Ed25519) and verified locally statelessly by the API Gateway using cached JWKS (`GetJWKS`).
- **Revocation Window**: Because access tokens are stateless, revocation events (logout, password change, session revocation) take effect immediately on session and refresh token usage, while existing short-lived access tokens expire naturally within their 15-minute validity window.
- **API Tokens**: Opaque `kr0n_pat_<random>` tokens are hashed (SHA-256) and verified on-demand via the Auth Service `ValidateAPIToken` RPC, reflecting privilege changes and revocation in real time.

### Database Schema, Token Lifecycle & UUID Strategy
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
*(Destructive integration tests require `TEST_DATABASE_URL` pointing to an isolated test database and will never fall back to `DATABASE_URL`.)*


