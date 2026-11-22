# kr0n Platform Architecture Documentation

Comprehensive architecture map, communication topology, and service-to-service relationship reference for the **kr0n** cloud control and service planes.

---

## 1. Architectural Philosophy & Overview

kr0n is built on a **Zero-Trust, Microservices-based Control Plane and Service Plane** design in Go:

* **Control Plane (`control-plane/`)**: Orchestrates user identity, multi-tenant organizations, project lifecycles, VCS integrations, asynchronous batch emailing, and audit logging.
* **Service Plane (`service-plane/`)**: Manages high-throughput workload execution, agent/runner messaging, and runtime communication.
* **Zero-Trust Network Model**: All internal service-to-service communication occurs strictly over **mutual TLS (mTLS)** validated against an internal root Certificate Authority (`certs/ca/ca.crt`).
* **Identity Passporting**: Edge API Gateway validates incoming Ed25519 JWT tokens or API Tokens, resolves permissions, and injects trusted identity headers (`X-Passport-*`) into downstream gRPC metadata.
* **Reliable Asynchronous Operations**: Uses the **Transactional Outbox Pattern** and dedicated **RabbitMQ message brokers** to guarantee resilient delivery of system events (emails, audit trails).

---

## 2. End-to-End Architecture Map

```mermaid
flowchart TB
    subgraph Ingress["Client & Edge Layer"]
        UserBrowser["Web Browser / Client Apps<br/>(http://localhost:3000)"]
        SwaggerUI["Swagger UI API Docs<br/>(http://localhost:8081)"]
    end

    subgraph EdgeGateway["kr0n API Gateway (:8080 HTTP)"]
        Mux["Dynamic Route Matcher / Reverse Proxy<br/>(grpc-gateway Mux)"]
        subgraph Pipeline["Middleware Execution Pipeline"]
            MW_Trace["Request ID & Panic Recovery"]
            MW_CORS["CORS Handler"]
            MW_Rate["Redis Leaky-Bucket Rate Limiter"]
            MW_Auth["JWKS / Ed25519 JWT & PAT Validator"]
            MW_Passport["Identity Passport Injector<br/>(X-Passport-*)"]
        end
    end

    subgraph ControlPlaneCore["Control Plane Microservices (Internal Network)"]
        AuthSvc["Auth Service (:50051 gRPC mTLS)<br/>• Identity, Argon2id Passwords<br/>• Ed25519 JWT Issuance & JWKS<br/>• Multi-tenant Orgs & RBAC Engine<br/>• GitHub & Google OAuth Providers<br/>• GitHub App Installation Management<br/>• Transactional Email Outbox"]
        
        GitHubSvc["GitHub VCS Service (:50052 gRPC mTLS)<br/>• GitHub App Token Consumer<br/>• VCS Repo & Branch Indexing<br/>• Monorepo Directory Tree Traverser<br/>• In-memory Response Cache (TTL 2m)"]
        
        ServiceMgr["Service Manager (:50053 gRPC mTLS)<br/>• Repository-linked Projects<br/>• Build Settings & Env Configuration<br/>• Railpack Application Presets"]
        
        BatchMailer["Batch Mailer Worker (Daemon)<br/>• Pulls jobs from RabbitMQ<br/>• Worker Pool (5 workers, batch 20)<br/>• Retry, Backoff, DLQ handling"]
        
        AuditWorker["Audit Worker (Daemon)<br/>• Subscribes to audit.events<br/>• Multi-sink: Postgres + Stdout"]
    end

    subgraph ServicePlaneCore["Service Plane (High-Throughput Workloads)"]
        SP_Router["REST Server (Chi Router)"]
        SP_gRPC["MessageService gRPC Server (message.v1)"]
    end

    subgraph ExternalServices["Third-Party SaaS Integrations"]
        GitHubAPI["GitHub API (api.github.com)<br/>• App Tokens, Repos, Trees, Webhooks"]
        GoogleOAuth["Google Identity (accounts.google.com)<br/>• OAuth2 Token Exchange"]
    end

    subgraph DataInfra["Backing Infrastructure (Docker Compose)"]
        Postgres[("PostgreSQL 16 (Host :5433 -> 5432)<br/>• users, sessions, orgs, rbac<br/>• projects, project_build_settings<br/>• email_outbox, audit_logs")]
        RedisDB[("Redis 7 (Host :6379)<br/>• Distributed Rate Limiter States")]
        RMQ_Mail["RabbitMQ Mailer (Host :5672 | UI :15672)<br/>• Queue: email.jobs"]
        RMQ_Audit["Audit RabbitMQ (Host :5673 | UI :15673)<br/>• Exchange: audit.events"]
        MailpitSmtp["Mailpit (SMTP :1025 | Web UI :8025)<br/>• Local Mail Trap & Inspector"]
    end

    %% Ingress Connections
    UserBrowser -->|HTTP REST / JSON| Mux
    SwaggerUI -.->|Inspects Specs| Mux
    Mux --> MW_Trace --> MW_CORS --> MW_Rate --> MW_Auth --> MW_Passport

    %% Gateway to Backends
    MW_Passport -->|mTLS gRPC (:50051)| AuthSvc
    MW_Passport -->|mTLS gRPC (:50052)| GitHubSvc
    MW_Passport -->|mTLS gRPC (:50053)| ServiceMgr
    MW_Rate <-->|Increment / Read Bucket| RedisDB
    Mux -.->|Publish HTTP Audit Events| RMQ_Audit

    %% Service-to-Service Links
    GitHubSvc -->|Internal mTLS gRPC: GetGitHubInstallationToken| AuthSvc
    ServiceMgr -->|Internal mTLS gRPC: CheckPermission| AuthSvc

    %% Control Plane to Storage & Messaging
    AuthSvc <-->|Read / Write Auth Data & Outbox| Postgres
    AuthSvc -->|Publish Email Jobs| RMQ_Mail
    AuthSvc -.->|Publish Auth Audit Events| RMQ_Audit

    ServiceMgr <-->|Read / Write Project Data| Postgres
    ServiceMgr -.->|Publish Project Audit Events| RMQ_Audit

    %% Async Consumers
    RMQ_Mail -->|Consume Batches| BatchMailer
    BatchMailer -->|Deliver Mail via SMTP| MailpitSmtp

    RMQ_Audit -->|Consume Event Stream| AuditWorker
    AuditWorker -->|Insert Audit Rows| Postgres
    AuditWorker -->|Log Events| UserBrowser

    %% External APIs
    AuthSvc <-->|OAuth Exchange & Webhook Ingestion| GitHubAPI
    AuthSvc <-->|OAuth Token Exchange| GoogleOAuth
    GitHubSvc <-->|Fetch Repos, Trees, Branches| GitHubAPI
```

---

## 3. Microservice Catalog & Deep-Dive

### 3.1. API Gateway (`control-plane/cmd/gateway`)
* **Entrypoint**: `http://localhost:8080` (Configured via `gateway.yaml`)
* **Role**: The single public perimeter router and security policy enforcement point.
* **Core Responsibilities**:
  * **Dynamic Route Forwarding**: Maps incoming HTTP requests to internal gRPC endpoints via `grpc-gateway` muxing.
  * **Middleware Profiles**:
    * `public_api`: CORS enabled, 100 req/min rate limit (e.g. `/api/v1/auth/register`, `/api/v1/auth/login`).
    * `authenticated_api`: Strict authentication required, audit logging, 300 req/min rate limit.
    * `sensitive_api`: Strict authentication, audit logging, 50 req/min rate limit (e.g. Org creation/deletion, Project configuration).
    * `webhook_ingress`: Bypasses client JWT auth, enforces webhook signature verification.
  * **Identity Passporting**: Parses incoming `Bearer` JWT tokens or API Tokens, decodes user identity, and attaches `X-Passport-User-ID`, `X-Passport-Org-ID`, and `X-Passport-Roles` metadata to outbound gRPC calls.
  * **Distributed Rate Limiting**: Employs a Redis-backed leaky-bucket algorithm using atomic Lua scripts.

### 3.2. Auth Service (`control-plane/cmd/auth`)
* **Entrypoint**: `127.0.0.1:50051` (mTLS gRPC)
* **Role**: Authoritative identity, authentication, multi-tenant RBAC, and credential engine.
* **Core Responsibilities**:
  * **Identity Lifecycle**: Registration, login, password hashing with **Argon2id**, email verification, and password recovery.
  * **Token Management**: Issues asymmetric **Ed25519 JWTs** (short-lived access tokens, 15m) and secure cryptographic refresh tokens (720h). Exposes public keys via `/api/v1/auth/jwks`.
  * **Multi-tenant RBAC**: Hierarchical Organizations, system and custom Roles, Memberships, Invitations, and Personal Access Tokens (PATs).
  * **Service-to-Service RPCs**:
    * `CheckPermission`: Internal RPC called by other microservices to enforce authorization checks.
    * `ValidateAPIToken`: Validates scoped automation tokens.
    * `GetGitHubInstallationToken`: Issues ephemeral GitHub App installation tokens to satellite services.
  * **OAuth & App Integrations**: Native GitHub OAuth, Google OAuth, and GitHub App installation state machine with secure HMAC-SHA256 state cookies.
  * **Transactional Outbox**: Queues transactional emails into PostgreSQL before publishing to RabbitMQ.

### 3.3. GitHub VCS Service (`control-plane/cmd/github`)
* **Entrypoint**: `127.0.0.1:50052` (mTLS gRPC)
* **Role**: Version Control System proxy and monorepo structural discovery engine.
* **Core Responsibilities**:
  * **Token Federation**: Calls `AuthService.GetGitHubInstallationToken` via internal mTLS to retrieve short-lived GitHub App tokens on demand.
  * **Repository Exploration**: Proxies GitHub API queries to list repositories, organizations, and branches.
  * **Tree & Monorepo Discovery**: Recursively traverses repository tree structures (`ListDirectories`) to automatically locate nested projects, Dockerfiles, and configuration manifests.
  * **In-Memory Caching**: Implements a concurrent TTL cache (default 2 minutes) to prevent hitting GitHub API rate limits.

### 3.4. Service Manager (`control-plane/cmd/servicemanager`)
* **Entrypoint**: `127.0.0.1:50053` (mTLS gRPC)
* **Role**: Application and project metadata controller.
* **Core Responsibilities**:
  * **Project Management**: CRUD operations for repository-linked projects within organizations.
  * **Railpack Application Presets**: Catalogs pre-configured runtime buildpacks and environment templates.
  * **Build Settings**: Manages build command overrides, output directories, root directories, and deploy triggers.
  * **Authorization Checks**: Calls `AuthService.CheckPermission` to ensure actors hold `project:create`, `project:read`, `project:write`, or `project:delete` permissions.
  * **Audit Emitter**: Emits fine-grained project modification events to RabbitMQ.

### 3.5. Batch Mailer (`control-plane/cmd/mailer`)
* **Role**: Stateless background worker for asynchronous email delivery.
* **Core Responsibilities**:
  * Consumes transactional email messages from RabbitMQ queue `email.jobs`.
  * Micro-batching engine: Groups messages into batches of 20 with a 2-second timeout window.
  * Concurrently processes jobs using a 5-worker goroutine pool.
  * Transports emails over SMTP to **Mailpit** (dev port `:1025`) or transactional providers (SES/SendGrid) in production.
  * Dead-lettering: Automatic retry with exponential backoff on failure.

### 3.6. Audit Worker (`control-plane/cmd/audit`)
* **Role**: Dedicated event-driven compliance and audit logging processor.
* **Core Responsibilities**:
  * Subscribes to the `audit.events` exchange on the dedicated Audit RabbitMQ broker.
  * Pluggable **Multi-Sink Architecture**:
    * **PostgreSQL Sink**: Asynchronously batches and commits audit logs into the `audit_logs` table.
    * **Logger Sink**: Streams formatted JSON logs to `os.Stdout` for container log collectors.

### 3.7. Service Plane (`service-plane/`)
* **Role**: Scalable runtime plane for agent messaging and execution workloads.
* **Core Responsibilities**:
  * **REST Server**: Chi HTTP multiplexer for lightweight REST communication.
  * **gRPC Server**: Implements `MessageService` (`service-plane/gen/message/v1`) for low-latency node-to-node messaging and job coordination.

---

## 4. Backing Infrastructure Topology

All backing infrastructure runs in Docker via `infrastructure/docker/docker-compose.dev.yml`:

| Container | Host Port | Internal Port | Protocol | Purpose |
|---|---|---|---|---|
| **kr0n-dev-postgres** | `5433` | `5432` | PostgreSQL Wire | Authoritative persistence for identity, RBAC, projects, and outbox |
| **kr0n-dev-redis** | `6379` | `6379` | RESP (Redis) | Distributed rate limiting and leaky-bucket sliding counters |
| **kr0n-dev-rabbitmq** | `5672` / `15672` | `5672` / `15672` | AMQP 0-9-1 / HTTP | Message queue for asynchronous email delivery (`email.jobs`) |
| **kr0n-dev-audit-rabbitmq**| `5673` / `15673` | `5672` / `15672` | AMQP 0-9-1 / HTTP | Dedicated message bus for security and audit events (`audit.events`) |
| **kr0n-dev-mailpit** | `1025` / `8025` | `1025` / `8025` | SMTP / HTTP | Dev SMTP capture server and web inspection UI |
| **kr0n-dev-swagger-ui**| `8081` | `8080` | HTTP | Interactive OpenAPI documentation for Auth and GitHub APIs |

---

## 5. Security & Zero-Trust mTLS Network

kr0n strictly enforces zero-trust inter-service communication:

```
[ Root CA ] (certs/ca/ca.crt)
    ├── Signs -> Gateway Client Cert    (certs/gateway/client.crt)
    ├── Signs -> Auth Server Cert       (certs/auth/server.crt)
    └── Signs -> GitHub Server Cert     (certs/github/server.crt)
```

1. **Mutual Authentication (mTLS)**:
   * Services present X.509 certificates signed by the common Root CA during TLS handshakes.
   * Internal services enforce Subject Alternative Names (SANs) such as `auth.internal` and `github.internal`.
2. **Identity Passport Pattern**:
   * Downstream services do **not** re-parse raw client JWTs.
   * The API Gateway parses and validates the client JWT, converts claims into a verified passport, and propagates identity through a dual-channel mechanism:
     * **gRPC Metadata Headers**:
       * `X-Passport-User-ID`: UUID of authenticated user
       * `X-Passport-Org-ID`: UUID of active tenant organization
       * `X-Passport-Roles` / `X-Passport-Permissions`: Comma-separated list of assigned permissions
       * `X-Passport-Kind`: Principal type (`session` or `api_token`)
       * `X-Passport-Session-ID`: UUID of authenticated session
     * **Protobuf Message Payload**: When a request message includes a `caller` field, the gateway's `PassportUnaryClientInterceptor` injects a typed `auth.v1.CallerPrincipal`.
   * Downstream microservices evaluate `CallerPrincipal` or fallback to verified `X-Passport-*` metadata from authenticated internal mTLS callers.

---

## 6. PostgreSQL Schema & Migrations

Database schema migrations are applied modularly per microservice via `control-plane/cmd/migrate -service=<auth|servicemanager|secrets|all>`:

### Auth Service (`internal/auth/migrations`)
| Migration File | Key Tables / Objects Created | Purpose |
|---|---|---|
| `000001_initial_auth.up.sql` | `users`, `sessions`, `email_verification_tokens`, `password_reset_tokens` | Core user identity, argon2id credentials, and session state |
| `000002_auth_completion.up.sql` | `organizations`, `org_members`, `roles`, `permissions`, `invitations`, `api_tokens`, `email_outbox` | Multi-tenant RBAC, team invites, PATs, and transactional email outbox |
| `000003_github_installations.up.sql` | `github_installations` | GitHub App account links, installation IDs, and org bindings |
| `000004_github_webhook_status.up.sql` | `github_webhook_events` | Webhook delivery log and idempotency tracking |
| `000005_default_user_organizations.up.sql` | Default org auto-creation triggers | Automatically provisions personal organization upon user signup |

### Service Manager (`internal/servicemanager/migrations`)
| Migration File | Key Tables / Objects Created | Purpose |
|---|---|---|
| `000001_create_projects.up.sql` | `projects` | Organization projects linked to Git repositories |
| `000002_create_project_build_settings.up.sql` | `project_build_settings` | Railpack presets, root directory overrides, and build flags |

### Secrets Service (`internal/secrets/migrations`)
| Migration File | Key Tables / Objects Created | Purpose |
|---|---|---|
| `000001_create_project_secrets.up.sql` | `project_keys`, `project_env_vars` | Envelope encryption DEKs and AES-256-GCM encrypted env vars |

---

## 7. Developer Lifecycle & Common Commands

| Command | Action |
|---|---|
| `make certs` | Generates self-signed Root CA and mTLS service certificates in `./certs/` |
| `make doctor` | Validates `.env`, certificates, and verifies port mappings |
| `make dev-infra` | Launches all backing Docker containers (PostgreSQL, Redis, RabbitMQs, Mailpit) |
| `make migrate-up` | Applies all pending PostgreSQL database migrations |
| `make dev` | Pre-checks env, boots backing infra, runs migrations, and launches all microservices with Air live reloading |
| `make swagger-ui` | Opens interactive Swagger documentation at `http://localhost:8081` |
| `make test` | Executes unit and integration test suites across the repository |
