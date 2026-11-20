# kr0n Backend

High-performance, zero-trust cloud control plane and service plane built in Go.

---

## Architecture Overview

```text
                           ┌──────────────────────────┐
                           │    Client / Browser      │
                           └─────────────┬────────────┘
                                         │ HTTP :8080
                                         ▼
                     ┌──────────────────────────────────────┐
                     │          kr0n API Gateway            │
                     │  (Dynamic Routing, Rate Limit, JWKS) │
                     └───────┬───────────────────┬──────────┘
                             │                   │
         mTLS gRPC (:50051)  │                   │ mTLS gRPC (:50052)
                             ▼                   ▼
                 ┌───────────────────────┐   ┌───────────────────────┐
                 │     Auth Service      │   │    GitHub Service     │
                 │  (Identity, Orgs, PAT)│   │  (VCS Proxy & Trees)  │
                 └───────────┬───────────┘   └───────────┬───────────┘
                             │ Outbox                    │
                             ▼                           │
                 ┌───────────────────────┐               │
                 │     Batch Mailer      │               │
                 │   (RabbitMQ Worker)   │               │
                 └───────────────────────┘               │
                             │                           │
  ───────────────────────────┼───────────────────────────┼───────────────────────────
  Backing Infrastructure     │                           │
  ───────────────────────────┼───────────────────────────┼───────────────────────────
                             ▼                           ▼
                     ┌───────────────┐           ┌───────────────┐
                     │  PostgreSQL   │           │     Redis     │
                     │  (Host :5433) │           │  (Host :6379) │
                     └───────────────┘           └───────────────┘
                     ┌───────────────┐           ┌───────────────┐
                     │   RabbitMQ    │           │    Mailpit    │
                     │  (Host :5672) │           │  (SMTP:1025)  │
                     └───────────────┘           └───────────────┘
```

---

## Ports & Services Cheat-Sheet

| Service | Host Port | Protocol | Purpose |
|---|---|---|---|
| **API Gateway** | `8080` | HTTP | Public REST API entrypoint |
| **Auth Service** | `50051` | gRPC (mTLS) | Internal authentication & identity engine |
| **GitHub Service** | `50052` | gRPC (mTLS) | Internal GitHub VCS & repository proxy |
| **Batch Mailer** | N/A | AMQP worker | Asynchronous background email delivery |
| **PostgreSQL** | `5433` *(mapped to 5432)* | TCP | Database (user accounts, orgs, outbox) |
| **Redis** | `6379` | TCP | Distributed leaky-bucket rate limiting |
| **RabbitMQ AMQP** | `5672` | AMQP | Message broker for outbox jobs |
| **RabbitMQ Management**| `15672` | HTTP | RabbitMQ Web Dashboard (`guest`/`guest`) |
| **Mailpit SMTP** | `1025` | SMTP | Local dev mail receiver |
| **Mailpit Web UI** | `8025` | HTTP | View received verification & reset emails |
| **Swagger UI** | `8081` | HTTP | Interactive API docs (`make swagger-ui`) |

---

## Brand New Developer Quickstart (Zero to Running in 3 Steps)

### 1. Prerequisites
Install these tools if not already present on your machine:
- **Go 1.24+**: `brew install go`
- **Docker & Docker Compose**: Ensure Docker Desktop or OrbStack is running
- **Air** (for live hot reloading):
  ```bash
  go install github.com/air-verse/air@latest
  ```

---

### 2. Initial Setup

Clone the repository and prepare your environment:

```bash
# 1. Clone & enter repository
git clone git@github.com:skxm03/kr0n-backend.git
cd kr0n-backend

# 2. Copy the default development environment
cp .env.example .env

# 3. Generate zero-trust mTLS certificates (Root CA, Auth, Gateway, GitHub)
make certs
```

*(Optional) Configure GitHub App*:
If you are developing GitHub VCS or OAuth integrations:
1. Save your GitHub App private key into `./keys/` (e.g. `keys/kr0n-app.private-key.pem`).
2. Generate your state secret:
   ```bash
   openssl rand -hex 32
   ```
3. Update `GITHUB_CLIENT_ID`, `GITHUB_CLIENT_SECRET`, `GITHUB_APP_ID`, `GITHUB_APP_SLUG`, `GITHUB_APP_PRIVATE_KEY`, and `GITHUB_APP_STATE_SECRET` in `.env`.

---

### 3. Verify Configuration (Doctor Check)

Run the pre-flight check to confirm your environment, certificates, and keys are valid:

```bash
make doctor
```

You should see:
```text
  [✓] Root .env found
  [✓] DATABASE_URL is correctly targeting port 5433 (host mapped dev container)
  [✓] Root CA Certificate found at certs/ca/ca.crt
  [✓] Auth Server Certificate found at certs/auth/server.crt
  [✓] Gateway Client Certificate found at certs/gateway/client.crt
  [✓] GitHub Server Certificate found at certs/github/server.crt
  All pre-flight configuration and certificate checks passed!
```

---

### 4. Start Development (`make dev`)

Start the entire stack with a single command:

```bash
make dev
```

**What `make dev` does automatically:**
1. Runs `check-env` pre-flight validation.
2. Starts Docker backing containers (**PostgreSQL on 5433**, **Redis on 6379**, **RabbitMQ on 5672**, **Mailpit on 1025/8025**) and waits until all healthchecks pass.
3. Automatically applies database migrations up to the latest schema version.
4. Concurrently launches all 4 microservices with **Air live reload**:
   - Gateway (`:8080`)
   - Auth (`:50051`)
   - GitHub (`:50052`)
   - Mailer (RabbitMQ worker)
5. Cleanly traps `Ctrl+C` to shut down all processes upon exit.

---

## Exploring the Services

- **Test the Public API**:
  ```bash
  curl http://localhost:8080/healthz
  ```
- **Interactive Swagger UI**:
  ```bash
  make swagger-ui
  ```
  Open **http://localhost:8081** to view and test Auth and GitHub APIs against `http://localhost:8080`.
- **View Outgoing Emails (Verification / Password Reset)**:
  Open **http://localhost:8025** (Mailpit UI) to inspect emails without configuring real SMTP credentials.
- **Inspect RabbitMQ Queues**:
  Open **http://localhost:15672** (user: `guest`, password: `guest`).

---

## Makefile Command Reference

### Development & Hot Reloading
```bash
make dev             # Full dev environment: starts infra, migrates DB, and launches all services with Air
make dev-auth        # Run only Auth service with Air
make dev-gateway     # Run only Gateway service with Air
make dev-github      # Run only GitHub service with Air
make dev-mailer      # Run only Mailer worker with Air
make swagger-ui      # Run Swagger UI container at http://localhost:8081
```

### Infrastructure Management
```bash
make dev-infra       # Boot PostgreSQL (5433), Redis, RabbitMQ, Mailpit
make dev-infra-down  # Stop and destroy development backing containers
make dev-infra-logs  # Stream Docker container logs
```

### Database Schema Migrations
```bash
make migrate-up      # Apply all pending PostgreSQL schema migrations
make migrate-down    # Rollback the last migration
make migrate-status  # Check migration version and dirty status
```

### Diagnostics & Healthchecks
```bash
make check-env       # Run pre-flight configuration & certificate check
make doctor          # Alias for check-env
```

### Builds & Tests
```bash
make build           # Compile static binaries to control-plane/bin/
make test            # Run unit tests across all control-plane modules
make test-race       # Run race detector tests
make docker-build    # Build production multi-stage Docker images
make clean           # Remove binaries, temporary Air build files, and certificates
```
