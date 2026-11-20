.PHONY: all certs test test-race e2e build clean dev dev-infra dev-infra-down dev-infra-logs migrate-up migrate-down migrate-status dev-auth dev-gateway dev-github dev-mailer docker-build docker-up docker-down

DEV_COMPOSE := infrastructure/docker/docker-compose.dev.yml
FULL_COMPOSE := infrastructure/docker/compose.yaml

all: build test

## -----------------------------------------------------------------------------
## Development Infrastructure (PostgreSQL:5433, Redis:6379, RabbitMQ:5672, Mailpit:1025/8025)
## -----------------------------------------------------------------------------

## dev-infra: Start dev backing services in Docker Compose and wait for healthchecks
dev-infra:
	@echo "Starting development backing services (PostgreSQL on port 5433, Redis, RabbitMQ, Mailpit)..."
	@docker compose -f $(DEV_COMPOSE) up -d --wait
	@echo "All development backing services are healthy and ready."

## dev-infra-down: Stop and tear down dev backing services
dev-infra-down:
	@docker compose -f $(DEV_COMPOSE) down

## dev-infra-logs: Tail logs of dev backing services
dev-infra-logs:
	@docker compose -f $(DEV_COMPOSE) logs -f

## -----------------------------------------------------------------------------
## Database Migrations (PostgreSQL host port 5433)
## -----------------------------------------------------------------------------

## migrate-up: Run database schema migrations up against PostgreSQL (port 5433)
migrate-up:
	@echo "Running database migrations..."
	@cd control-plane && go run ./cmd/migrate up

## migrate-down: Rollback the most recent database migration
migrate-down:
	@cd control-plane && go run ./cmd/migrate down

## migrate-status: Print current migration version and dirty state
migrate-status:
	@cd control-plane && go run ./cmd/migrate version

## -----------------------------------------------------------------------------
## Hot Reload Development (Air)
## -----------------------------------------------------------------------------

## dev: Boot dev infra, apply migrations, and launch all 4 microservices with Air
dev: dev-infra migrate-up
	@echo "Starting all microservices with Air live reloading (Ctrl+C to stop)..."
	@trap 'kill 0' EXIT INT TERM; \
	(cd control-plane && air -c .air.auth.toml) & \
	(cd control-plane && air -c .air.gateway.toml) & \
	(cd control-plane && air -c .air.github.toml) & \
	(cd control-plane && air -c .air.mailer.toml) & \
	wait

## dev-auth: Run Auth microservice with Air live reloading
dev-auth: dev-infra
	@cd control-plane && air -c .air.auth.toml

## dev-gateway: Run API Gateway microservice with Air live reloading
dev-gateway: dev-infra
	@cd control-plane && air -c .air.gateway.toml

## dev-github: Run GitHub VCS microservice with Air live reloading
dev-github: dev-infra
	@cd control-plane && air -c .air.github.toml

## dev-mailer: Run Batch Mailer microservice with Air live reloading
dev-mailer: dev-infra
	@cd control-plane && air -c .air.mailer.toml

## -----------------------------------------------------------------------------
## Docker Build & Full-Stack Compose
## -----------------------------------------------------------------------------

## docker-build: Build Docker images for all microservices (auth, gateway, github, mailer)
docker-build:
	@docker compose -f $(FULL_COMPOSE) build

## docker-up: Start the entire containerized stack via Docker Compose
docker-up:
	@docker compose -f $(FULL_COMPOSE) up -d

## docker-down: Stop the containerized stack
docker-down:
	@docker compose -f $(FULL_COMPOSE) down

## -----------------------------------------------------------------------------
## Build, Test & Utilities
## -----------------------------------------------------------------------------

## certs: Generate zero-trust mTLS certificates (Root CA, Auth server, Gateway client)
certs:
	@chmod +x scripts/gen-certs.sh
	@./scripts/gen-certs.sh ./certs

## test: Run control-plane unit tests
test:
	@cd control-plane && go test ./...

## test-race: Run control-plane tests with the Go race detector
test-race:
	@cd control-plane && go test -race ./internal/gateway/...

## e2e: Run containerized end-to-end integration tests via Testcontainers
e2e:
	@cd control-plane && go test -v -timeout 120s ./test/e2e -run TestE2E_DynamicGateway_Testcontainers_FullFlow

## build: Build static binaries for all control-plane microservices and tools
build:
	@mkdir -p control-plane/bin
	@cd control-plane && go build -trimpath -o bin/kr0n-auth ./cmd/auth
	@cd control-plane && go build -trimpath -o bin/kr0n-gateway ./cmd/gateway
	@cd control-plane && go build -trimpath -o bin/kr0n-github ./cmd/github
	@cd control-plane && go build -trimpath -o bin/kr0n-mailer ./cmd/mailer
	@cd control-plane && go build -trimpath -o bin/kr0n-migrate ./cmd/migrate

## clean: Remove generated certificates, binaries, and Air temp build files
clean:
	@rm -rf certs/ control-plane/bin/ control-plane/tmp/
