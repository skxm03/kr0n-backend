.PHONY: all certs test test-race e2e build clean

all: build test

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

## build: Build binaries for control-plane
build:
	@cd control-plane && go build -trimpath -o bin/kr0n-gateway ./cmd/gateway
	@cd control-plane && go build -trimpath -o bin/kr0n-auth ./cmd/auth

## clean: Remove generated certificates and binaries
clean:
	@rm -rf certs/ control-plane/bin/
