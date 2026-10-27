# syntax=docker/dockerfile:1
ARG GO_VERSION=1.25

FROM golang:${GO_VERSION}-alpine AS builder
WORKDIR /src

# Cache dependencies before copying source code
COPY go.mod go.sum ./
RUN go mod download

# Copy control-plane source
COPY cmd/ ./cmd/
COPY gen/ ./gen/
COPY internal/ ./internal/
COPY migrations/ ./migrations/

# Build static binaries
RUN CGO_ENABLED=0 GOOS=linux go build -trimpath -ldflags="-s -w" -o /out/kr0n-migrate ./cmd/migrate && \
    CGO_ENABLED=0 GOOS=linux go build -trimpath -ldflags="-s -w" -o /out/kr0n-auth ./cmd/auth

# -----------------------------------------------------------------------------
# Target: migrate (one-shot database schema migrator)
# -----------------------------------------------------------------------------
FROM alpine:3.21 AS migrate
RUN apk --no-cache add ca-certificates && \
    addgroup -g 65532 -S kr0n && \
    adduser -u 65532 -S -G kr0n -H -s /sbin/nologin kr0n

COPY --from=builder /out/kr0n-migrate /usr/local/bin/kr0n-migrate
USER 65532:65532
ENTRYPOINT ["kr0n-migrate"]
CMD ["up"]

# -----------------------------------------------------------------------------
# Target: auth (internal gRPC Auth Service)
# -----------------------------------------------------------------------------
FROM alpine:3.21 AS auth
RUN apk --no-cache add ca-certificates netcat-openbsd && \
    addgroup -g 65532 -S kr0n && \
    adduser -u 65532 -S -G kr0n -H -s /sbin/nologin kr0n

COPY --from=builder /out/kr0n-auth /usr/local/bin/kr0n-auth
USER 65532:65532
EXPOSE 50051
ENTRYPOINT ["kr0n-auth"]
