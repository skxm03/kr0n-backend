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

# Build static binary
RUN CGO_ENABLED=0 GOOS=linux go build -trimpath -ldflags="-s -w" -o /out/kr0n-mailer ./cmd/mailer

# -----------------------------------------------------------------------------
# Target: mailer (RabbitMQ-backed batch email dispatcher)
# -----------------------------------------------------------------------------
FROM alpine:3.21 AS mailer
RUN apk --no-cache add ca-certificates && \
    addgroup -g 65532 -S kr0n && \
    adduser -u 65532 -S -G kr0n -H -s /sbin/nologin kr0n

COPY --from=builder /out/kr0n-mailer /usr/local/bin/kr0n-mailer
USER 65532:65532
ENTRYPOINT ["kr0n-mailer"]
