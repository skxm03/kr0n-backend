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
RUN CGO_ENABLED=0 GOOS=linux go build -trimpath -ldflags="-s -w" -o /out/kr0n-github ./cmd/github

# -----------------------------------------------------------------------------
# Target: github (GitHub VCS proxy microservice)
# -----------------------------------------------------------------------------
FROM alpine:3.21 AS github
RUN apk --no-cache add ca-certificates && \
    addgroup -g 65532 -S kr0n && \
    adduser -u 65532 -S -G kr0n -H -s /sbin/nologin kr0n

COPY --from=builder /out/kr0n-github /usr/local/bin/kr0n-github
USER 65532:65532
EXPOSE 50052
ENTRYPOINT ["kr0n-github"]
