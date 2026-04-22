# Quantix Node Docker Image
# Build: docker build -t quantix/node:latest .
# Run:   docker run -p 7331:7331 -p 8545:8545 quantix/node:latest

# ============================================
# Stage 1: Build
# ============================================
FROM golang:1.22-alpine AS builder

# Install build dependencies
RUN apk add --no-cache git make gcc musl-dev linux-headers

WORKDIR /build

# Copy go mod files first for layer caching
COPY go.mod go.sum ./
RUN go mod download

# Copy source code
COPY . .

# Build the node binary
RUN CGO_ENABLED=1 GOOS=linux go build -ldflags="-s -w" -o quantix-node ./cmd/node

# Build CLI tools
RUN CGO_ENABLED=0 GOOS=linux go build -ldflags="-s -w" -o quantix-cli ./cmd/cli 2>/dev/null || echo "CLI not yet implemented"

# ============================================
# Stage 2: Runtime
# ============================================
FROM alpine:3.19

# Install runtime dependencies
RUN apk add --no-cache ca-certificates tzdata

# Create non-root user
RUN addgroup -g 1000 quantix && \
    adduser -u 1000 -G quantix -h /home/quantix -D quantix

# Create directories
RUN mkdir -p /data /config && \
    chown -R quantix:quantix /data /config

WORKDIR /home/quantix

# Copy binaries from builder
COPY --from=builder /build/quantix-node /usr/local/bin/
# COPY --from=builder /build/quantix-cli /usr/local/bin/

# Copy default config
COPY --chown=quantix:quantix docker/config.toml /config/config.toml

# Switch to non-root user
USER quantix

# Expose ports
# 7331  - P2P (mainnet)
# 17331 - P2P (testnet)
# 73310 - P2P (devnet)
# 8545  - JSON-RPC HTTP
# 8546  - JSON-RPC WebSocket
# 9090  - Prometheus metrics
EXPOSE 7331 17331 73310 8545 8546 9090

# Data volume
VOLUME ["/data"]

# Health check
HEALTHCHECK --interval=30s --timeout=10s --start-period=5s --retries=3 \
    CMD wget -qO- http://localhost:8545/health || exit 1

# Default command
ENTRYPOINT ["quantix-node"]
CMD ["--config", "/config/config.toml", "--datadir", "/data"]
