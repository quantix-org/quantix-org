# syntax=docker/dockerfile:1

# ─────────────────────────────────────────────
# Stage 1: Builder
# ─────────────────────────────────────────────
FROM golang:1.24 AS builder

WORKDIR /build

# Cache dependencies first
COPY go.mod go.sum ./
RUN go mod download

# Copy source
COPY . .

# Build the CLI binary (headless node — no GUI)
RUN CGO_ENABLED=0 GOOS=linux go build \
    -ldflags="-s -w" \
    -o /usr/local/bin/quantix \
    ./src/cli

# ─────────────────────────────────────────────
# Stage 2: Runtime
# ─────────────────────────────────────────────
FROM debian:bookworm-slim

RUN apt-get update && apt-get install -y --no-install-recommends \
    ca-certificates \
    curl \
    && rm -rf /var/lib/apt/lists/*

# Create non-root user
RUN useradd -r -u 1000 -m -d /home/quantix quantix

COPY --from=builder /usr/local/bin/quantix /usr/local/bin/quantix

# Data directory
RUN mkdir -p /data && chown quantix:quantix /data
VOLUME ["/data"]

USER quantix
WORKDIR /data

# Port legend:
#   8560  — HTTP RPC API
#   32421 — P2P TCP (peer networking)
#   8700  — WebSocket (real-time events)
EXPOSE 8560 32421 8700

ENTRYPOINT ["quantix"]
CMD ["--help"]
