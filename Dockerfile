# syntax=docker/dockerfile:1

# ─────────────────────────────────────────────
# Stage 1: Builder
# ─────────────────────────────────────────────
FROM golang:1.24-bookworm AS builder

RUN apt-get update && apt-get install -y --no-install-recommends git gcc libc-dev

WORKDIR /app
COPY go.mod go.sum ./
COPY src/crypto/SPHINCSPLUS-golang ./src/crypto/SPHINCSPLUS-golang
RUN go mod download
COPY . .

RUN go build -o bin/quantix ./src/cli/main.go

# ─────────────────────────────────────────────
# Stage 2: Runtime
# ─────────────────────────────────────────────
FROM debian:bookworm-slim

RUN apt-get update && apt-get install -y --no-install-recommends \
    ca-certificates \
    curl \
    && rm -rf /var/lib/apt/lists/*

# Non-root user
# RUN useradd -r -u 1000 -m -d /home/quantix quantix

WORKDIR /app
COPY --from=builder /app/bin/quantix .

RUN mkdir -p /app/data
VOLUME ["/app/data"]

# USER quantix

# Port legend:
#   8560  — HTTP RPC API
#   32307 — P2P TCP + UDP (peer networking / DHT)
#   8700  — WebSocket (real-time events)
EXPOSE 8560 32307 8700

ENTRYPOINT ["./quantix"]
