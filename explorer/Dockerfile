# Quantix Explorer Docker Image
# Build: docker build -t quantix/explorer:latest .
# Run:   docker run -p 3000:3000 -e RPC_URL=http://node:8545 quantix/explorer:latest

# Build stage
FROM golang:1.22-alpine AS builder

RUN apk add --no-cache git

WORKDIR /build

# Copy go mod files
COPY go.mod go.sum ./
RUN go mod download

# Copy source
COPY . .

# Build explorer
RUN CGO_ENABLED=0 GOOS=linux go build -ldflags="-s -w" -o explorer ./explorer

# Runtime stage
FROM alpine:3.19

RUN apk add --no-cache ca-certificates tzdata

RUN addgroup -g 1000 explorer && \
    adduser -u 1000 -G explorer -h /home/explorer -D explorer

WORKDIR /home/explorer

COPY --from=builder /build/explorer /usr/local/bin/

USER explorer

EXPOSE 3000

HEALTHCHECK --interval=30s --timeout=5s --start-period=5s --retries=3 \
    CMD wget -qO- http://localhost:3000/health || exit 1

ENTRYPOINT ["explorer"]
CMD ["--addr", ":3000"]
