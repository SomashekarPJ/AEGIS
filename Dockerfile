# ==========================================
# STAGE 1: Build the React SOC Dashboard
# ==========================================
FROM node:20-alpine AS frontend-builder
WORKDIR /app
COPY dashboard/package*.json ./
RUN npm install
COPY dashboard/ ./
RUN npm run build

# ==========================================
# STAGE 2: Build the Go Security Daemon & CLI
# ==========================================
FROM golang:1.21-alpine AS backend-builder
WORKDIR /app
RUN apk add --no-cache git gcc musl-dev
COPY go.mod ./
COPY pkg/ ./pkg/
COPY cmd/ ./cmd/
RUN go env -w GOPROXY=https://proxy.golang.org,direct
RUN go mod tidy
RUN CGO_ENABLED=0 GOOS=linux go build -ldflags="-s -w" -o aegisd cmd/aegisd/main.go
RUN CGO_ENABLED=0 GOOS=linux go build -ldflags="-s -w" -o aegis cmd/aegis/main.go

# ==========================================
# STAGE 3: Final Secure Execution Container
# ==========================================
FROM python:3.10-slim
WORKDIR /app

# Install standard security tools and utility packages
RUN apt-get update && apt-get install -y --no-install-recommends \
    iproute2 \
    procps \
    libc6 \
    && rm -rf /var/lib/apt/lists/*

# Copy binaries from builder stage
COPY --from=backend-builder /app/aegisd /usr/local/bin/aegisd
COPY --from=backend-builder /app/aegis /usr/local/bin/aegis

# Copy static dashboard frontend assets into app root (Go daemon automatically serves them)
COPY --from=frontend-builder /app/dist ./dist

# Copy threat simulation payload scripts and configurations
COPY demo/ ./demo/

# Expose Secure Daemon API and WebSocket broadcast socket
EXPOSE 8080

# Run Secure Daemon. Railway injects PORT; local Docker falls back to 8080.
CMD ["sh", "-c", "aegisd --port ${PORT:-8080} --db /app/data/audit_logs.jsonl"]
