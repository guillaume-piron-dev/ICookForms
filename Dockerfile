# ICOokForms - Production Docker Image
# Multi-stage build for optimal size and security

# Build stage
FROM rust:1.83-alpine AS builder

# Install build dependencies
RUN apk add --no-cache \
    musl-dev \
    openssl-dev \
    pkgconfig \
    git

# Set working directory
WORKDIR /app

# Copy manifests
COPY Cargo.toml Cargo.lock ./

# Copy source code
COPY src ./src
COPY benches ./benches

# Build for release with musl target for static linking
RUN cargo build --locked --release --target x86_64-unknown-linux-musl

# Runtime stage
FROM alpine:latest

# Install CA certificates for HTTPS
RUN apk add --no-cache ca-certificates tzdata

# Create non-root user
RUN addgroup -g 1000 icookforms && \
    adduser -D -u 1000 -G icookforms icookforms

# Set working directory
WORKDIR /app

# Copy binary from builder
COPY --from=builder --chown=icookforms:icookforms \
    /app/target/x86_64-unknown-linux-musl/release/icookforms \
    /usr/local/bin/icookforms

# Create directories for data
RUN mkdir -p /app/data /app/reports && \
    chown -R icookforms:icookforms /app

# Switch to non-root user
USER icookforms

# Set environment variables
ENV RUST_LOG=info
ENV ICOOKFORMS_DATA_DIR=/app/data
ENV ICOOKFORMS_REPORTS_DIR=/app/reports

# Volume for persistent data
VOLUME ["/app/data", "/app/reports"]

# Health check
HEALTHCHECK --interval=30s --timeout=3s --start-period=5s --retries=3 \
    CMD icookforms version || exit 1

# Default command
ENTRYPOINT ["icookforms"]
CMD ["--help"]

# Metadata
LABEL maintainer="guillaume-piron-dev" \
      version="1.0.0" \
      description="ICOokForms - The World's Reference Cookie Audit Software" \
      org.opencontainers.image.source="https://github.com/guillaume-piron-dev/ICookForms" \
      org.opencontainers.image.documentation="https://github.com/guillaume-piron-dev/ICookForms/blob/main/README.md" \
      org.opencontainers.image.licenses="Apache-2.0"

# Usage examples:
# Build: docker build -t icookforms:latest .
# Run scan: docker run --rm icookforms scan https://example.com
# Run with volumes: docker run --rm -v $(pwd)/reports:/app/reports icookforms scan https://example.com --output /app/reports/report.json
