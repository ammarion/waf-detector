# Multi-stage Dockerfile for WAF Detector

# Build stage
FROM rust:1.75-slim as builder

# Install dependencies
RUN apt-get update && apt-get install -y \
    pkg-config \
    libssl-dev \
    ca-certificates \
    && rm -rf /var/lib/apt/lists/*

# Create app directory
WORKDIR /app

# Copy manifests
COPY Cargo.toml Cargo.lock ./

# Copy source code
COPY src ./src
COPY tests ./tests
COPY build.rs ./build.rs 2>/dev/null || true

# Build the application
RUN cargo build --release

# Runtime stage
FROM debian:bookworm-slim

# Install runtime dependencies
RUN apt-get update && apt-get install -y \
    ca-certificates \
    libssl3 \
    && rm -rf /var/lib/apt/lists/*

# Copy the binary from builder
COPY --from=builder /app/target/release/waf-detect /usr/local/bin/waf-detect

# Create non-root user
RUN useradd -m -u 1000 wafdetector

# Switch to non-root user
USER wafdetector

# Set the entrypoint
ENTRYPOINT ["waf-detect"]

# Default command (show help)
CMD ["--help"]