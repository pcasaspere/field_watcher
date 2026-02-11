# Multi-stage build for Field Watcher (amd64 Linux)
FROM rust:1-bookworm AS builder

# Install system dependencies
RUN apt-get update && apt-get install -y \
    libpcap-dev \
    pkg-config \
    libsqlite3-dev \
    gcc \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /usr/src/field_watcher
COPY . .

# Build the application
RUN cargo build --release

# Final stage
FROM debian:bookworm-slim

# Install runtime dependencies
RUN apt-get update && apt-get install -y \
    libpcap0.8 \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /app
COPY --from:builder /usr/src/field_watcher/target/release/field_watcher .

# Run the binary
ENTRYPOINT ["./field_watcher"]
