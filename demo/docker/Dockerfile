# Veriscan Demo Container
# =======================
# Multi-stage build: builder compiles the Rust binary; runtime provides a
# minimal environment with ClamAV, GPG, and demo fixtures.
#
# Build system dependencies for sequoia-openpgp crypto-rust backend:
#   - No C library dependencies (pure-Rust cryptography)
#
# Build: docker build -t veriscan-demo -f demo/docker/Dockerfile .
# Run:   docker run --rm -it -v $(pwd)/demo/out:/demo/out veriscan-demo

# ── Stage 1: Builder ────────────────────────────────────────────────────────
FROM rust:1.86-bookworm AS builder

WORKDIR /build

# Cache dependency compilation.
COPY Cargo.toml ./
COPY src/lib.rs src/lib.rs

# Create stub main to cache deps.
RUN mkdir -p src && echo 'fn main() {}' > src/main_stub.rs

# Copy real sources.
COPY src/ src/
COPY policies/ policies/

# Build the release binary.
RUN cargo build --release 2>&1

# ── Stage 2: Runtime ────────────────────────────────────────────────────────
FROM debian:bookworm-slim AS runtime

# Install ClamAV, GPG, and minimal utilities.
RUN apt-get update && \
    apt-get install -y --no-install-recommends \
        clamav \
        clamav-daemon \
        gnupg2 \
        ca-certificates \
        curl \
        jq \
        && \
    # Update ClamAV virus database (needs network during build).
    freshclam --no-warnings || true && \
    apt-get clean && \
    rm -rf /var/lib/apt/lists/*

# Copy compiled binary.
COPY --from=builder /build/target/release/veriscan /usr/local/bin/veriscan

# Copy demo scripts and policies.
COPY demo/ /demo/
COPY policies/ /policies/

# Create output directory.
RUN mkdir -p /demo/out /demo/keys /demo/fixtures/good \
    /demo/fixtures/tampered /demo/fixtures/unsigned /demo/fixtures/malware_sim

# Set up demo keys directory.
WORKDIR /demo

# Entrypoint runs the full demo sequence.
COPY demo/docker/entrypoint.sh /entrypoint.sh
RUN chmod +x /entrypoint.sh /demo/scripts/*.sh

ENV VERISCAN_LOG=info
ENV PATH="/usr/local/bin:${PATH}"

ENTRYPOINT ["/entrypoint.sh"]
