# Multi-stage Dockerfile using cargo-chef for optimal caching
# This is the FASTEST build option - recommended for Render

# Rust ≥1.78 required: Cargo.lock v4 (project + cargo-chef 0.1.77)
FROM rust:1.82-slim AS chef
WORKDIR /app
RUN apt-get update && apt-get install -y \
    pkg-config \
    libssl-dev \
    && rm -rf /var/lib/apt/lists/*
RUN cargo install cargo-chef --locked

FROM chef as planner
WORKDIR /app
COPY Cargo.toml Cargo.lock ./
COPY src ./src
RUN cargo chef prepare --recipe-path recipe.json

FROM chef as builder
WORKDIR /app
COPY --from=planner /app/recipe.json recipe.json
# Build dependencies (this layer will be cached unless Cargo.toml changes)
RUN cargo chef cook --release --recipe-path recipe.json
# Copy source code and build application
COPY . .
RUN cargo build --release --bin backend

# Runtime stage
FROM debian:bookworm-slim
RUN apt-get update && apt-get install -y \
    ca-certificates \
    libssl3 \
    && rm -rf /var/lib/apt/lists/*
RUN useradd -m -u 1000 appuser
COPY --from=builder /app/target/release/backend /usr/local/bin/backend
RUN chown appuser:appuser /usr/local/bin/backend
USER appuser
EXPOSE 3000
CMD ["/usr/local/bin/backend"]
