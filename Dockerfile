# Use the official Rust image as the build environment
FROM rust:1.76 as builder

# Set the working directory
WORKDIR /app

# Copy the manifest and source
COPY Cargo.toml Cargo.lock ./
COPY src ./src

# Build the application in release mode
RUN cargo build --release

# Use a minimal base image for the runtime
FROM debian:buster-slim

# Install needed system dependencies
RUN apt-get update && apt-get install -y libssl-dev ca-certificates && rm -rf /var/lib/apt/lists/*

# Create a non-root user
RUN useradd -m appuser

# Copy the compiled binary from the builder
COPY --from=builder /app/target/release/backend /usr/local/bin/backend

# Set permissions
RUN chown appuser:appuser /usr/local/bin/backend

# Switch to the non-root user
USER appuser

# Expose the port (change if your app uses a different port)
EXPOSE 3000

# Set the startup command
CMD ["/usr/local/bin/backend"]
