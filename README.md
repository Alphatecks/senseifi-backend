# Axum Layered/Modular Rust Backend

## Structure

- `src/main.rs`: Entry point, Axum server setup
- `src/routes/`: Route definitions
- `src/services/`: Business logic
- `src/repositories/`: Data access
- `src/models/`: Data models

## Running

1. Set environment variable (optional):
   ```sh
   export BIND_ADDRESS=127.0.0.1:3000
   ```
2. Run the server:
   ```sh
   cargo run
   ```
3. Test endpoint:
   - GET http://127.0.0.1:3000/api/hello

## Dependencies
- axum
- tokio (full)
- serde
- serde_json
- dotenv

## Example Endpoint
- `/api/hello` — Returns a message from the repository layer through all layers.
