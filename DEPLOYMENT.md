# Deployment Options for Senseifi Backend

This project includes three deployment options for Render. Choose the one that works best for you.

## Option 1: cargo-chef Dockerfile (RECOMMENDED - Fastest) ⚡

**File:** `Dockerfile` (already set as default)

**Why use it:**
- Fastest build times (2-3x faster than manual caching)
- Best Docker layer caching
- Dependencies cached separately from source code

**How to use:**
1. Make sure `Dockerfile` is in your repo (it already is)
2. In Render dashboard:
   - Service Type: Web Service
   - Build Command: (leave empty - uses Dockerfile automatically)
   - Start Command: (leave empty - uses Dockerfile CMD)
3. Deploy!

## Option 2: Native Rust Build (No Docker) 🚀

**File:** `render.yaml`

**Why use it:**
- Simpler setup
- No Docker overhead
- Faster for small projects
- Render handles Rust natively

**How to use:**
1. In Render dashboard, connect your GitHub repo
2. Render will detect `render.yaml` automatically
3. Or manually set:
   - Environment: Rust
   - Build Command: `cargo build --release`
   - Start Command: `./target/release/backend`
   - Environment Variables:
     - `PORT`: (auto-set by Render)
     - `HOST`: `0.0.0.0`
     - `RUST_LOG`: `info`

## Option 3: Manual Dockerfile (Backup)

**File:** `Dockerfile.manual`

**Why use it:**
- If cargo-chef has issues
- More straightforward caching approach

**How to use:**
1. Rename `Dockerfile.manual` to `Dockerfile`
2. Deploy normally

## Environment Variables

All options support these environment variables:

- `PORT`: Port to bind to (Render sets this automatically)
- `HOST`: Host to bind to (default: `0.0.0.0`)
- `RUST_LOG`: Logging level (default: `info`)
- `BIND_ADDRESS`: Legacy option (format: `host:port`)

## Troubleshooting

### Build Timeout
- Use Option 1 (cargo-chef) - it's the fastest
- Or use Option 2 (native build) - often faster than Docker

### Port Issues
- Make sure your app binds to `0.0.0.0`, not `127.0.0.1`
- The code now automatically uses Render's `PORT` variable

### Build Fails
- Check that `Cargo.lock` is committed
- Ensure all dependencies are in `Cargo.toml`
- Try Option 2 (native build) if Docker is problematic
