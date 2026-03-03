# Security

## What’s in place

- **Security headers**  
  Every response includes:
  - `X-Content-Type-Options: nosniff`
  - `X-Frame-Options: DENY`
  - `Referrer-Policy: strict-origin-when-cross-origin`

- **CORS**  
  - If `ALLOWED_ORIGINS` is set (comma-separated list), only those origins are allowed.  
  - If not set, a dev default allows common localhost origins (3000, 5173).  
  - Allowed methods: GET, POST, DELETE, OPTIONS.  
  - Allowed headers: `Content-Type`, `Authorization`.

- **Rate limiting**  
  Per-IP limits to reduce abuse and DoS:
  - `RATE_LIMIT_PER_SEC` (default: 10) – refill rate.
  - `RATE_LIMIT_BURST` (default: 20) – burst size.  
  When exceeded, the client gets HTTP 429. Use `into_make_service_with_connect_info` so the server sees client IP (and, behind a proxy, set `X-Forwarded-For` / `X-Real-IP` if you use a key extractor that reads them).

- **Request body limit**  
  Max 256 KiB per request to avoid large-body DoS.

- **Input validation**  
  - Wallet `address`: must be `0x` + 40 hex chars (Ethereum style).  
  - `chain_id`: must be in `1..=999_999`.  
  - `wallet_type`: allowlist `metamask`, `coinbase`.  
  Path and JSON inputs are validated before use.

- **No sensitive error detail**  
  API responses do not expose internal errors or stack traces; only generic messages for failures. Details are logged server-side only.

- **Parameterized SQL**  
  All DB access uses SQLx with bound parameters (no raw string interpolation), reducing SQL injection risk.

## What you should add for production

1. **Authentication and authorization**  
   Endpoints are currently unauthenticated. Add:
   - Session or JWT (or API keys) for user identity.
   - Authorization so users can only access their own wallets (e.g. bind wallet to user and check on each request).

2. **HTTPS**  
   Run behind TLS (e.g. Render, Cloudflare, or a reverse proxy). Do not send secrets over plain HTTP.

3. **Secrets**  
   - Keep `DATABASE_URL` and any API keys in env (or a secrets manager), never in code or logs.  
   - Use different DB and keys per environment (dev/staging/prod).

4. **Dependencies**  
   - Run `cargo audit` and fix reported vulnerabilities.  
   - Keep dependencies up to date.

5. **Logging**  
   - Avoid logging request/response bodies or headers that may contain tokens or PII.  
   - Use structured logging and level (e.g. `RUST_LOG`) so production logs are useful without leaking secrets.

## Environment variables (security-related)

| Variable            | Purpose |
|---------------------|--------|
| `ALLOWED_ORIGINS`   | Comma-separated CORS origins (e.g. `https://app.example.com`). Set in production. |
| `RATE_LIMIT_PER_SEC`| Rate limit refill (default: 10). |
| `RATE_LIMIT_BURST`  | Rate limit burst size (default: 20). |
| `DATABASE_URL`      | PostgreSQL URL. Keep secret, use strong DB credentials. |

## Reporting issues

If you find a security bug, report it privately (e.g. maintainer email or private issue) rather than in a public issue.
