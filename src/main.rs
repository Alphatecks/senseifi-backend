use axum::Router;
use std::net::SocketAddr;
use std::time::Duration;
use tower_governor::{governor::GovernorConfigBuilder, GovernorLayer};
use tower_http::cors::{AllowOrigin, CorsLayer};
use tower_http::limit::RequestBodyLimitLayer;
use tower_http::set_header::SetResponseHeaderLayer;
use http::header::{HeaderName, HeaderValue, X_CONTENT_TYPE_OPTIONS, X_FRAME_OPTIONS};

mod clients;
mod routes;
mod services;
mod models;
mod repositories;
mod db;

#[tokio::main]
async fn main() {
    dotenv::dotenv().ok();
    tracing_subscriber::fmt::init();

    let database_url = std::env::var("DATABASE_URL")
        .expect("DATABASE_URL must be set");

    let pool = db::create_pool(&database_url)
        .await
        .expect("Failed to create database pool");

    db::init_db(&pool)
        .await
        .expect("Failed to run database migrations");

    println!("Database connected and migrations completed");

    // Log scanner env so you can confirm keys are loaded (no values logged)
    let has_etherscan = std::env::var("ETHERSCAN_API_KEY").ok().filter(|s| !s.is_empty()).is_some();
    let has_rpc = std::env::var("ETHEREUM_RPC_URL").ok().filter(|s| !s.is_empty()).is_some();
    tracing::info!("Contract scanner env: ETHERSCAN_API_KEY={}, ETHEREUM_RPC_URL={}", has_etherscan, has_rpc);

    // CORS: allow frontend origins. Always include localhost so local dev works.
    // Set ALLOWED_ORIGINS (comma-separated) for production, e.g. https://your-app.vercel.app
    let dev_origins: [&str; 4] = [
        "http://localhost:3000",
        "http://127.0.0.1:3000",
        "http://localhost:5173",
        "http://127.0.0.1:5173",
    ];
    let mut list: Vec<HeaderValue> = dev_origins
        .iter()
        .map(|s| HeaderValue::from_static(s))
        .collect();
    if let Ok(origins) = std::env::var("ALLOWED_ORIGINS") {
        for s in origins.split(',') {
            let s = s.trim();
            if s.is_empty() {
                continue;
            }
            if let Ok(v) = HeaderValue::try_from(s) {
                if !v.as_bytes().is_empty() && !list.iter().any(|e| e.as_bytes() == v.as_bytes()) {
                    list.push(v);
                }
            }
        }
    }
    let cors = CorsLayer::new()
        .allow_origin(AllowOrigin::list(list))
        .allow_methods([
            http::Method::GET,
            http::Method::POST,
            http::Method::PUT,
            http::Method::DELETE,
            http::Method::OPTIONS,
        ])
        .allow_headers([http::header::CONTENT_TYPE, http::header::AUTHORIZATION])
        .max_age(Duration::from_secs(86400));

    // Rate limiting: per-IP. Higher defaults so dashboard polling (e.g. activity every few sec) doesn't 429.
    let rate_per_sec = std::env::var("RATE_LIMIT_PER_SEC")
        .ok()
        .and_then(|s| s.parse::<u64>().ok())
        .unwrap_or(30);
    let burst = std::env::var("RATE_LIMIT_BURST")
        .ok()
        .and_then(|s| s.parse::<u32>().ok())
        .unwrap_or(60);
    let governor_conf = GovernorConfigBuilder::default()
        .per_second(rate_per_sec)
        .burst_size(burst)
        .finish()
        .expect("governor config");
    let governor_limiter = governor_conf.limiter().clone();
    let cleanup_interval = Duration::from_secs(60);
    std::thread::spawn(move || loop {
        std::thread::sleep(cleanup_interval);
        governor_limiter.retain_recent();
    });

    // Layer order: last added = outermost. CORS must be outermost so every response
    // (including 429 from rate limit, 404, 5xx) gets CORS headers.
    let app = Router::new()
        .nest("/api", routes::api_routes(pool))
        .layer(GovernorLayer::new(governor_conf))
        .layer(RequestBodyLimitLayer::new(256 * 1024)) // 256 KiB max body
        .layer(SetResponseHeaderLayer::overriding(
            X_CONTENT_TYPE_OPTIONS,
            HeaderValue::from_static("nosniff"),
        ))
        .layer(SetResponseHeaderLayer::overriding(
            X_FRAME_OPTIONS,
            HeaderValue::from_static("DENY"),
        ))
        .layer(SetResponseHeaderLayer::overriding(
            HeaderName::from_static("referrer-policy"),
            HeaderValue::from_static("strict-origin-when-cross-origin"),
        ))
        .layer(cors);

    let port = std::env::var("PORT")
        .ok()
        .and_then(|p| p.parse::<u16>().ok())
        .unwrap_or(3000);
    let host = std::env::var("HOST").unwrap_or_else(|_| "0.0.0.0".to_string());
    let addr: SocketAddr = format!("{}:{}", host, port)
        .parse()
        .expect("Invalid address");
    println!("Listening on {}", addr);

    let listener = tokio::net::TcpListener::bind(addr).await.unwrap();
    axum::serve(listener, app.into_make_service_with_connect_info::<SocketAddr>())
        .await
        .unwrap();
}
