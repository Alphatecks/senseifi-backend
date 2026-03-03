use axum::Router;
use std::net::SocketAddr;
use std::time::Duration;
use tower_governor::{governor::GovernorConfigBuilder, GovernorLayer};
use tower_http::cors::{AllowOrigin, CorsLayer};
use tower_http::limit::RequestBodyLimitLayer;
use tower_http::set_header::SetResponseHeaderLayer;
use http::header::{HeaderName, HeaderValue, X_CONTENT_TYPE_OPTIONS, X_FRAME_OPTIONS};

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

    // CORS: restrict to allowed origins when ALLOWED_ORIGINS is set
    let cors = match std::env::var("ALLOWED_ORIGINS") {
        Ok(origins) => {
            let list: Vec<HeaderValue> = origins
                .split(',')
                .map(|s| s.trim())
                .filter(|s| !s.is_empty())
                .map(|s| HeaderValue::try_from(s).unwrap_or_else(|_| HeaderValue::from_static("")))
                .filter(|v| !v.as_bytes().is_empty())
                .collect();
            CorsLayer::new()
                .allow_origin(AllowOrigin::list(list))
                .allow_methods([http::Method::GET, http::Method::POST, http::Method::DELETE, http::Method::OPTIONS])
                .allow_headers([http::header::CONTENT_TYPE, http::header::AUTHORIZATION])
        }
        Err(_) => {
            // Dev fallback: allow same-origin and common localhost origins
            let list: Vec<HeaderValue> = [
                "http://localhost:3000",
                "http://127.0.0.1:3000",
                "http://localhost:5173",
                "http://127.0.0.1:5173",
            ]
            .iter()
            .map(|s| HeaderValue::from_static(s))
            .collect();
            CorsLayer::new()
                .allow_origin(AllowOrigin::list(list))
                .allow_methods([http::Method::GET, http::Method::POST, http::Method::DELETE, http::Method::OPTIONS])
                .allow_headers([http::header::CONTENT_TYPE, http::header::AUTHORIZATION])
        }
    };

    // Rate limiting: per-IP, configurable via env
    let rate_per_sec = std::env::var("RATE_LIMIT_PER_SEC")
        .ok()
        .and_then(|s| s.parse::<u64>().ok())
        .unwrap_or(10);
    let burst = std::env::var("RATE_LIMIT_BURST")
        .ok()
        .and_then(|s| s.parse::<u32>().ok())
        .unwrap_or(20);
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

    let app = Router::new()
        .nest("/api", routes::api_routes(pool))
        .layer(cors)
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
        ));

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
