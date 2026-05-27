use crate::services::hello_service::hello_service;
use axum::{routing::get, Router};

pub mod dashboard_routes;
pub mod payment_routes;
pub mod protection_routes;
pub mod scan_routes;
pub mod scamsniffer_proxy_routes;
pub mod subscription_routes;
pub mod wallet_routes;

pub fn api_routes(pool: crate::db::DbPool) -> Router {
    Router::new()
        .route("/hello", get(hello_service))
        .nest("/wallets", wallet_routes::wallet_routes())
        .nest("/subscriptions", subscription_routes::subscription_routes())
        .nest("/payments", payment_routes::payment_routes())
        .nest("/dashboard", dashboard_routes::dashboard_routes())
        .nest("/scan-contract", scan_routes::scan_routes())
        .nest("/protection", protection_routes::protection_routes())
        .nest("/telemetry", protection_routes::telemetry_routes())
        .with_state(pool)
}
