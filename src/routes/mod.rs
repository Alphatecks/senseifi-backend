use axum::{Router, routing::get};
use crate::services::hello_service::hello_service;

pub mod dashboard_routes;
pub mod protection_routes;
pub mod scan_routes;
pub mod wallet_routes;

pub fn api_routes(pool: crate::db::DbPool) -> Router {
    Router::new()
        .route("/hello", get(hello_service))
        .nest("/wallets", wallet_routes::wallet_routes())
        .nest("/dashboard", dashboard_routes::dashboard_routes())
        .nest("/scan-contract", scan_routes::scan_routes())
        .nest("/protection", protection_routes::protection_routes())
        .with_state(pool)
}
