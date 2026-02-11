use axum::{Router, routing::get};
use crate::services::hello_service::hello_service;

pub mod wallet_routes;

pub fn api_routes(pool: crate::db::DbPool) -> Router {
    Router::new()
        .route("/hello", get(hello_service))
        .nest("/wallets", wallet_routes::wallet_routes())
        .with_state(pool)
}
