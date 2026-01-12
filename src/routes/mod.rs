use axum::{Router, routing::get};
use crate::services::hello_service::hello_service;

pub fn api_routes() -> Router {
    Router::new()
        .route("/hello", get(hello_service))
}
