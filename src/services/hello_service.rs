use axum::Json;
use serde_json::json;
use crate::repositories::hello_repository;

pub async fn hello_service() -> Json<serde_json::Value> {
    let hello = hello_repository::get_hello_message();
    Json(json!({ "message": hello.message }))
}
