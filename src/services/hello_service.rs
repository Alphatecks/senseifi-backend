use crate::repositories::hello_repository;
use axum::Json;
use serde_json::json;

pub async fn hello_service() -> Json<serde_json::Value> {
    let hello = hello_repository::get_hello_message();
    Json(json!({ "message": hello.message }))
}
