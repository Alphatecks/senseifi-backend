pub mod hello_service;

use axum::Json;
use crate::repositories::hello_repository;
use crate::models::hello_model::HelloModel;
use serde_json::json;

pub async fn hello_service() -> Json<serde_json::Value> {
	let hello = hello_repository::get_hello_message();
	Json(json!({ "message": hello.message }))
}
