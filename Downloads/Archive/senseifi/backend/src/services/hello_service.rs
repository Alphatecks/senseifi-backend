use axum::Json;
use serde_json::json;

pub async fn hello_service() -> Json<serde_json::Value> {
    Json(json!({ "message": "Hello from the service layer!" }))
}
