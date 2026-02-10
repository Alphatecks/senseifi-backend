
use axum::Router;
use std::net::SocketAddr;


mod routes;
mod services;
mod models;
mod repositories;

#[tokio::main]
async fn main() {
    dotenv::dotenv().ok();
    tracing_subscriber::fmt::init();

    let app = Router::new()
        .nest("/api", routes::api_routes());

    // Render uses PORT env var, fallback to BIND_ADDRESS or default
    let port = std::env::var("PORT")
        .ok()
        .and_then(|p| p.parse::<u16>().ok())
        .unwrap_or(3000);
    let host = std::env::var("HOST")
        .unwrap_or_else(|_| "0.0.0.0".to_string());
    let addr: SocketAddr = format!("{}:{}", host, port)
        .parse()
        .expect("Invalid address");
    println!("Listening on {}", addr);
    axum::serve(
        tokio::net::TcpListener::bind(addr).await.unwrap(),
        app
    )
    .await
    .unwrap();
}
