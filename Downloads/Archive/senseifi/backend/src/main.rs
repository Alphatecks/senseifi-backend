
use axum::Router;
use axum::serve;
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

    let addr: SocketAddr = std::env::var("BIND_ADDRESS")
        .unwrap_or_else(|_| "127.0.0.1:3000".to_string())
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
