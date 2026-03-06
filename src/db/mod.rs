use sqlx::postgres::{PgConnectOptions, PgPoolOptions};
use sqlx::PgPool;
use std::str::FromStr;
use std::time::Duration;

pub type DbPool = PgPool;

/// Create the DB pool. Statement cache is disabled so that schema changes (e.g. new columns
/// from migrations) do not cause "cached plan must not change result type" after deploy.
pub async fn create_pool(database_url: &str) -> Result<DbPool, sqlx::Error> {
    let opts = PgConnectOptions::from_str(database_url)?
        .statement_cache_capacity(0);
    PgPoolOptions::new()
        .max_connections(10)
        .acquire_timeout(Duration::from_secs(30))
        .connect_with(opts)
        .await
}

pub async fn init_db(pool: &DbPool) -> Result<(), sqlx::Error> {
    sqlx::migrate!("./migrations")
        .run(pool)
        .await?;
    Ok(())
}
