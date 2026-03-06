use crate::db::DbPool;
use crate::models::wallet::DashboardUser;
use sqlx::Error;

pub struct DashboardUserRepository;

impl DashboardUserRepository {
    pub async fn get_by_wallet(pool: &DbPool, wallet_address: &str) -> Result<Option<DashboardUser>, Error> {
        let row = sqlx::query_as::<_, (String, String, i32)>(
            "SELECT user_id, display_name, user_number FROM dashboard_users WHERE wallet_address = $1",
        )
        .bind(wallet_address)
        .fetch_optional(pool)
        .await?;
        Ok(row.map(|(user_id, display_name, user_number)| DashboardUser {
            user_id,
            display_name,
            user_number,
        }))
    }

    pub async fn get_by_user_id(pool: &DbPool, user_id: &str) -> Result<Option<DashboardUser>, Error> {
        let row = sqlx::query_as::<_, (String, String, i32)>(
            "SELECT user_id, display_name, user_number FROM dashboard_users WHERE user_id = $1",
        )
        .bind(user_id)
        .fetch_optional(pool)
        .await?;
        Ok(row.map(|(user_id, display_name, user_number)| DashboardUser {
            user_id,
            display_name,
            user_number,
        }))
    }

    pub async fn create(
        pool: &DbPool,
        wallet_address: &str,
        user_id: &str,
        display_name: &str,
        user_number: i32,
    ) -> Result<DashboardUser, Error> {
        sqlx::query(
            r#"
            INSERT INTO dashboard_users (wallet_address, user_id, display_name, user_number, created_at, updated_at)
            VALUES ($1, $2, $3, $4, NOW(), NOW())
            ON CONFLICT (wallet_address)
            DO UPDATE SET user_id = EXCLUDED.user_id, display_name = EXCLUDED.display_name,
                          user_number = EXCLUDED.user_number, updated_at = NOW()
            "#,
        )
        .bind(wallet_address)
        .bind(user_id)
        .bind(display_name)
        .bind(user_number)
        .execute(pool)
        .await?;

        let out = Self::get_by_wallet(pool, wallet_address)
            .await?
            .ok_or(Error::RowNotFound)?;
        Ok(out)
    }
}
