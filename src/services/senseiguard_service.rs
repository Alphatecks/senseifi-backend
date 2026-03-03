use crate::db::DbPool;
use crate::models::senseiguard::{
    ActivityFeedItem, Alert, DashboardSummaryResponse, SecurityStatusResponse, SecurityScan,
    Threat, WalletAsset,
};
use crate::repositories::senseiguard_repository::SenseiguardRepository;
use crate::repositories::wallet_repository::WalletRepository;
use sqlx::Error;
use uuid::Uuid;

pub struct SenseiguardService;

impl SenseiguardService {
    async fn wallet_id_by_address(pool: &DbPool, address: &str) -> Result<Uuid, Error> {
        let wallet = WalletRepository::get_wallet_by_address(pool, address)
            .await?
            .ok_or(Error::RowNotFound)?;
        Ok(wallet.id)
    }

    pub async fn get_security_status(
        pool: &DbPool,
        address: &str,
    ) -> Result<SecurityStatusResponse, Error> {
        let wallet_id = Self::wallet_id_by_address(pool, address).await?;
        let latest = SenseiguardRepository::get_latest_scan(pool, wallet_id).await?;
        let (score, status, last_scan_at) = match &latest {
            Some(s) => (
                s.score,
                s.status.clone(),
                Some(s.scanned_at),
            ),
            None => {
                let sc: (i32,) = sqlx::query_as(
                    "SELECT COALESCE(security_score, 0) FROM wallet_monitoring WHERE wallet_id = $1",
                )
                .bind(wallet_id)
                .fetch_optional(pool)
                .await?
                .unwrap_or((0,));
                let at: (Option<chrono::DateTime<chrono::Utc>>,) = sqlx::query_as(
                    "SELECT last_scan_at FROM wallet_monitoring WHERE wallet_id = $1",
                )
                .bind(wallet_id)
                .fetch_optional(pool)
                .await?
                .unwrap_or((None,));
                (sc.0, Self::status_from_score(sc.0), at.0)
            }
        };
        let message = match status.as_str() {
            "strong" => "Your wallet is well protected. A few settings can be improved for stronger security.",
            "moderate" => "Your wallet has moderate protection. Run a scan and address the findings.",
            "weak" => "Your wallet needs attention. Run a full scan and fix critical issues.",
            _ => "Run a full scan to see your security status.",
        };
        Ok(SecurityStatusResponse {
            score,
            status,
            message: message.to_string(),
            last_scan_at,
        })
    }

    fn status_from_score(score: i32) -> String {
        match score {
            0..=39 => "weak".to_string(),
            40..=69 => "moderate".to_string(),
            _ => "strong".to_string(),
        }
    }

    pub async fn run_full_scan(pool: &DbPool, address: &str) -> Result<SecurityScan, Error> {
        let wallet_id = Self::wallet_id_by_address(pool, address).await?;
        // Placeholder: compute score (e.g. from existing threats, alerts). AI/real scanner later.
        let threats = SenseiguardRepository::count_threats_this_month(pool, wallet_id).await?;
        let high_risk = SenseiguardRepository::high_risk_alerts_count(pool, wallet_id).await?;
        let score = (100i32)
            .saturating_sub(threats as i32 * 5)
            .saturating_sub(high_risk as i32 * 10)
            .clamp(0, 100);
        SenseiguardRepository::create_scan(pool, wallet_id, score).await
    }

    pub async fn dashboard_summary(
        pool: &DbPool,
        address: &str,
    ) -> Result<DashboardSummaryResponse, Error> {
        let wallet_id = Self::wallet_id_by_address(pool, address).await?;
        let security_status = Self::get_security_status(pool, address).await?;
        let threats_this_month =
            SenseiguardRepository::count_threats_this_month(pool, wallet_id).await?;
        let scans_this_month =
            SenseiguardRepository::count_scans_this_month(pool, wallet_id).await?;
        let total_asset_usd = SenseiguardRepository::total_asset_usd(pool, wallet_id).await?;
        let unread_alerts = SenseiguardRepository::unread_alerts_count(pool, wallet_id).await?;
        let high_risk_alerts =
            SenseiguardRepository::high_risk_alerts_count(pool, wallet_id).await?;
        let issues_this_month =
            SenseiguardRepository::get_wallet_issues_this_month(pool, wallet_id).await?;

        Ok(DashboardSummaryResponse {
            security_status,
            threats_this_month,
            threats_trend_percent: -2.3,
            scans_this_month,
            scans_trend_percent: 2.3,
            total_asset_usd: format!("{:.2}", total_asset_usd),
            total_asset_trend_percent: 2.3,
            unread_alerts,
            high_risk_alerts,
            alerts_trend_percent: -2.3,
            issues_this_month,
        })
    }

    pub async fn list_threats(
        pool: &DbPool,
        address: &str,
        limit: i64,
    ) -> Result<Vec<Threat>, Error> {
        let wallet_id = Self::wallet_id_by_address(pool, address).await?;
        SenseiguardRepository::list_threats(pool, wallet_id, limit).await
    }

    pub async fn list_scans(
        pool: &DbPool,
        address: &str,
        limit: i64,
    ) -> Result<Vec<SecurityScan>, Error> {
        let wallet_id = Self::wallet_id_by_address(pool, address).await?;
        SenseiguardRepository::list_scans(pool, wallet_id, limit).await
    }

    pub async fn list_alerts(
        pool: &DbPool,
        address: &str,
        limit: i64,
    ) -> Result<Vec<Alert>, Error> {
        let wallet_id = Self::wallet_id_by_address(pool, address).await?;
        SenseiguardRepository::list_alerts(pool, wallet_id, limit).await
    }

    pub async fn list_activity(
        pool: &DbPool,
        address: &str,
        limit: i64,
    ) -> Result<Vec<ActivityFeedItem>, Error> {
        let wallet_id = Self::wallet_id_by_address(pool, address).await?;
        SenseiguardRepository::list_activity(pool, wallet_id, limit).await
    }

    pub async fn list_assets(pool: &DbPool, address: &str) -> Result<Vec<WalletAsset>, Error> {
        let wallet_id = Self::wallet_id_by_address(pool, address).await?;
        SenseiguardRepository::list_assets(pool, wallet_id).await
    }
}
