// Example model for demonstration
use serde::{Deserialize, Serialize};

#[derive(Debug, Serialize, Deserialize)]
pub struct HelloModel {
    pub message: String,
}
