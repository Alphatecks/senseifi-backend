// Example model for demonstration
use serde::{Serialize, Deserialize};

#[derive(Debug, Serialize, Deserialize)]
pub struct HelloModel {
    pub message: String,
}
