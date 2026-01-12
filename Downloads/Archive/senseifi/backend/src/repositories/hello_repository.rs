// Example repository for demonstration
use crate::models::hello_model::HelloModel;

pub fn get_hello_message() -> HelloModel {
    HelloModel {
        message: "Hello from the repository layer!".to_string(),
    }
}
