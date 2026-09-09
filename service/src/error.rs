//! Error types for Ceasefire Firewall Service

use serde::{Deserialize, Serialize};

pub type Result<T> = std::result::Result<T, ServiceError>;

#[derive(Debug, thiserror::Error)]
pub enum ServiceError {
    #[error("Database error: {0}")]
    Database(String),

    #[error("I/O error: {0}")]
    Io(#[from] std::io::Error),

    #[error("Driver error: {0}")]
    Driver(String),

    #[error("IPC error: {0}")]
    Ipc(String),

    #[error("Validation error: {0}")]
    Validation(String),

    #[error("Service error: {0}")]
    Service(String),

    #[error("Not found: {0}")]
    NotFound(String),

    #[error("Serialization error: {0}")]
    Serialization(String),

    #[error("WFP error: {0}")]
    Wfp(String),

    #[error("Unknown error: {0}")]
    Unknown(String),
}

impl From<Box<bincode::ErrorKind>> for ServiceError {
    fn from(err: Box<bincode::ErrorKind>) -> Self {
        ServiceError::Serialization(err.to_string())
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ErrorResponse {
    pub error: String,
    pub code: u16,
}

impl ErrorResponse {
    pub fn new(error: &ServiceError) -> Self {
        ErrorResponse {
            error: error.to_string(),
            code: error.code(),
        }
    }
}

impl ServiceError {
    fn code(&self) -> u16 {
        match self {
            ServiceError::Database(_) => 1001,
            ServiceError::Io(_) => 1002,
            ServiceError::Driver(_) => 1003,
            ServiceError::Ipc(_) => 1004,
            ServiceError::Validation(_) => 1005,
            ServiceError::Service(_) => 1006,
            ServiceError::NotFound(_) => 1007,
            ServiceError::Serialization(_) => 1008,
            ServiceError::Wfp(_) => 1009,
            ServiceError::Unknown(_) => 1000,
        }
    }
}