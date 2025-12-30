//! Error types for the Apriori client

use thiserror::Error;

/// Client error types
#[derive(Error, Debug)]
pub enum ClientError {
    #[error("HTTP request failed: {0}")]
    HttpRequest(#[from] reqwest::Error),

    #[error("Serialization error: {0}")]
    Serialization(#[from] serde_json::Error),

    #[error("Cryptography error: {0}")]
    Crypto(String),

    #[error("Authentication failed: {0}")]
    Authentication(String),

    #[error("Token expired")]
    TokenExpired,

    #[error("Invalid response: {0}")]
    InvalidResponse(String),

    #[error("Configuration error: {0}")]
    Configuration(String),
}

pub type Result<T> = std::result::Result<T, ClientError>;

