//! Apriori Rust Client
//!
//! A Rust client library for interacting with the Apriori RPC service,
//! with automatic JWT authentication, token management, and auto-refresh capabilities.

pub mod auth_client;
pub mod error;
pub mod signer;
pub mod token_store;
pub mod types;

pub use auth_client::{AuthClientConfig, AuthClientHttp, AuthClientNoop};
pub use error::{ClientError, Result};
pub use signer::Signer;
pub use token_store::TokenStore;
pub use types::AuthTokens;

