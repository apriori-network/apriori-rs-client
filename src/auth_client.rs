// Human: Authentication client with automatic token management and refresh

use crate::error::{ClientError, Result};
use crate::signer::Signer;
use crate::token_store::TokenStore;
use crate::types::*;
use apriori_mev_dto::{AuthRequest, AuthResponse, ChallengeRequest, ChallengeResponse, RefreshRequest, RefreshResponse};
use async_singleflight::Group;
use reqwest::Client;
use std::future::Future;
use std::sync::Arc;
use std::time::Duration;
use tracing::{debug, info, warn};

/// Macro to check HTTP response status and return error if not successful
macro_rules! check_response {
    ($response:expr, $error_msg:expr) => {
        if !$response.status().is_success() {
            let status = $response.status();
            let text = $response.text().await.unwrap_or_default();
            return Err(ClientError::Authentication(format!(
                "{} with status {}: {}",
                $error_msg, status, text
            )));
        }
    };
}

/// Configuration for the authentication client
#[derive(Debug, Clone)]
pub struct AuthClientConfig {
    /// Private key in hex format (with or without "0x" prefix)
    /// The public key (Ethereum address) will be automatically derived from this.
    pub private_key_hex: String,

    /// Refresh threshold in seconds (refresh when this many seconds before expiry)
    /// Default: 60 seconds
    pub refresh_before_expiry_secs: u64,

    /// Auto-refresh check interval in seconds
    /// Default: 30 seconds
    pub refresh_check_interval_secs: u64,

    /// User role (0=Searcher, 1=Builder, 2=Relayer, 3=Fullnode)
    pub role: i32,
}

impl AuthClientConfig {
    pub fn new(private_key_hex: String, refresh_before_expiry_secs: u64, refresh_check_interval_secs: u64, role: apriori_mev_dto::Role) -> Self {
        Self {
            private_key_hex,
            refresh_before_expiry_secs,
            refresh_check_interval_secs,
            role: role as i32,
        }
    }
}

/// Base authentication client trait
///
/// Provides basic token management functionality
pub trait AuthClient: Send + Sync + 'static {
    /// Get the current access token for an endpoint
    ///
    /// This method handles all token scenarios automatically:
    /// - No tokens: performs full authentication
    /// - Valid token: returns immediately
    /// - Expired access token: refreshes the token
    /// - Expired refresh token: re-authenticates
    ///
    /// # Arguments
    /// * `endpoint` - Server endpoint URL
    fn get_access_token(&self, endpoint: &str) -> impl Future<Output=Result<String>> + Send;
}

/// No-op authentication client for testing or unauthenticated scenarios
pub struct AuthClientNoop {}

impl AuthClient for AuthClientNoop {
    async fn get_access_token(&self, _endpoint: &str) -> Result<String> {
        Ok(String::new())
    }
}

impl AuthClientNoop {
    pub fn new() -> Arc<Self> {
        Arc::new(Self {})
    }
}


/// Authentication client with automatic token management
///
/// Manages authentication tokens for multiple endpoints
pub struct AuthClientHttp {
    config: AuthClientConfig,
    signer: Signer,
    token_store: TokenStore,
    http_client: Client,
    /// Singleflight group to prevent concurrent token refresh/authentication for the same endpoint
    /// Error type is String because singleflight requires shared error type
    token_refresh_singleflight: Group<String, String>,
}

impl AuthClientHttp {
    /// Create a new authentication client
    ///
    /// # Arguments
    /// * `config` - Client configuration (includes private key hex string)
    ///
    /// The public key (Ethereum address) is automatically derived from the private key.
    pub fn new(config: AuthClientConfig) -> Result<Arc<Self>> {
        // Create signer from config (pubkey is automatically derived)
        let signer = Signer::new(&config.private_key_hex)?;

        let client = Arc::new(Self {
            config,
            signer,
            token_store: TokenStore::new(),
            http_client: Client::new(),
            token_refresh_singleflight: Group::new(),
        });

        // Start auto-refresh task on creation
        let client_ref = Arc::clone(&client);
        tokio::spawn(async move {
            client_ref.run_refresh_task().await;
        });

        Ok(client)
    }

    async fn do_refresh_or_auth_singleflight(&self, endpoint: &str) -> Result<String> {
        // Use singleflight to deduplicate concurrent token refresh/authentication requests
        // This ensures only one task per endpoint performs the actual refresh/auth operation
        let endpoint_key = endpoint.to_string();
        let (success_opt, error_opt, _shared) = self.token_refresh_singleflight.work(&endpoint_key, async {
            // Refresh or authenticate (do_refresh_or_auth handles both scenarios)
            match self.do_refresh_or_auth(&endpoint_key).await {
                Ok(new_tokens) => Ok(new_tokens.access_token),
                Err(e) => {
                    let err_msg = e.to_string();
                    warn!(endpoint = %endpoint_key, error = %err_msg, "Token refresh/authentication failed");
                    Err(err_msg)
                }
            }
        }).await;

        // Convert singleflight result to Result type
        match (success_opt, error_opt) {
            (Some(token), None) => Ok(token),
            (None, Some(err_str)) => Err(ClientError::Authentication(err_str)),
            _ => Err(ClientError::Authentication("Unknown error during token refresh".to_string())),
        }
    }
}

impl AuthClient for AuthClientHttp {
    async fn get_access_token(&self, endpoint: &str) -> Result<String> {
        // Fast path: check if we have valid tokens without singleflight
        if let Some(tokens) = self.token_store.get(endpoint) {
            if !tokens.is_expired() {
                return Ok(tokens.access_token);
            }
        }

        self.do_refresh_or_auth_singleflight(endpoint).await
    }
}

impl AuthClientHttp {
    /// Run the automatic token refresh task
    ///
    /// This task periodically checks all endpoints and refreshes tokens that are about to expire
    async fn run_refresh_task(&self) {
        info!(
            check_interval_secs = %self.config.refresh_check_interval_secs,
            refresh_before_expiry_secs = %self.config.refresh_before_expiry_secs,
            "Started auto-refresh task"
        );

        let mut interval = tokio::time::interval(Duration::from_secs(self.config.refresh_check_interval_secs));

        loop {
            interval.tick().await;

            // Get current time once per iteration
            let now = std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_secs() as i64;

            // Get all endpoints with tokens
            let endpoints = self.token_store.endpoints();

            // Filter endpoints that need refresh (without calling get_time repeatedly)
            let mut endpoints_to_refresh = Vec::new();
            for endpoint in endpoints {
                if let Some(tokens) = self.token_store.get(&endpoint) {
                    if tokens.should_refresh(now, self.config.refresh_before_expiry_secs) {
                        endpoints_to_refresh.push((endpoint, tokens));
                    }
                }
            }

            // Refresh tokens for filtered endpoints
            if !endpoints_to_refresh.is_empty() {
                debug!(
                    count = %endpoints_to_refresh.len(),
                    "Found endpoints that need token refresh"
                );

                for (endpoint, _tokens) in endpoints_to_refresh {
                    debug!(
                        endpoint = %endpoint,
                        role = %self.config.role,
                        "Refreshing token"
                    );

                    // Call get_access_token which will use singleflight to deduplicate
                    // If another task is already refreshing, this will wait and reuse the result
                    match self.do_refresh_or_auth_singleflight(&endpoint).await {
                        Ok(_) => {
                            info!(
                                endpoint = %endpoint,
                                "Auto-refresh successful"
                            );
                        }
                        Err(e) => {
                            warn!(
                                endpoint = %endpoint,
                                error = %e,
                                "Auto-refresh failed"
                            );
                            // Don't panic, the next access will return an error
                        }
                    }
                }
            }
        }
    }

    /// Helper method to perform token refresh or authentication
    ///
    /// This method handles both scenarios:
    /// - If tokens exist: tries to refresh, falls back to re-authentication if refresh fails
    /// - If no tokens: performs full authentication
    async fn do_refresh_or_auth(&self, endpoint: &str) -> Result<AuthTokens> {
        // Check if we have existing tokens to refresh
        if let Some(tokens) = self.token_store.get(endpoint) {
            // Try to refresh
            let url = format!("{endpoint}/auth/refresh");

            let request = RefreshRequest {
                refresh_token: tokens.refresh_token.clone(),
            };

            let response = self.http_client
                .post(&url)
                .json(&request)
                .send()
                .await?;

            if !response.status().is_success() {
                let status = response.status();
                let error_text = response.text().await.unwrap_or_default();
                warn!(
                    endpoint = %endpoint,
                    status = %status,
                    error = %error_text,
                    "Token refresh failed, attempting re-authentication"
                );

                // Refresh token likely expired, fall through to authenticate
            } else {
                // Refresh succeeded
                let refresh_response: RefreshResponse = response.json().await?;

                let now = std::time::SystemTime::now()
                    .duration_since(std::time::UNIX_EPOCH)
                    .unwrap()
                    .as_secs() as i64;

                let new_tokens = AuthTokens {
                    access_token: refresh_response.access_token,
                    refresh_token: tokens.refresh_token.clone(),
                    expires_in_secs: tokens.expires_in_secs,
                    issued_at_secs: now,
                    role: tokens.role,
                };

                self.token_store.store(endpoint.to_string(), new_tokens.clone());
                info!(endpoint = %endpoint, "Access token refreshed successfully");

                return Ok(new_tokens);
            }
        }

        // No tokens or refresh failed, perform full authentication
        self.do_authenticate(endpoint).await
    }

    /// Helper method to perform full authentication
    ///
    /// This performs the full authentication flow: challenge -> sign -> auth
    async fn do_authenticate(&self, endpoint: &str) -> Result<AuthTokens> {
        // Step 1: Request challenge
        let challenge_url = format!("{endpoint}/auth/challenge");
        let challenge_request = ChallengeRequest {
            pubkey: format!("0x{}", self.signer.pubkey_hex()),
            role: self.config.role,
        };

        let challenge_response = self.http_client
            .post(&challenge_url)
            .json(&challenge_request)
            .send()
            .await?;

        check_response!(challenge_response, "Challenge request failed");

        let challenge: ChallengeResponse = challenge_response.json().await?;

        // Step 2: Sign challenge
        let signature = self.signer.sign_challenge(&challenge.challenge)?;

        // Step 3: Authenticate
        let auth_url = format!("{endpoint}/auth/authenticate");
        let auth_request = AuthRequest {
            pubkey: format!("0x{}", self.signer.pubkey_hex()),
            challenge: challenge.challenge,
            sig: signature,
        };

        let auth_response = self.http_client
            .post(&auth_url)
            .json(&auth_request)
            .send()
            .await?;

        check_response!(auth_response, "Authentication failed");

        let auth_result: AuthResponse = auth_response.json().await?;

        // Step 4: Store tokens
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_secs() as i64;

        let tokens = AuthTokens {
            access_token: auth_result.access_token,
            refresh_token: auth_result.refresh_token,
            expires_in_secs: auth_result.expires_in_secs as u64,
            issued_at_secs: now,
            role: self.config.role,
        };

        self.token_store.store(endpoint.to_string(), tokens.clone());

        Ok(tokens)
    }

    /// Get the token store (for advanced usage)
    pub fn token_store(&self) -> &TokenStore {
        &self.token_store
    }
}






