//! Type definitions for authentication

/// Authentication tokens (access + refresh)
#[derive(Debug, Clone)]
pub struct AuthTokens {
    pub access_token: String,
    pub refresh_token: String,
    pub expires_in_secs: u64,
    pub issued_at_secs: i64,
    /// User role (0=Searcher, 1=Builder, 2=Relayer, 3=Fullnode)
    /// Needed for re-authentication when refresh token expires
    pub role: i32,
}

impl AuthTokens {
    pub fn should_refresh(&self, now: i64, refresh_before_expiry_secs: u64) -> bool {
        let expires_at = self.issued_at_secs + self.expires_in_secs as i64;
        let time_until_expiry = expires_at - now;

        time_until_expiry < refresh_before_expiry_secs as i64
    }

    /// Check if access token is expired
    pub fn is_expired(&self) -> bool {
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_secs() as i64;

        let expires_at = self.issued_at_secs + self.expires_in_secs as i64;
        now >= expires_at
    }
}