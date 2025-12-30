//! Thread-safe token storage using Papaya HashMap

use crate::types::AuthTokens;
use papaya::HashMap;
use std::sync::Arc;

/// Thread-safe token store using Papaya HashMap
///
/// Stores authentication tokens per endpoint URL
#[derive(Clone)]
pub struct TokenStore {
    tokens: Arc<HashMap<String, AuthTokens>>,
}

impl TokenStore {
    /// Create a new token store
    pub fn new() -> Self {
        Self {
            tokens: Arc::new(HashMap::new()),
        }
    }

    /// Store tokens for an endpoint
    pub fn store(&self, endpoint: String, tokens: AuthTokens) {
        self.tokens.pin().insert(endpoint, tokens);
    }

    /// Get tokens for an endpoint
    pub fn get(&self, endpoint: &str) -> Option<AuthTokens> {
        self.tokens.pin().get(endpoint).cloned()
    }

    /// Remove tokens for an endpoint
    pub fn remove(&self, endpoint: &str) {
        self.tokens.pin().remove(endpoint);
    }

    /// Check if tokens exist for an endpoint
    pub fn contains(&self, endpoint: &str) -> bool {
        self.tokens.pin().contains_key(endpoint)
    }

    /// Get all endpoints with stored tokens
    pub fn endpoints(&self) -> Vec<String> {
        self.tokens
            .pin()
            .iter()
            .map(|(k, _)| k.clone())
            .collect()
    }

    /// Clear all stored tokens
    pub fn clear(&self) {
        self.tokens.pin().clear();
    }
}

impl Default for TokenStore {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_token_store() {
        let store = TokenStore::new();
        let endpoint = "http://localhost:8080".to_string();
        
        let tokens = AuthTokens {
            access_token: "access_token_123".to_string(),
            refresh_token: "refresh_token_456".to_string(),
            expires_in_secs: 900,
            issued_at_secs: 1000,
            role: 0,
        };
        
        // Store tokens
        store.store(endpoint.clone(), tokens.clone());
        
        // Retrieve tokens
        let retrieved = store.get(&endpoint).unwrap();
        assert_eq!(retrieved.access_token, "access_token_123");
        assert_eq!(retrieved.refresh_token, "refresh_token_456");
        
        // Check existence
        assert!(store.contains(&endpoint));
        
        // Remove tokens
        store.remove(&endpoint);
        assert!(!store.contains(&endpoint));
    }

    #[test]
    fn test_token_store_endpoints() {
        let store = TokenStore::new();
        
        let tokens = AuthTokens {
            access_token: "token".to_string(),
            refresh_token: "refresh".to_string(),
            expires_in_secs: 900,
            issued_at_secs: 1000,
            role: 0,
        };
        
        store.store("http://endpoint1".to_string(), tokens.clone());
        store.store("http://endpoint2".to_string(), tokens.clone());
        
        let endpoints = store.endpoints();
        assert_eq!(endpoints.len(), 2);
    }
}

