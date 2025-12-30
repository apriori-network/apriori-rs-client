//! Ethereum-compatible signing utilities

use crate::error::{ClientError, Result};
use alloy_primitives::hex;
use k256::ecdsa::signature::hazmat::PrehashSigner;
use k256::ecdsa::{RecoveryId, Signature, SigningKey, VerifyingKey};
use sha3::{Digest, Keccak256};

/// Ethereum-compatible signer for challenge authentication
#[derive(Clone)]
pub struct Signer {
    signing_key: SigningKey,
    /// Full uncompressed public key (65 bytes: 0x04 + x + y)
    pubkey: Vec<u8>,
}

impl Signer {
    /// Create a new signer from a private key hex string
    ///
    /// The full uncompressed public key is automatically derived from the private key.
    ///
    /// # Arguments
    /// * `private_key_hex` - Private key in hex format (with or without "0x" prefix)
    pub fn new(private_key_hex: &str) -> Result<Self> {
        let private_key_hex = private_key_hex.trim_start_matches("0x");

        let private_key_bytes = hex::decode(private_key_hex)
            .map_err(|e| ClientError::Crypto(format!("Invalid private key hex: {e}")))?;

        let signing_key = SigningKey::from_bytes(private_key_bytes.as_slice().into())
            .map_err(|e| ClientError::Crypto(format!("Invalid private key: {e}")))?;

        // Get verifying key (public key)
        let verifying_key = signing_key.verifying_key();

        // Get full uncompressed public key (65 bytes: 0x04 + x + y)
        let pubkey_bytes = verifying_key.to_encoded_point(false);
        let pubkey = pubkey_bytes.as_bytes().to_vec();

        Ok(Self {
            signing_key,
            pubkey,
        })
    }

    /// Get the full uncompressed public key as bytes (65 bytes: 0x04 + x + y)
    pub fn pubkey(&self) -> &[u8] {
        &self.pubkey
    }

    /// Get the full uncompressed public key as hex string (130 hex chars)
    /// Format: 04 + x-coordinate (32 bytes) + y-coordinate (32 bytes)
    pub fn pubkey_hex(&self) -> String {
        hex::encode(&self.pubkey)
    }

    /// Get the Ethereum address derived from the public key (40 hex chars, no 0x prefix)
    pub fn address(&self) -> String {
        // Skip the 0x04 prefix and hash the rest (64 bytes)
        let mut hasher = Keccak256::new();
        hasher.update(&self.pubkey[1..]);
        let hash = hasher.finalize();

        // Take last 20 bytes as Ethereum address
        hex::encode(&hash[12..])
    }

    /// Sign a challenge JWT token
    ///
    /// The signature scheme follows Ethereum's signing standard:
    /// 1. message = full_pubkey_bytes || keccak256(challenge_utf8)
    /// 2. message_hash = keccak256(message)
    /// 3. signature = sign(message_hash)
    /// 4. Return signature as hex: r(32) + s(32) + v(1)
    ///
    /// Note: Uses the full uncompressed public key (65 bytes), not the address
    pub fn sign_challenge(&self, challenge: &str) -> Result<String> {
        let challenge_bytes = challenge.as_bytes();

        // Hash the challenge
        let mut hasher = Keccak256::new();
        hasher.update(challenge_bytes);
        let challenge_hash = hasher.finalize();

        // Concatenate pubkey and challenge hash
        let mut message = Vec::new();
        message.extend_from_slice(self.pubkey.as_slice());
        message.extend_from_slice(&challenge_hash);

        // Hash the combined message
        let mut hasher = Keccak256::new();
        hasher.update(&message);
        let message_hash = hasher.finalize();

        // Sign the prehash
        let signature: Signature = self
            .signing_key
            .sign_prehash(&message_hash)
            .map_err(|e| ClientError::Crypto(format!("Failed to sign: {e}")))?;

        // Find correct recovery ID
        let verifying_key = self.signing_key.verifying_key();
        let recovery_id = (0..4)
            .find_map(|v| {
                let rid = RecoveryId::try_from(v as u8).ok()?;
                let vk = VerifyingKey::recover_from_prehash(&message_hash, &signature, rid).ok()?;
                (vk == *verifying_key).then_some(rid)
            })
            .ok_or_else(|| ClientError::Crypto("Could not find valid recovery ID".to_string()))?;

        // Format as hex: r(32) + s(32) + v(1)
        let r_bytes = signature.r().to_bytes();
        let s_bytes = signature.s().to_bytes();
        let v = recovery_id.to_byte();

        let mut sig_bytes = Vec::new();
        sig_bytes.extend_from_slice(&r_bytes);
        sig_bytes.extend_from_slice(&s_bytes);
        sig_bytes.push(v);

        Ok(hex::encode(sig_bytes))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_signer_creation() {
        let private_key = "0x5de4111afa1a4b94908f83103eb1f1706367c2e68ca870fc3fb9a804cdab365a";

        let signer = Signer::new(private_key).unwrap();

        // Verify the derived address matches the expected address
        assert_eq!(signer.address(), "3c44cdddb6a900fa2b585dd299e03d12fa4293bc");

        // Verify the full public key is 65 bytes
        assert_eq!(signer.pubkey().len(), 65);

        // Verify it starts with 04 (uncompressed public key)
        assert_eq!(signer.pubkey()[0], 0x04);

        // Verify the hex representation is 130 characters
        assert_eq!(signer.pubkey_hex().len(), 130);
        assert!(signer.pubkey_hex().starts_with("04"));
    }

    #[test]
    fn test_sign_challenge() {
        let private_key = "0x5de4111afa1a4b94908f83103eb1f1706367c2e68ca870fc3fb9a804cdab365a";
        let challenge = "test_challenge_jwt_token";

        let signer = Signer::new(private_key).unwrap();
        let signature = signer.sign_challenge(challenge).unwrap();

        // Signature should be 65 bytes (130 hex characters)
        assert_eq!(signature.len(), 130);
    }
}

