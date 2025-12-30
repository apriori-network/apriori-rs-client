//! Basic authentication example
//!
//! Usage:
//!   cargo run --example basic_auth

use apriori_common::Role;
use apriori_rs_client::auth_client::AuthClient;
use apriori_rs_client::{AuthClientConfig, AuthClientHttp};

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    // Initialize logging
    tracing_subscriber::fmt::init();

    // Configuration
    let endpoint1 = std::env::var("APRIORI_ENDPOINT")
        .unwrap_or_else(|_| "http://localhost:8080".to_string());
    
    let endpoint2 = std::env::var("APRIORI_ENDPOINT2")
        .unwrap_or_else(|_| "http://localhost:8081".to_string());
    
    let private_key = std::env::var("PRIVATE_KEY")
        .unwrap_or_else(|_| "0x5de4111afa1a4b94908f83103eb1f1706367c2e68ca870fc3fb9a804cdab365a".to_string());
    
    let role: i32 = std::env::var("ROLE")
        .unwrap_or_else(|_| "0".to_string())
        .parse()
        .unwrap_or(0);

    println!("=== Apriori Rust Client Example ===");
    println!("Endpoint 1: {}", endpoint1);
    println!("Endpoint 2: {}", endpoint2);
    println!("Role: {}", role);
    println!();

    // Create client config (pubkey will be automatically derived from private key)
    let config = AuthClientConfig::new(private_key, 60, 30, Role::Searcher);

    // Create auth client (manages multiple endpoints, returns Arc for cheap cloning)
    let client = AuthClientHttp::new(config)?;
    println!("✓ Auth client created (auto-refresh task started)");
    println!();

    // Get access token for endpoint 1 (auto-authenticates if needed)
    println!("Getting access token for endpoint 1...");
    let access_token1 = client.get_access_token(&endpoint1).await?;
    println!("✓ Got access token for endpoint 1!");
    println!("  Access Token: {}...", &access_token1[..50]);
    println!();

    // Demonstrate multi-endpoint support - get token for endpoint 2
    println!("Getting access token for endpoint 2...");
    match client.get_access_token(&endpoint2).await {
        Ok(access_token2) => {
            println!("✓ Got access token for endpoint 2!");
            println!("  Access Token: {}...", &access_token2[..50]);
            println!();
        }
        Err(e) => {
            println!("! Failed to get token for endpoint 2: {}", e);
            println!("  (This is expected if endpoint 2 is not running)");
            println!();
        }
    }

    // Get access tokens again (should use cached tokens)
    println!("Getting access token for endpoint 1...");
    let access_token1 = client.get_access_token(&endpoint1).await?;
    println!("✓ Got access token: {}...", &access_token1[..50]);
    println!();

    // Show token store contents
    println!("Managed endpoints:");
    for endpoint in client.token_store().endpoints() {
        println!("  - {}", endpoint);
    }
    println!();

    // Demonstrate auto-refresh capability
    println!("Auto-refresh task is running in the background...");
    println!("Tokens will be automatically refreshed when needed.");
    println!();
    
    // Keep the program running for a bit to demonstrate auto-refresh
    println!("Press Ctrl+C to exit");
    println!("(Sleeping for 120 seconds to allow auto-refresh to trigger)");
    
    tokio::time::sleep(tokio::time::Duration::from_secs(120)).await;

    println!();
    println!("Done!");

    Ok(())
}
