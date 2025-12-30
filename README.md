# Apriori Rust Client

A Rust client library for interacting with the Apriori RPC service, featuring automatic JWT authentication, token management, and auto-refresh capabilities.

## Features

- 🔐 **Automatic Authentication**: Complete challenge-response authentication flow
- 🔄 **Auto Token Refresh**: Automatically refreshes access tokens before expiration
- 🚀 **Thread-Safe**: Uses Papaya HashMap for concurrent token storage
- ⚡ **Async/Await**: Built on Tokio for efficient async operations
- 🔑 **Ethereum-Compatible Signing**: Implements EIP-191 signing standard

## Installation

Add to your `Cargo.toml`:

```toml
[dependencies]
apriori-rs-client = { path = "../apriori-rs-client" }
```

## Usage

### Basic Authentication

```rust
use apriori_rs_client::{AuthClient, AuthClientConfig};
use std::sync::Arc;

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    // Create client config with private key (pubkey is automatically derived)
    let config = AuthClientConfig::new(
        "0x5de4111afa1a4b94908f83103eb1f1706367c2e68ca870fc3fb9a804cdab365a".to_string(),
    );

    // Create client (returns Arc<AuthClient>, auto-refresh task starts automatically)
    let client: Arc<AuthClient> = AuthClient::new(config)?;

    // Get access token (handles authentication, refresh, and re-auth automatically)
    let endpoint = "http://localhost:8080";
    let role = 0; // 0=Searcher, 1=Builder, 2=Relayer, 3=Fullnode
    let access_token = client.get_access_token(endpoint, role).await?;
    println!("Access Token: {}", access_token);

    Ok(())
}
```

### Advanced Configuration

```rust
use std::sync::Arc;

// Customize refresh behavior
let config = AuthClientConfig::new(private_key.to_string())
    .with_refresh_threshold(120)  // Refresh 2 minutes before expiration
    .with_check_interval(15);      // Check for refresh every 15 seconds

let client: Arc<AuthClient> = AuthClient::new(config)?;
```

### Multiple Endpoints

The client can manage authentication for multiple endpoints simultaneously:

```rust
use std::sync::Arc;

let config = AuthClientConfig::new(private_key.to_string());
let client: Arc<AuthClient> = AuthClient::new(config)?;

// Get tokens for multiple endpoints (auto-authenticates on first call)
let token1 = client.get_access_token("http://endpoint1:8080", 0).await?;
let token2 = client.get_access_token("http://endpoint2:8080", 1).await?;

// All endpoints are auto-refreshed by a single background task
// Arc allows cheap cloning to share the client across threads/tasks
let client_clone = Arc::clone(&client);
tokio::spawn(async move {
    // Use client_clone in another task
    let token = client_clone.get_access_token("http://endpoint1:8080", 0).await?;
    // ...
    Ok::<_, Box<dyn std::error::Error>>(())
});
```

### Token Management

Tokens are fully managed automatically:
- **First call**: If no tokens exist, `get_access_token()` will authenticate automatically
- **Valid token**: Returns immediately without network call
- **Expired access token**: Automatically refreshes using refresh token
- **Expired refresh token**: Automatically re-authenticates with the server
- **Background task**: Continuously monitors and preemptively refreshes tokens before expiry

```rust
// Just get the access token - everything is handled automatically
// No need to call authenticate() first!
let access_token = client.get_access_token("http://localhost:8080", 0).await?;
```

## Architecture

### Components

1. **AuthClient**: Main client that orchestrates the authentication flow
2. **Signer**: Ethereum-compatible signing for challenge authentication
3. **TokenStore**: Thread-safe storage for tokens using Papaya HashMap
4. **Types**: Data structures for authentication requests/responses

### Authentication Flow

```
┌─────────────────────────────────┐
│        AuthClient               │
│  (manages multiple endpoints)   │
└───────────┬─────────────────────┘
            │
            ├─── get_access_token(endpoint, role)
            │         │
            │         ├─── Fast path: Check cached token (no lock)
            │         │
            │         ├─── If expired/missing: Acquire per-endpoint lock
            │         │
            │         ├─── Double-check: Re-check cached token
            │         │
            │         └─── Refresh or Authenticate:
            │               ├─── 1. Try Refresh ──→ Server
            │               └─── 2. If failed, Re-authenticate ──→ Server
            │
            │
            └─── Auto-Refresh Task (single task for all endpoints)
                      │
                      ├─── Check every N seconds
                      │
                      ├─── For each endpoint needing refresh:
                      │     ├─── Try acquire lock (non-blocking)
                      │     └─── If acquired: Refresh token
                      │
                      └─── Runs continuously
```

### Token Lifecycle

```
Access Token Timeline:
|─────────────────────|───────|───|
0                    T-60    T   T (expiry)
                       ↑
                  Auto-refresh
                  triggered here
```

## Roles

- `0` - **Searcher**: Can submit and simulate bundles
- `1` - **Builder**: Searcher + leader info access
- `2` - **Relayer**: Can stream bundles to leaders
- `3` - **Fullnode**: Can stream bundles to leaders

## Error Handling

The client provides detailed error types:

```rust
use apriori_rs_client::ClientError;

match client.authenticate().await {
    Ok(tokens) => println!("Authenticated!"),
    Err(ClientError::Authentication(msg)) => eprintln!("Auth failed: {}", msg),
    Err(ClientError::Crypto(msg)) => eprintln!("Crypto error: {}", msg),
    Err(ClientError::HttpRequest(e)) => eprintln!("HTTP error: {}", e),
    Err(e) => eprintln!("Other error: {}", e),
}
```

## Development

### Run Tests

```bash
cargo test
```

### Enable Logging

```rust
use tracing_subscriber;

tracing_subscriber::fmt::init();
```

## License

Same as the Apriori project.

