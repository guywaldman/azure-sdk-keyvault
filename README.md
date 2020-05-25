# azure-sdk-keyvault

![Crates.io](https://img.shields.io/crates/v/azure-sdk-rust)
![Crates.io](https://img.shields.io/crates/l/azure-sdk-rust)


Rust bindings for Azure Key Vault [REST API](https://docs.microsoft.com/en-us/rest/api/keyvault/).

> 🚧 Work in progress, not encouraged for use in production. 🚧

This project is a standalone contribution to [MindFlavor/AzureSDKForRust](https://github.com/MindFlavor/AzureSDKForRust) and is also a learning project for Rust 🦀

## Example Usage

```rust
use azure_sdk_keyvault::KeyVaultClient;
use std::env;

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let mut client = KeyVaultClient::new(&"c1a6d79b-082b-4798-b362-a77e96de50db", &"SUPER_SECRET_KEY", &"bc598e67-03d8-44d5-aa46-8289b9a39a14", &"test-keyvault");

    // Set a secret.
    client.set_secret("test-secret", "42").await?;

    // Get a secret.
    let secret = client.get_secret(&secret_name).await?;
    assert_eq!("42", secret.value());

    Ok(())
}
```

## Contributions

...are welcome! Currently the repo exposes a very small number of operations.

## Related Projects

This project was started from the fantastic [MindFlavor/AzureSDKForRust](https://github.com/MindFlavor/AzureSDKForRust) repo.
