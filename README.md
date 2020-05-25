# azure-sdk-keyvault

![Crates.io](https://img.shields.io/crates/v/azure-sdk-rust)
![Crates.io](https://img.shields.io/crates/l/azure-sdk-rust)
![Stability: Unstable](https://img.shields.io/badge/stability-unstable-red)
![Travis CI](https://img.shields.io/travis/guywaldman/azure-sdk-keyvault)



> 🚧 Work in progress, not encouraged for use in production. 🚧

## what is this?

[Azure Key Vault](https://azure.microsoft.com/en-us/services/key-vault/) is a service in Microsoft Azure for securely storing and accessing secrets, credentials and certificates in the cloud.
This crate exposes Rust bindings for the Azure Key Vault [REST API](https://docs.microsoft.com/en-us/rest/api/keyvault/).

This was started as a standalone contribution to [MindFlavor/AzureSDKForRust](https://github.com/MindFlavor/AzureSDKForRust),
which has many other useful Azure REST API bindings for Rust.

## Important Disclaimer

I am a Microsoft employee, but this is not an official Microsoft product nor an endorsed product.
Purely a project for fun and for learning Rust.

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

## Related Work

This project was started from the fantastic [MindFlavor/AzureSDKForRust](https://github.com/MindFlavor/AzureSDKForRust) repo.
